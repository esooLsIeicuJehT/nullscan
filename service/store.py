"""
service.store — durable job state.

FLOW POSITION: the only stateful component. Everything else is a pure function
or a transport.

SQLite with WAL, not a dict. A dict loses every in-flight job on the Railway
container recycling, and the customer's CI job hangs forever polling a job_id
that no longer exists. WAL + a single writer is good for thousands of scans a
day; swap to Postgres by reimplementing this one module's five functions.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Literal

JobState = Literal["queued", "running", "done", "failed", "timeout"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id           TEXT PRIMARY KEY,
    state        TEXT NOT NULL,
    api_key      TEXT,
    filename     TEXT,
    apk_sha256   TEXT,
    created_at   REAL NOT NULL,
    started_at   REAL,
    finished_at  REAL,
    report_json  TEXT,
    error        TEXT
);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at);
CREATE INDEX IF NOT EXISTS idx_jobs_sha     ON jobs(apk_sha256);
CREATE INDEX IF NOT EXISTS idx_jobs_key     ON jobs(api_key, created_at);
"""


class JobStore:
    def __init__(self, db_path: str) -> None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._path = db_path
        with self._session() as c:
            c.executescript(_SCHEMA)

    @contextlib.contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        """Open a connection and ALWAYS close it.

        `with sqlite3.connect(...) as c` is a TRANSACTION context manager, not
        a resource one — it commits on exit and leaves the connection open. In
        a long-lived service that leaks a handle per query, and it made the
        key-hashing migration fail with "database is locked" because the schema
        connection from __init__ was still holding the file.
        """
        c = self._conn()
        try:
            yield c
        finally:
            c.close()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self._path, timeout=15.0, isolation_level=None)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=15000")
        c.row_factory = sqlite3.Row
        return c

    # --- writes --------------------------------------------------------------
    def create(self, filename: str, api_key: str | None) -> str:
        job_id = uuid.uuid4().hex
        with self._session() as c:
            c.execute(
                "INSERT INTO jobs (id, state, api_key, filename, created_at) "
                "VALUES (?, 'queued', ?, ?, ?)",
                (job_id, api_key, filename, time.time()),
            )
        return job_id

    def mark_running(self, job_id: str) -> None:
        with self._session() as c:
            c.execute("UPDATE jobs SET state='running', started_at=? WHERE id=?",
                      (time.time(), job_id))

    def finish(self, job_id: str, report: dict[str, Any]) -> None:
        with self._session() as c:
            c.execute(
                "UPDATE jobs SET state='done', finished_at=?, report_json=?, "
                "apk_sha256=? WHERE id=?",
                (time.time(), json.dumps(report), report.get("apk_sha256", ""), job_id),
            )

    def fail(self, job_id: str, error: str, state: JobState = "failed") -> None:
        with self._session() as c:
            c.execute("UPDATE jobs SET state=?, finished_at=?, error=? WHERE id=?",
                      (state, time.time(), error[:2000], job_id))

    # --- reads ---------------------------------------------------------------
    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._session() as c:
            row = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["report"] = json.loads(d.pop("report_json")) if d.get("report_json") else None
        return d

    def latest_for_key(self, api_key: str | None, limit: int = 20) -> list[dict[str, Any]]:
        with self._session() as c:
            rows = c.execute(
                "SELECT id, state, filename, apk_sha256, created_at, finished_at "
                "FROM jobs WHERE api_key IS ? ORDER BY created_at DESC LIMIT ?",
                (api_key, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def find_report_by_sha(self, sha: str) -> dict[str, Any] | None:
        """Cache hit path: the same APK never needs analysing twice."""
        with self._session() as c:
            row = c.execute(
                "SELECT report_json FROM jobs WHERE apk_sha256=? AND state='done' "
                "ORDER BY finished_at DESC LIMIT 1", (sha,),
            ).fetchone()
        return json.loads(row["report_json"]) if row else None

    def purge_older_than(self, hours: int) -> int:
        cutoff = time.time() - hours * 3600
        with self._session() as c:
            cur = c.execute("DELETE FROM jobs WHERE created_at < ?", (cutoff,))
        return cur.rowcount
