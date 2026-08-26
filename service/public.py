"""
service.public — everything the free scanner needs that the paid API doesn't.

FLOW POSITION: a gate in front of `POST /v1/scans`, plus one small write path
for the waitlist. No analysis logic. No knowledge of what an APK is.

WHY A SEPARATE MODULE
    The free scanner and the paid API are the same endpoint with different
    economics. Folding the quota logic into main.py would mean every future
    change to pricing edits the request router. Keeping it here means the
    router just asks "am I allowed?" and this module owns the answer.

TWO THINGS THAT MATTER COMMERCIALLY
    1. The quota is content-addressed-aware: a repeat scan of a SHA-256 we
       already have costs nothing to serve, so it does not consume a quota
       slot. Someone re-checking the same build isn't abusing anything.
    2. Anonymous users are keyed by IP, API-key holders bypass entirely.
       That's the whole free-vs-paid boundary, in one function.
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
import sqlite3
import time
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS quota (
    principal  TEXT NOT NULL,
    at         REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_quota ON quota(principal, at);

CREATE TABLE IF NOT EXISTS waitlist (
    email      TEXT PRIMARY KEY,
    source     TEXT,
    created_at REAL NOT NULL
);
"""

# Deliberately permissive. Bouncing a valid address is a lost lead; accepting a
# junk one costs a row. Real validation is the confirmation email.
_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s.]+(\.[^@\s.]+)+$")


class PublicStore:
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

    # --- quota ---------------------------------------------------------------
    def used(self, principal: str, window_s: int) -> int:
        cutoff = time.time() - window_s
        with self._session() as c:
            row = c.execute(
                "SELECT COUNT(*) n FROM quota WHERE principal=? AND at>?",
                (principal, cutoff),
            ).fetchone()
        return int(row["n"])

    def charge(self, principal: str) -> None:
        with self._session() as c:
            c.execute("INSERT INTO quota (principal, at) VALUES (?,?)",
                      (principal, time.time()))

    def next_reset(self, principal: str, window_s: int) -> int:
        """Seconds until the oldest charge in the window expires."""
        cutoff = time.time() - window_s
        with self._session() as c:
            row = c.execute(
                "SELECT MIN(at) t FROM quota WHERE principal=? AND at>?",
                (principal, cutoff),
            ).fetchone()
        if row is None or row["t"] is None:
            return 0
        return max(0, int(row["t"] + window_s - time.time()))

    def purge_quota(self, window_s: int) -> int:
        with self._session() as c:
            cur = c.execute("DELETE FROM quota WHERE at < ?", (time.time() - window_s,))
        return cur.rowcount

    # --- waitlist ------------------------------------------------------------
    def add_email(self, email: str, source: str = "web") -> bool:
        """True if newly added, False if already present. Never raises on dupes."""
        with self._session() as c:
            cur = c.execute(
                "INSERT OR IGNORE INTO waitlist (email, source, created_at) VALUES (?,?,?)",
                (email.strip().lower(), source, time.time()),
            )
        return cur.rowcount == 1

    def waitlist_count(self) -> int:
        with self._session() as c:
            return int(c.execute("SELECT COUNT(*) n FROM waitlist").fetchone()["n"])


def valid_email(value: str) -> bool:
    v = (value or "").strip()
    return len(v) <= 254 and bool(_EMAIL.match(v))


def client_principal(
    *,
    api_key: str | None,
    peer: str | None,
    forwarded_for: str | None,
    trust_proxy: bool,
) -> str:
    """Who is this request charged to?

    Behind Railway/Cloudflare the socket peer is the proxy, so every visitor
    would share one quota bucket. X-Forwarded-For fixes that — but it is
    caller-controlled, so honouring it when NOT behind a proxy hands anyone an
    unlimited quota by sending a header. Hence the explicit trust flag: opt in
    only when a proxy is actually in front.
    """
    if api_key:
        return f"key:{api_key}"

    ip = peer or "unknown"
    if trust_proxy and forwarded_for:
        # leftmost entry is the original client; the rest are proxy hops
        candidate = forwarded_for.split(",")[0].strip()
        try:
            ipaddress.ip_address(candidate)
            ip = candidate
        except ValueError:
            pass  # malformed header, fall back to the socket peer

    # /24 bucket for IPv4, /64 for IPv6: one office NAT shouldn't get 200 free
    # scans, and one phone shouldn't lose its quota when the carrier rotates
    # the last octet.
    try:
        addr = ipaddress.ip_address(ip)
        net = ipaddress.ip_network(f"{ip}/{24 if addr.version == 4 else 64}",
                                   strict=False)
        return f"net:{net.network_address}"
    except ValueError:
        return f"ip:{ip}"
