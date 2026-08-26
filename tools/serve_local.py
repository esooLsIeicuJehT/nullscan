#!/usr/bin/env python3
"""
tools/serve_local.py — run the scanner UI with nothing installed.

WHY THIS EXISTS
    FastAPI needs pydantic, pydantic needs pydantic-core, pydantic-core is Rust
    with no aarch64-linux-android wheel. On Termux `pip install -r
    requirements.txt` compiles for 30+ minutes and often fails. But `core/` is
    stdlib-only, so the analysis engine already runs fine there — the only
    thing missing was a way to reach it from a browser.

    This is http.server plus about 120 lines of routing. Same engine, same
    web/index.html, no dependencies at all.

WHAT THIS IS NOT
    Not production. Single process, in-memory jobs, no quota persistence, no
    auth, no signature verification. `service/` remains the real server and
    the source of truth for the API contract.

    Two implementations of one API is a drift risk, and the mitigation is
    deliberate scope: this speaks the minimum the bundled page needs, and the
    page is the shared artifact. If you find yourself adding a feature here,
    it belongs in service/ instead.

USAGE
    python3 $HOME/nullscan/tools/serve_local.py
    python3 $HOME/nullscan/tools/serve_local.py --port 8080 --host 0.0.0.0
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import ENGINE_VERSION, analyze_path
from service.billing import TIERS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(ROOT, "web", "index.html")
MAX_UPLOAD = 512 * 1024 * 1024
HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s.]+(\.[^@\s.]+)+$")

JOBS: dict[str, dict] = {}
BY_SHA: dict[str, dict] = {}
WAITLIST: list[str] = []
LOCK = threading.Lock()


def stream_multipart_to_file(rfile, total: int, content_type: str,
                            dest_path: str) -> tuple[str, int] | None:
    """Stream the first file part straight to disk. Returns (filename, bytes).

    The first version of this read the whole body into memory and then called
    body.split(boundary). For a 122 MB APK that is the upload buffered once,
    plus a full copy per part from split() — comfortably 250 MB+ resident on a
    phone that has other things to do. Real APKs are exactly the case this
    server exists for, so buffering them was the wrong shape.

    This keeps a tail window of boundary-length bytes so a boundary marker
    split across two reads is still detected, and never holds more than one
    chunk plus that window.
    """
    m = re.search(r'boundary="?([^";]+)"?', content_type)
    if not m:
        return None
    sep = b"--" + m.group(1).encode()
    keep = len(sep) + 8

    buf = b""
    filename = "upload.apk"
    left = total

    def pull(n: int = 1 << 18) -> bytes:
        nonlocal left
        if left <= 0:
            return b""
        chunk = rfile.read(min(n, left))
        left -= len(chunk)
        return chunk

    # 1. find the header block of the first part that carries a filename
    while b"\r\n\r\n" not in buf:
        chunk = pull()
        if not chunk:
            return None
        buf += chunk
        if len(buf) > 1 << 20:      # 1 MB of headers is not a real request
            return None

    head, _, buf = buf.partition(b"\r\n\r\n")
    if b"filename=" not in head:
        return None
    fn = re.search(rb'filename="([^"]*)"', head)
    if fn and fn.group(1):
        # basename only: a crafted filename must never steer the write path
        filename = os.path.basename(fn.group(1).decode("utf-8", "replace")) or "upload.apk"

    # 2. stream body until the closing boundary
    written = 0
    with open(dest_path, "wb") as out:
        while True:
            idx = buf.find(b"\r\n" + sep)
            if idx != -1:
                out.write(buf[:idx])
                written += idx
                break
            if len(buf) > keep:
                flush = buf[:-keep]
                out.write(flush)
                written += len(flush)
                buf = buf[-keep:]
            chunk = pull()
            if not chunk:
                out.write(buf)
                written += len(buf)
                break
            buf += chunk

    return (filename, written) if written else None


def run_scan(job_id: str, path: str) -> None:
    try:
        report = analyze_path(path)
        with LOCK:
            JOBS[job_id].update(state="done", report=report, finished_at=time.time())
            if report.get("apk_sha256"):
                BY_SHA[report["apk_sha256"]] = report
    except Exception as exc:
        with LOCK:
            JOBS[job_id].update(state="failed", error=f"{type(exc).__name__}: {exc}")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


class Handler(BaseHTTPRequestHandler):
    server_version = f"nullscan-dev/{ENGINE_VERSION}"

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write(f"  {self.address_string()} {fmt % args}\n")

    # --- helpers ---------------------------------------------------------
    def send_json(self, obj: object, code: int = 200) -> None:
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def err(self, msg: str, code: int) -> None:
        self.send_json({"error": msg, "detail": None}, code)

    def read_body(self) -> bytes | None:
        """None means 'too large'; b'' means 'empty'. Collapsing the two made
        an empty upload report 413 Payload Too Large, which is the opposite of
        what happened and sends the caller looking for a size problem."""
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_UPLOAD:
            return None
        chunks, left = [], n
        while left > 0:
            b = self.rfile.read(min(left, 1 << 20))
            if not b:
                break
            chunks.append(b)
            left -= len(b)
        return b"".join(chunks)

    # --- routes ----------------------------------------------------------
    def do_GET(self) -> None:
        p = urlparse(self.path)

        if p.path in ("/", "/index.html"):
            if not os.path.exists(PAGE):
                self.err("web/index.html not found", 404)
                return
            with open(PAGE, "rb") as fh:
                raw = fh.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)
            return

        if p.path == "/healthz":
            self.send_json({"status": "ok", "engine": ENGINE_VERSION, "mode": "dev"})
            return

        if p.path == "/v1/plans":
            # Imported from service.billing, NOT re-declared here. The first
            # version of this file omitted the route entirely and the pricing
            # section silently rendered empty — the page 404'd and swallowed it.
            # Duplicating the tier list would have been the same bug with extra
            # steps: two prices that drift apart.
            self.send_json([
                {"slug": t.slug, "name": t.name, "price_cents": t.price_cents,
                 "monthly_scans": t.monthly_scans, "blurb": t.blurb}
                for t in TIERS.values()
            ])
            return

        if p.path == "/v1/quota":
            # The dev server does not meter. Saying "unlimited" is honest here
            # and keeps the page's quota line from lying about production.
            self.send_json({"limit": -1, "used": 0, "remaining": -1,
                            "resets_in_s": 0, "metered": False})
            return

        if p.path == "/v1/account":
            self.err("Accounts run on the real server, not the dev one.", 503)
            return

        m = re.fullmatch(r"/v1/scans/([0-9a-f]{32})", p.path)
        if m:
            with LOCK:
                job = JOBS.get(m.group(1))
            if job is None:
                self.err("unknown job_id", 404)
                return
            self.send_json(job)
            return

        self.err("not found", 404)

    def do_POST(self) -> None:
        p = urlparse(self.path)

        if p.path in ("/v1/checkout", "/v1/billing-portal", "/v1/keys/recover"):
            self.read_body()
            self.err("Accounts and billing run on the real server, not the dev "
                     "one. Start service/ with Stripe and mail configured.", 503)
            return

        if p.path == "/v1/waitlist":
            raw = self.read_body()
            if raw is None:
                self.err("request too large", 413)
                return
            try:
                data = json.loads(raw or b"{}")
            except ValueError:
                self.err("invalid JSON", 400)
                return
            email = str(data.get("email", "")).strip().lower()
            if not EMAIL.match(email) or len(email) > 254:
                self.err("That address does not look right.", 400)
                return
            with LOCK:
                added = email not in WAITLIST
                if added:
                    WAITLIST.append(email)
            print(f"  waitlist: {email}" + ("" if added else " (already had it)"))
            self.send_json({"email": email, "added": added})
            return

        if p.path == "/v1/scans":
            q = parse_qs(p.query)
            sha = (q.get("sha256") or [""])[0]
            if sha and HEX64.match(sha):
                with LOCK:
                    hit = BY_SHA.get(sha.lower())
                if hit is not None:
                    jid = uuid.uuid4().hex
                    with LOCK:
                        JOBS[jid] = {"id": jid, "state": "done", "filename": None,
                                     "apk_sha256": sha.lower(), "created_at": time.time(),
                                     "finished_at": time.time(), "error": None,
                                     "report": hit}
                    self.send_json({"job_id": jid, "state": "done",
                                    "poll_url": f"/v1/scans/{jid}", "cached": True})
                    return

            ctype = self.headers.get("Content-Type", "")
            if not ctype.startswith("multipart/form-data"):
                self.err("expected multipart/form-data", 400)
                return

            total = int(self.headers.get("Content-Length") or 0)
            if total > MAX_UPLOAD:
                self.err(f"upload exceeds {MAX_UPLOAD // (1024 * 1024)} MB", 413)
                return
            if total <= 0:
                self.err("empty upload", 400)
                return

            fd, path = tempfile.mkstemp(suffix=".apk", prefix="nullscan-")
            os.close(fd)
            try:
                parsed = stream_multipart_to_file(self.rfile, total, ctype, path)
            except Exception as exc:
                os.unlink(path)
                self.err(f"could not read the upload: {exc}", 400)
                return
            if parsed is None:
                os.unlink(path)
                self.err("empty upload", 400)
                return
            filename, nbytes = parsed
            print(f"  received {filename} ({nbytes / 1048576:.1f} MB) -> scanning")

            jid = uuid.uuid4().hex
            with LOCK:
                JOBS[jid] = {"id": jid, "state": "queued", "filename": filename,
                             "apk_sha256": None, "created_at": time.time(),
                             "started_at": None, "finished_at": None,
                             "error": None, "report": None}
            threading.Thread(target=run_scan, args=(jid, path), daemon=True).start()
            self.send_json({"job_id": jid, "state": "queued",
                            "poll_url": f"/v1/scans/{jid}", "cached": False}, 202)
            return

        self.err("not found", 404)


def main() -> int:
    ap = argparse.ArgumentParser(prog="serve_local")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--host", default="127.0.0.1",
                    help="use 0.0.0.0 to reach it from another device on your wifi")
    a = ap.parse_args()

    if not os.path.exists(PAGE):
        print(f"missing {PAGE}", file=sys.stderr)
        return 1

    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    shown = "localhost" if a.host in ("127.0.0.1", "0.0.0.0") else a.host
    print(f"\n  NULLSCAN dev server (no dependencies)  engine {ENGINE_VERSION}")
    print(f"  http://{shown}:{a.port}")
    if a.host == "0.0.0.0":
        print("  reachable from other devices on this network")
    print("\n  in-memory jobs, no metering, dev only — service/ is the real server")
    print("  ctrl-C to stop\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print(f"\n  stopped. {len(WAITLIST)} waitlist signup(s) this session.")
        for e in WAITLIST:
            print(f"    {e}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
