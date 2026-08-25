"""
service.jobs — dispatch layer between HTTP and the engine.

THE BOTTLENECK YOUR ORIGINAL CODE HAD:
    result = await extract_and_analyze(file)

`async def` does not make CPU-bound work concurrent. Unzipping and walking a
multidex APK is 3-40 seconds of pure-Python CPU. Awaiting it inside the request
handler pins the event loop: every other request on that worker — health checks
included — stalls until it finishes. One 90 MB APK takes your whole service down.

The fix is two-part:
  1. Move the work off the loop entirely -> ProcessPoolExecutor (processes, not
     threads: the GIL makes a thread pool useless for this workload).
  2. Move the work out of the request -> submit returns 202 + job_id.
     A 40 s hold also dies to Cloudflare's 100 s edge timeout the moment one
     customer uploads a fat AAB.

This is the same submit/poll shape as the Runway provider in ViralForge. Same
problem, same answer.
"""

from __future__ import annotations

import asyncio
import logging
import os
from concurrent.futures import ProcessPoolExecutor
from typing import Any

from core import analyze_path

from .config import settings
from .store import JobStore

log = logging.getLogger("nullscan.jobs")


class Dispatcher:
    """Owns the process pool. One instance per app, created in the lifespan hook."""

    def __init__(self, store: JobStore) -> None:
        self.store = store
        self._pool: ProcessPoolExecutor | None = None
        self._inflight: set[asyncio.Task[None]] = set()

    def start(self) -> None:
        self._pool = ProcessPoolExecutor(max_workers=settings.workers)
        log.info("dispatcher up with %d worker process(es)", settings.workers)

    def shutdown(self) -> None:
        for task in list(self._inflight):
            task.cancel()
        if self._pool is not None:
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._pool = None

    def submit(self, job_id: str, apk_path: str) -> None:
        """Fire and forget. State transitions land in the store, not in memory."""
        task = asyncio.create_task(self._run(job_id, apk_path))
        self._inflight.add(task)
        task.add_done_callback(self._inflight.discard)

    async def _run(self, job_id: str, apk_path: str) -> None:
        assert self._pool is not None, "dispatcher not started"
        loop = asyncio.get_running_loop()
        self.store.mark_running(job_id)
        try:
            fut = loop.run_in_executor(self._pool, analyze_path, apk_path)
            report: dict[str, Any] = await asyncio.wait_for(
                fut, timeout=settings.job_timeout_s
            )
            self.store.finish(job_id, report)
        except asyncio.TimeoutError:
            self.store.fail(job_id, f"exceeded {settings.job_timeout_s}s", state="timeout")
        except asyncio.CancelledError:
            self.store.fail(job_id, "cancelled during shutdown")
            raise
        except Exception as exc:  # noqa: BLE001
            log.exception("job %s failed", job_id)
            self.store.fail(job_id, f"{type(exc).__name__}: {exc}")
        finally:
            # The upload is the largest artefact in the system. Never let a
            # failure path leak it — that's how a scanner fills a Railway volume.
            try:
                os.unlink(apk_path)
            except OSError:
                pass
