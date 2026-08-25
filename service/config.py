"""service.config — single source of truth for runtime knobs."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass(frozen=True, slots=True)
class Settings:
    # upload limits — enforced by streaming, never by trusting Content-Length
    max_upload_bytes: int = _int("NULLSCAN_MAX_UPLOAD_MB", 512) * 1024 * 1024
    upload_dir: str = os.environ.get("NULLSCAN_UPLOAD_DIR", "/tmp/nullscan")
    db_path: str = os.environ.get("NULLSCAN_DB", "/tmp/nullscan/jobs.db")

    # workers: analysis is CPU-bound pure Python, so processes, not threads.
    workers: int = _int("NULLSCAN_WORKERS", max(1, (os.cpu_count() or 2) - 1))
    job_timeout_s: int = _int("NULLSCAN_JOB_TIMEOUT", 300)
    retain_hours: int = _int("NULLSCAN_RETAIN_HOURS", 72)

    # webhook signing (principal-architect-2026: X-Midnight-Signature)
    signing_secret: str = os.environ.get("NULLSCAN_SIGNING_SECRET", "")
    require_signature: bool = os.environ.get("NULLSCAN_REQUIRE_SIG", "0") == "1"

    api_keys: frozenset[str] = frozenset(
        k.strip() for k in os.environ.get("NULLSCAN_API_KEYS", "").split(",") if k.strip()
    )

    # free public scanner
    serve_web: bool = os.environ.get("NULLSCAN_SERVE_WEB", "1") == "1"
    free_scans: int = _int("NULLSCAN_FREE_SCANS", 3)
    free_window_s: int = _int("NULLSCAN_FREE_WINDOW_S", 86_400)
    # Only enable behind a real proxy. X-Forwarded-For is caller-controlled, so
    # trusting it on a directly-exposed host gives anyone unlimited free scans
    # for the price of one header.
    trust_proxy: bool = os.environ.get("NULLSCAN_TRUST_PROXY", "0") == "1"

    # billing — absent keys disable the endpoints rather than crash the app,
    # so local dev and self-hosting work with no Stripe account at all.
    stripe_secret: str = os.environ.get("STRIPE_SECRET_KEY", "")
    stripe_webhook_secret: str = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    public_url: str = os.environ.get("NULLSCAN_PUBLIC_URL", "http://localhost:8000")


settings = Settings()
