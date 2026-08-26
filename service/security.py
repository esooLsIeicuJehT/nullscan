"""
service.security — auth and payload integrity.

Two independent mechanisms, do not confuse them:
  * API key  -> identifies a paying customer, gates and meters access.
  * Signature -> proves an inbound webhook body was produced by a holder of the
                 shared secret. Prevents CI-callback spoofing.
"""

from __future__ import annotations

import hashlib
import hmac

from fastapi import Header, HTTPException, Request, status

from .config import settings

SIGNATURE_HEADER = "x-midnight-signature"


_key_store: object | None = None


def bind_key_store(store: object) -> None:
    """Injected at startup so this module stays importable without a database.

    security.py must not import billing.py directly: billing imports the
    network layer, and a circular import between auth and payments is a
    debugging afternoon nobody needs.
    """
    global _key_store
    _key_store = store


def require_api_key(x_api_key: str | None = Header(default=None)) -> str | None:
    """Returns the key, or None when the caller is anonymous.

    Anonymous is ALLOWED — that's the free public scanner. A key upgrades the
    caller to a paid tier; a bad key is rejected outright rather than silently
    downgraded, because silently metering someone who is paying is worse than
    an error they can see.
    """
    if x_api_key is None:
        # legacy env-var mode: if keys are configured there, demand one
        if settings.api_keys:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing X-API-Key")
        return None

    for known in settings.api_keys:
        if hmac.compare_digest(x_api_key, known):
            return x_api_key

    if _key_store is not None:
        row = _key_store.lookup(x_api_key)  # type: ignore[attr-defined]
        if row is not None:
            if row["status"] == "active":
                return x_api_key
            if row["status"] == "rotated":
                # A rotated key is not a billing problem, and telling the
                # customer to "update billing" sends them to Stripe to fix
                # something Stripe cannot fix.
                raise HTTPException(
                    status.HTTP_401_UNAUTHORIZED,
                    "This key was replaced. Use the key from your most recent "
                    "NULLSCAN email, or request a new one at /#account.",
                )
            raise HTTPException(
                status.HTTP_402_PAYMENT_REQUIRED,
                f"This key is {row['status']}. Update billing to reactivate it.",
            )

    raise HTTPException(status.HTTP_403_FORBIDDEN, "invalid API key")


def sign(body: bytes) -> str:
    return "sha256=" + hmac.new(
        settings.signing_secret.encode(), body, hashlib.sha256
    ).hexdigest()


async def verify_signature(request: Request) -> None:
    """Reject unsigned or mis-signed bodies when signing is enforced."""
    if not settings.require_signature:
        return
    if not settings.signing_secret:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "signature required but NULLSCAN_SIGNING_SECRET is unset",
        )
    supplied = request.headers.get(SIGNATURE_HEADER)
    if not supplied:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"missing {SIGNATURE_HEADER}")
    body = await request.body()
    if not hmac.compare_digest(supplied, sign(body)):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "signature mismatch")
