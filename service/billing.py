"""
service.billing — payment to provisioned API key.

FLOW POSITION
    Checkout   : browser -> POST /v1/checkout -> Stripe -> redirect
    Fulfilment : Stripe -> POST /v1/stripe/webhook -> key issued
    Enforcement: every /v1/scans -> key lookup -> tier quota

WHY NO `stripe` PACKAGE
    Stripe's REST API is form-encoded POSTs with a Bearer token, and webhook
    verification is HMAC-SHA256. Both are stdlib. Adding the SDK would pull
    another dependency chain into a service that currently installs in four
    packages — and on Termux every added wheel is a possible Rust compile.

WHY KEYS LIVE IN SQLITE AND NOT AN ENV VAR
    The env-var key list was fine for one hand-issued key. It cannot express
    "this key belongs to a subscription that lapsed last night". Keys now carry
    a tier, a status, and a Stripe subscription id, so cancellation is a state
    change rather than a redeploy.

IDEMPOTENCY IS NOT OPTIONAL
    Stripe retries webhooks. Without a dedupe table a retried
    checkout.session.completed issues a second key for one payment, and the
    customer ends up with two — one of which nobody knows about.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

STRIPE_API = "https://api.stripe.com/v1"

# Stripe's Managed Payments (default-on for new accounts) refuses any line item
# whose product has no tax code — it needs one to work out VAT/GST/sales tax per
# jurisdiction on your behalf. Without it, checkout fails with a 400 that never
# reaches the customer, so this is not optional.
#
#   txcd_10103001  SaaS, business use     <- a developer tool sold to companies
#   txcd_10103000  SaaS, personal use
#   txcd_10000000  General electronically supplied services
#
# Override with NULLSCAN_TAX_CODE if your accountant disagrees; the eligible
# list is at https://docs.stripe.com/tax/tax-codes
DEFAULT_TAX_CODE = os.environ.get("NULLSCAN_TAX_CODE", "txcd_10103001")


@dataclass(frozen=True, slots=True)
class Tier:
    slug: str
    name: str
    price_cents: int
    monthly_scans: int
    blurb: str


TIERS: dict[str, Tier] = {
    "indie": Tier("indie", "Indie", 1900, 200,
                  "One developer, unlimited apps, build-over-build diffs."),
    "studio": Tier("studio", "Studio", 9900, 2000,
                   "Agencies and teams. CI integration and priority scanning."),
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS api_keys (
    key             TEXT PRIMARY KEY,
    tier            TEXT NOT NULL,
    email           TEXT,
    status          TEXT NOT NULL DEFAULT 'active',
    customer_id     TEXT,
    subscription_id TEXT,
    created_at      REAL NOT NULL,
    updated_at      REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_keys_sub  ON api_keys(subscription_id);
CREATE INDEX IF NOT EXISTS idx_keys_cust ON api_keys(customer_id);

CREATE TABLE IF NOT EXISTS stripe_events (
    event_id   TEXT PRIMARY KEY,
    kind       TEXT,
    handled_at REAL NOT NULL
);
"""


class BillingStore:
    def __init__(self, db_path: str) -> None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._path = db_path
        with self._conn() as c:
            c.executescript(_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self._path, timeout=15.0, isolation_level=None)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=15000")
        c.row_factory = sqlite3.Row
        return c

    # --- keys ----------------------------------------------------------------
    def issue(self, tier: str, email: str | None,
              customer_id: str | None, subscription_id: str | None) -> str:
        # nsk_ prefix so a leaked key is greppable in logs and recognisable in
        # a screenshot; token_urlsafe(32) is 256 bits of entropy.
        key = "nsk_" + secrets.token_urlsafe(32)
        now = time.time()
        with self._conn() as c:
            c.execute(
                "INSERT INTO api_keys (key,tier,email,status,customer_id,"
                "subscription_id,created_at,updated_at) VALUES (?,?,?,'active',?,?,?,?)",
                (key, tier, (email or "").lower() or None, customer_id,
                 subscription_id, now, now),
            )
        return key

    def lookup(self, key: str) -> dict[str, Any] | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM api_keys WHERE key=?", (key,)).fetchone()
        return dict(row) if row else None

    def set_status(self, *, subscription_id: str, status: str) -> int:
        with self._conn() as c:
            cur = c.execute(
                "UPDATE api_keys SET status=?, updated_at=? WHERE subscription_id=?",
                (status, time.time(), subscription_id),
            )
        return cur.rowcount

    def key_for_subscription(self, subscription_id: str) -> str | None:
        with self._conn() as c:
            row = c.execute("SELECT key FROM api_keys WHERE subscription_id=?",
                            (subscription_id,)).fetchone()
        return row["key"] if row else None

    # --- webhook idempotency -------------------------------------------------
    def seen_event(self, event_id: str, kind: str) -> bool:
        """True if already processed. Stripe retries; this is what stops a
        retried checkout.session.completed from issuing a second key."""
        try:
            with self._conn() as c:
                c.execute(
                    "INSERT INTO stripe_events (event_id, kind, handled_at) VALUES (?,?,?)",
                    (event_id, kind, time.time()),
                )
            return False
        except sqlite3.IntegrityError:
            return True


# --- Stripe REST -------------------------------------------------------------
class StripeError(RuntimeError):
    pass


def _post(path: str, secret_key: str, params: list[tuple[str, str]],
          *, idempotency_key: str | None = None, timeout: int = 20) -> dict[str, Any]:
    body = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(f"{STRIPE_API}{path}", data=body, method="POST")
    req.add_header("Authorization", f"Bearer {secret_key}")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if idempotency_key:
        req.add_header("Idempotency-Key", idempotency_key)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:400]
        raise StripeError(f"stripe {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise StripeError(f"stripe unreachable: {exc.reason}") from exc


def create_checkout_session(
    *, secret_key: str, tier: Tier, success_url: str, cancel_url: str,
    email: str | None = None, tax_code: str = "",
) -> dict[str, Any]:
    """Build a Checkout session with an inline price.

    Inline `price_data` rather than pre-created Price objects: it keeps pricing
    in version control next to the tier definition instead of split between the
    repo and a dashboard where the two can silently disagree.
    """
    params: list[tuple[str, str]] = [
        ("mode", "subscription"),
        ("success_url", success_url),
        ("cancel_url", cancel_url),
        ("line_items[0][quantity]", "1"),
        ("line_items[0][price_data][currency]", "usd"),
        ("line_items[0][price_data][recurring][interval]", "month"),
        ("line_items[0][price_data][unit_amount]", str(tier.price_cents)),
        ("line_items[0][price_data][product_data][name]", f"NULLSCAN {tier.name}"),
        ("line_items[0][price_data][product_data][description]", tier.blurb),
        ("line_items[0][price_data][product_data][tax_code]", tax_code or DEFAULT_TAX_CODE),
        ("metadata[tier]", tier.slug),
        ("subscription_data[metadata][tier]", tier.slug),
        ("allow_promotion_codes", "true"),
    ]
    if email:
        params.append(("customer_email", email))
    return _post("/checkout/sessions", secret_key, params)


def create_portal_session(*, secret_key: str, customer_id: str,
                          return_url: str) -> dict[str, Any]:
    """Stripe's hosted billing portal. Cancellations, card updates and invoices
    all live there — building any of that ourselves would be weeks of work to
    reproduce something customers already trust."""
    return _post("/billing_portal/sessions", secret_key,
                 [("customer", customer_id), ("return_url", return_url)])


def verify_webhook(payload: bytes, sig_header: str, secret: str,
                   *, tolerance_s: int = 300) -> dict[str, Any]:
    """Verify a Stripe signature and return the parsed event.

    Two checks, both required. The HMAC proves the body came from Stripe. The
    timestamp tolerance stops a captured-and-replayed webhook from re-firing a
    provisioning event weeks later — the signature stays valid forever, so
    without the clock check a replay is indistinguishable from the original.
    """
    if not secret:
        raise StripeError("webhook secret not configured")

    parts = dict(
        p.split("=", 1) for p in sig_header.split(",") if "=" in p
    )
    ts, v1 = parts.get("t"), parts.get("v1")
    if not ts or not v1:
        raise StripeError("malformed Stripe-Signature header")

    try:
        age = abs(time.time() - int(ts))
    except ValueError as exc:
        raise StripeError("bad timestamp in signature") from exc
    if age > tolerance_s:
        raise StripeError(f"signature timestamp is {int(age)}s old")

    expected = hmac.new(secret.encode(), f"{ts}.".encode() + payload,
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, v1):
        raise StripeError("signature mismatch")

    try:
        return json.loads(payload)
    except ValueError as exc:
        raise StripeError("event body is not JSON") from exc


def sign_webhook(payload: bytes, secret: str, ts: int | None = None) -> str:
    """Produce a valid Stripe-Signature. Used by the tests, and by you when
    replaying an event locally without the Stripe CLI."""
    t = int(ts if ts is not None else time.time())
    mac = hmac.new(secret.encode(), f"{t}.".encode() + payload, hashlib.sha256)
    return f"t={t},v1={mac.hexdigest()}"


def apply_event(event: dict[str, Any], store: BillingStore) -> dict[str, Any]:
    """Pure-ish reducer: Stripe event in, provisioning action out.

    Kept separate from the HTTP handler so the fulfilment logic is testable
    without a server, a network, or a Stripe account.
    """
    kind = event.get("type", "")
    obj = (event.get("data") or {}).get("object") or {}
    event_id = event.get("id") or ""

    if event_id and store.seen_event(event_id, kind):
        return {"action": "duplicate_ignored", "type": kind}

    if kind == "checkout.session.completed":
        tier = (obj.get("metadata") or {}).get("tier", "indie")
        if tier not in TIERS:
            tier = "indie"
        sub = obj.get("subscription")
        # Second guard behind the event dedupe: if a subscription somehow
        # arrives twice under different event ids, reuse the existing key
        # rather than minting an orphan the customer never sees.
        if sub:
            existing = store.key_for_subscription(str(sub))
            if existing:
                return {"action": "already_provisioned", "key": existing, "tier": tier}
        key = store.issue(
            tier=tier,
            email=obj.get("customer_email") or (obj.get("customer_details") or {}).get("email"),
            customer_id=obj.get("customer"),
            subscription_id=str(sub) if sub else None,
        )
        return {"action": "key_issued", "key": key, "tier": tier}

    if kind in ("customer.subscription.deleted",):
        n = store.set_status(subscription_id=str(obj.get("id")), status="canceled")
        return {"action": "key_revoked", "updated": n}

    if kind == "invoice.payment_failed":
        sub = obj.get("subscription")
        n = store.set_status(subscription_id=str(sub), status="past_due") if sub else 0
        return {"action": "key_past_due", "updated": n}

    if kind == "invoice.paid":
        sub = obj.get("subscription")
        n = store.set_status(subscription_id=str(sub), status="active") if sub else 0
        return {"action": "key_reactivated", "updated": n}

    return {"action": "ignored", "type": kind}
