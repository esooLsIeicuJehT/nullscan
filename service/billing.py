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

import contextlib
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
    key_hash        TEXT PRIMARY KEY,
    key_fp          TEXT NOT NULL,
    tier            TEXT NOT NULL,
    email           TEXT,
    status          TEXT NOT NULL DEFAULT 'active',
    customer_id     TEXT,
    subscription_id TEXT,
    created_at      REAL NOT NULL,
    updated_at      REAL NOT NULL,
    delivery_status TEXT NOT NULL DEFAULT 'pending',
    delivery_attempts INTEGER NOT NULL DEFAULT 0,
    last_delivery_error TEXT
);
-- Event lifecycle, not a boolean. See begin_event() for why.
CREATE TABLE IF NOT EXISTS stripe_events (
    event_id     TEXT PRIMARY KEY,
    kind         TEXT,
    status       TEXT NOT NULL DEFAULT 'processing',
    attempts     INTEGER NOT NULL DEFAULT 0,
    received_at  REAL NOT NULL,
    processed_at REAL,
    last_error   TEXT
);
"""

_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_keys_sub  ON api_keys(subscription_id);
CREATE INDEX IF NOT EXISTS idx_keys_cust ON api_keys(customer_id);
CREATE INDEX IF NOT EXISTS idx_keys_fp   ON api_keys(key_fp);
"""

# A webhook stuck in 'processing' for longer than this is assumed dead (the
# process was killed mid-fulfilment) and a Stripe retry is allowed to take over.
STALE_PROCESSING_S = 300


def _pepper() -> str:
    return os.environ.get("NULLSCAN_KEY_PEPPER", "")


def hash_key(key: str) -> str:
    """SHA-256 of pepper+key.

    Keys are high-entropy random tokens, not passwords, so a slow KDF buys
    nothing here — there is no dictionary to attack. What matters is that a
    stolen database contains no usable credentials. The pepper lives in the
    environment, so a leaked DB alone is not enough to forge a lookup either.
    """
    return hashlib.sha256((_pepper() + key).encode()).hexdigest()


def fingerprint(key_hash: str) -> str:
    """Short, non-reversible handle for logs and support. Derived from the
    HASH, never from the key, so it leaks nothing about the credential."""
    return key_hash[:12]


class BillingStore:
    def __init__(self, db_path: str) -> None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._path = db_path
        with self._session() as c:
            c.executescript(_SCHEMA)
        self._migrate()
        with self._session() as c:
            c.executescript(_INDEXES)

    def _migrate(self) -> None:
        """Upgrade a database written by an earlier version.

        The first release stored raw keys. Anyone already running it has live
        credentials sitting in a file, so this hashes them in place and
        destroys the plaintext. Existing keys keep working — the customer never
        notices — but the database stops being a basket of working keys.
        """
        conn = self._conn()
        try:
            # stripe_events gained a lifecycle; the old table had only handled_at.
            ecols = {r["name"] for r in conn.execute("PRAGMA table_info(stripe_events)")}
            if ecols and "status" not in ecols:
                for col, ddl in (("status", "TEXT NOT NULL DEFAULT 'done'"),
                                 ("attempts", "INTEGER NOT NULL DEFAULT 1"),
                                 ("received_at", "REAL NOT NULL DEFAULT 0"),
                                 ("processed_at", "REAL"),
                                 ("last_error", "TEXT")):
                    if col not in ecols:
                        conn.execute(f"ALTER TABLE stripe_events ADD COLUMN {col} {ddl}")
                # Rows in the legacy table were fulfilled under the old code, so
                # they are 'done'. Defaulting them to 'processing' would let a
                # Stripe retry re-fulfil historic events.
                conn.execute("UPDATE stripe_events SET status='done', "
                             "received_at=COALESCE(handled_at,0) "
                             "WHERE status IS NULL OR status=''")

            cols = {r["name"] for r in conn.execute("PRAGMA table_info(api_keys)")}
            if "key" not in cols:
                return
            if "key_hash" not in cols:
                conn.execute("ALTER TABLE api_keys ADD COLUMN key_hash TEXT")
                conn.execute("ALTER TABLE api_keys ADD COLUMN key_fp TEXT")
            for col, ddl in (("delivery_status", "TEXT NOT NULL DEFAULT 'pending'"),
                             ("delivery_attempts", "INTEGER NOT NULL DEFAULT 0"),
                             ("last_delivery_error", "TEXT")):
                if col not in cols:
                    conn.execute(f"ALTER TABLE api_keys ADD COLUMN {col} {ddl}")

            rows = conn.execute(
                "SELECT key FROM api_keys WHERE key IS NOT NULL AND key != ''"
            ).fetchall()
            for r in rows:
                kh = hash_key(r["key"])
                conn.execute("UPDATE api_keys SET key_hash=?, key_fp=?, key=NULL "
                             "WHERE key=?", (kh, fingerprint(kh), r["key"]))
        finally:
            # Must CLOSE, not just commit. `with sqlite3.connect(...)` is a
            # transaction context manager, not a resource one — the connection
            # stays open and VACUUM below would fail with "database is locked".
            conn.close()

        if not rows:
            return

        # Scrubbing, in the only order that actually works.
        #
        # `UPDATE ... SET key=NULL` does not erase anything: SQLite frees the
        # page and moves on, so every migrated key stays readable with
        # `strings jobs.db`. VACUUM rewrites the file — but under WAL the
        # rewrite lands in the -wal sidecar and the stale page survives in both
        # until a checkpoint. Both facts were confirmed by grepping the raw
        # bytes; each fix alone still left the plaintext recoverable.
        scrub = self._conn()
        try:
            scrub.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            scrub.execute("PRAGMA journal_mode=DELETE")
            scrub.execute("PRAGMA secure_delete=ON")
            scrub.execute("VACUUM")
            scrub.execute("PRAGMA journal_mode=WAL")
            scrub.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            scrub.close()

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
        # Overwrite freed pages rather than merely marking them reusable, so a
        # rotated or revoked key does not linger in the file.
        c.execute("PRAGMA secure_delete=ON")
        c.row_factory = sqlite3.Row
        return c

    # --- keys ----------------------------------------------------------------
    def issue(self, tier: str, email: str | None,
              customer_id: str | None, subscription_id: str | None) -> str:
        # nsk_ prefix so a leaked key is greppable and recognisable in a
        # screenshot; token_urlsafe(32) is 256 bits of entropy.
        #
        # This is the ONLY moment the raw key exists on our side. It is
        # returned to the caller for delivery and never written down.
        key = "nsk_" + secrets.token_urlsafe(32)
        kh = hash_key(key)
        now = time.time()
        with self._session() as c:
            c.execute(
                "INSERT INTO api_keys (key_hash,key_fp,tier,email,status,customer_id,"
                "subscription_id,created_at,updated_at) "
                "VALUES (?,?,?,?,'active',?,?,?,?)",
                (kh, fingerprint(kh), tier, (email or "").lower() or None,
                 customer_id, subscription_id, now, now),
            )
        return key

    def lookup(self, key: str) -> dict[str, Any] | None:
        """Authenticate by hash. The raw key is never stored or compared."""
        with self._session() as c:
            row = c.execute("SELECT * FROM api_keys WHERE key_hash=?",
                            (hash_key(key),)).fetchone()
        return dict(row) if row else None

    def rotate_for_email(self, email: str) -> tuple[str, str] | None:
        """Revoke the active key for an address and issue a replacement.

        Recovery cannot re-send the original key: it is not stored, only its
        hash. That is the whole point of hashing. So "I lost my key" becomes
        "here is a new one and the old one is dead" — which is also the correct
        answer when the real reason for the request is that the key leaked.
        """
        row = self.active_key_for_email(email)
        if row is None:
            return None
        with self._session() as c:
            c.execute("UPDATE api_keys SET status='rotated', updated_at=? "
                      "WHERE key_hash=?", (time.time(), row["key_hash"]))
        new_key = self.issue(tier=row["tier"], email=row["email"],
                             customer_id=row["customer_id"],
                             subscription_id=row["subscription_id"])
        return new_key, row["tier"]

    # --- delivery tracking ---------------------------------------------------
    def mark_delivery(self, key_hash: str, status: str, error: str = "") -> None:
        with self._session() as c:
            c.execute(
                "UPDATE api_keys SET delivery_status=?, "
                "delivery_attempts=delivery_attempts+1, last_delivery_error=? "
                "WHERE key_hash=?", (status, error[:400] or None, key_hash))

    def undelivered(self, limit: int = 50) -> list[dict[str, Any]]:
        """Keys that were paid for but never reached the customer.

        Anything in here is a person who has been charged and has nothing to
        show for it, so it is swept on every startup rather than waiting for a
        support email.
        """
        with self._session() as c:
            rows = c.execute(
                "SELECT key_hash,key_fp,tier,email,delivery_attempts FROM api_keys "
                "WHERE status='active' AND delivery_status IN ('pending','failed') "
                "AND email IS NOT NULL AND delivery_attempts < 6 "
                "ORDER BY created_at LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def set_status(self, *, subscription_id: str, status: str) -> int:
        with self._session() as c:
            cur = c.execute(
                "UPDATE api_keys SET status=?, updated_at=? WHERE subscription_id=?",
                (status, time.time(), subscription_id),
            )
        return cur.rowcount

    def active_key_for_email(self, email: str) -> dict[str, Any] | None:
        """Most recent ACTIVE key for an address.

        Active only: handing back a cancelled key would look like the
        subscription still works, and the 402 they'd hit on first use is a
        worse way to learn otherwise than being told there is no key.
        """
        with self._session() as c:
            row = c.execute(
                "SELECT * FROM api_keys WHERE email=? AND status='active' "
                "ORDER BY created_at DESC LIMIT 1", ((email or "").strip().lower(),)
            ).fetchone()
        return dict(row) if row else None

    def fingerprint_for_subscription(self, subscription_id: str) -> str | None:
        """Fingerprint, not the key — we cannot return the key, and that is the
        point. A retried webhook proves a key already exists without being able
        to produce it; recovery goes through email, which proves ownership."""
        with self._session() as c:
            row = c.execute("SELECT key_fp FROM api_keys WHERE subscription_id=?",
                            (subscription_id,)).fetchone()
        return row["key_fp"] if row else None

    # --- webhook lifecycle ---------------------------------------------------
    def begin_event(self, event_id: str, kind: str) -> str:
        """Claim an event for processing. Returns "new", "retry" or "done".

        The previous version marked an event seen BEFORE fulfilment. If the
        process died in between — a deploy, an OOM, a Railway restart — the
        Stripe retry saw "already handled" and did nothing, leaving a customer
        who paid with no key and no error anywhere. Idempotent, but not
        crash-safe.

        A row is only "done" once fulfilment actually completed. A row stuck in
        'processing' past STALE_PROCESSING_S is assumed dead and the retry is
        allowed to take over.
        """
        now = time.time()
        with self._session() as c:
            try:
                c.execute(
                    "INSERT INTO stripe_events (event_id,kind,status,attempts,received_at) "
                    "VALUES (?,?,'processing',1,?)", (event_id, kind, now))
                return "new"
            except sqlite3.IntegrityError:
                pass
            row = c.execute("SELECT status, received_at FROM stripe_events "
                            "WHERE event_id=?", (event_id,)).fetchone()
            if row is None:
                return "new"
            if row["status"] == "done":
                return "done"
            if (row["status"] == "processing"
                    and now - row["received_at"] < STALE_PROCESSING_S):
                # Another worker is mid-flight. Do not double-fulfil.
                return "done"
            c.execute("UPDATE stripe_events SET status='processing', "
                      "attempts=attempts+1, received_at=? WHERE event_id=?",
                      (now, event_id))
            return "retry"

    def complete_event(self, event_id: str) -> None:
        with self._session() as c:
            c.execute("UPDATE stripe_events SET status='done', processed_at=?, "
                      "last_error=NULL WHERE event_id=?", (time.time(), event_id))

    def fail_event(self, event_id: str, error: str) -> None:
        """Leave it retryable. Stripe will resend, and begin_event will let the
        resend through because the row is not 'done'."""
        with self._session() as c:
            c.execute("UPDATE stripe_events SET status='failed', last_error=? "
                      "WHERE event_id=?", (error[:400], event_id))


# --- Stripe REST -------------------------------------------------------------
class StripeError(RuntimeError):
    pass


def _require_https(url: str) -> None:
    """Refuse anything that is not https.

    These URLs are module constants today, so this cannot currently fail. It is
    here so that stays true: the moment an endpoint becomes configurable, a
    file:// or http:// value would otherwise exfiltrate an API key or send one
    in the clear, and nothing would complain.
    """
    if not url.startswith("https://"):
        raise StripeError(f"refusing non-https endpoint: {url[:60]}")


def _post(path: str, secret_key: str, params: list[tuple[str, str]],
          *, idempotency_key: str | None = None, timeout: int = 20) -> dict[str, Any]:
    url = f"{STRIPE_API}{path}"
    _require_https(url)
    body = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(url, data=body, method="POST")
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


def _buyer_email(obj: dict[str, Any]) -> str | None:
    """Dig the buyer's address out of a Checkout session.

    Stripe only populates `customer_email` when YOU passed it when creating the
    session. When the buyer types it into Checkout — which is the normal case —
    it lands in `customer_details.email` instead. Reading only the first field
    silently stores None, and the first sign of trouble is a paying customer
    who never received a key.
    """
    for candidate in (
        obj.get("customer_email"),
        (obj.get("customer_details") or {}).get("email"),
        (obj.get("customer_details") or {}).get("name"),  # last resort identifier
    ):
        if isinstance(candidate, str) and "@" in candidate:
            return candidate.strip().lower()
    return None


def apply_event(event: dict[str, Any], store: BillingStore) -> dict[str, Any]:
    """Pure-ish reducer: Stripe event in, provisioning action out.

    Kept separate from the HTTP handler so the fulfilment logic is testable
    without a server, a network, or a Stripe account.
    """
    kind = event.get("type", "")
    obj = (event.get("data") or {}).get("object") or {}
    event_id = event.get("id") or ""

    if event_id:
        state = store.begin_event(event_id, kind)
        if state == "done":
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
            existing = store.fingerprint_for_subscription(str(sub))
            if existing:
                if event_id:
                    store.complete_event(event_id)
                return {"action": "already_provisioned", "key_fp": existing, "tier": tier}
        email = _buyer_email(obj)
        key = store.issue(
            tier=tier, email=email,
            customer_id=obj.get("customer"),
            subscription_id=str(sub) if sub else None,
        )
        # A key with no email is unusable in the ways that matter: you cannot
        # deliver it, and you cannot answer "I lost my key". Surface it as a
        # distinct action so it shows up as an anomaly rather than blending
        # into the success path.
        if event_id:
            store.complete_event(event_id)
        return {"action": "key_issued", "key": key, "key_hash": hash_key(key),
                "key_fp": fingerprint(hash_key(key)), "tier": tier,
                "email": email, "email_missing": email is None}

    if kind in ("customer.subscription.deleted",):
        n = store.set_status(subscription_id=str(obj.get("id")), status="canceled")
        if event_id:
            store.complete_event(event_id)
        return {"action": "key_revoked", "updated": n}

    if kind == "invoice.payment_failed":
        sub = obj.get("subscription")
        n = store.set_status(subscription_id=str(sub), status="past_due") if sub else 0
        if event_id:
            store.complete_event(event_id)
        return {"action": "key_past_due", "updated": n}

    if kind == "invoice.paid":
        sub = obj.get("subscription")
        n = store.set_status(subscription_id=str(sub), status="active") if sub else 0
        if event_id:
            store.complete_event(event_id)
        return {"action": "key_reactivated", "updated": n}

    if event_id:
        store.complete_event(event_id)
    return {"action": "ignored", "type": kind}
