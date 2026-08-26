"""
service.mailer — outbound email.

FLOW POSITION: terminal side-effect. Called after a key is issued or recovered.
Nothing depends on its return value; delivery failure must never lose a key
that was already provisioned.

WHY NO SDK
    Resend, Postmark and SendGrid are all "POST JSON with a Bearer token".
    That's urllib. The whole service still installs in four packages, and on
    Termux every added wheel is a possible Rust compile.

WHY IT FALLS BACK TO LOGGING
    Unconfigured, send() writes the message to the log and returns False. That
    is exactly the behaviour you already have — the key reaches you, just not
    the customer — so nothing regresses while you're in test mode. It never
    raises, because a failed email must not take down the webhook: Stripe would
    retry, and retries hit the idempotency guard and provision nothing, leaving
    a customer who paid with no key and no error anyone can see.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

log = logging.getLogger("nullscan.mail")

RESEND_API = "https://api.resend.com/emails"


def send(*, api_key: str, sender: str, to: str, subject: str,
         text: str, timeout: int = 15) -> bool:
    """Best-effort send. True if accepted, False otherwise. Never raises."""
    if not api_key or not to:
        log.warning("EMAIL NOT SENT (mailer unconfigured) to=%s subject=%s\n%s",
                    to or "?", subject, text)
        return False

    payload = json.dumps({
        "from": sender,
        "to": [to],
        "subject": subject,
        "text": text,
    }).encode()

    if not RESEND_API.startswith("https://"):
        log.error("refusing non-https mail endpoint")
        return False
    req = urllib.request.Request(RESEND_API, data=payload, method="POST")
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ok = 200 <= resp.status < 300
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:300]
        log.error("email to %s rejected: %s %s", to, exc.code, body)
        return False
    except Exception as exc:
        log.error("email to %s failed: %s", to, exc)
        return False

    if not ok:
        log.error("email to %s returned %s", to, resp.status)
    return ok


def key_delivery(*, key: str, tier_name: str, monthly_scans: int,
                 base_url: str) -> tuple[str, str]:
    subject = f"Your NULLSCAN {tier_name} API key"
    body = f"""Your NULLSCAN {tier_name} subscription is active.

API key:

    {key}

Keep this somewhere safe. It is the only credential on the account.
If you lose it, request it again at {base_url}/#account and it will be
re-sent to this address.

Quick start
-----------

Scan a build:

    curl -X POST {base_url}/v1/scans \\
      -H "X-API-Key: {key}" \\
      -F file=@app-release.apk

Poll the job id it returns:

    curl {base_url}/v1/scans/JOB_ID \\
      -H "X-API-Key: {key}"

Just the Data Safety declaration:

    curl {base_url}/v1/scans/JOB_ID/declaration \\
      -H "X-API-Key: {key}"

Two things worth knowing
------------------------

Re-scanning a build you have already scanned costs nothing. Send the
digest and skip the upload entirely:

    curl -X POST "{base_url}/v1/scans?sha256=$(sha256sum app.apk | cut -d' ' -f1)" \\
      -H "X-API-Key: {key}" -F file=@/dev/null

Your plan includes {monthly_scans:,} scans a month. Cached re-scans are
not counted.

Findings prove an API is LINKED into your app, not that it is called at
runtime — dead code inside a dependency still counts. Treat the output as
a starting point for your declaration, not the final word.

Manage billing: {base_url}/#account
"""
    return subject, body


def key_recovery(*, key: str, tier_name: str, base_url: str) -> tuple[str, str]:
    return (
        "Your new NULLSCAN API key",
        f"""You asked for the API key on this address.

We do not store your key — only a one-way hash of it — so we cannot send
the original back. Instead we have issued a replacement:

    {key}

Plan: {tier_name}

IMPORTANT: your previous key stopped working the moment this was issued.
Update your CI secrets and any local config.

If this wasn't you, someone knows your email address and nothing more —
they did not receive this key, and it only ever goes to the address that
paid. But your old key has been revoked, so you will need to use the one
above.

Manage billing: {base_url}/#account
""",
    )
