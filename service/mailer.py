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
        # Never log message bodies here. Credential emails contain API keys and
        # logs are a second, often less protected secret store.
        log.warning("EMAIL NOT SENT (mailer unconfigured) to=%s subject=%s",
                    to or "?", subject)
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
If you lose it, request recovery at {base_url}/#account. Recovery requires
proving control of this inbox and issues a replacement key.

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


def key_recovery(*, recovery_url: str, base_url: str) -> tuple[str, str]:
    return (
        "Confirm your NULLSCAN key recovery",
        f"""You asked to recover access to NULLSCAN.

Open this one-time link to prove control of this inbox and create a replacement key:

    {recovery_url}

The link expires in 15 minutes and can only be used once. Your existing key
will remain active until the replacement is actually issued.

If you did not request this, you can safely ignore this email.

Manage billing: {base_url}/#account
""",
    )
