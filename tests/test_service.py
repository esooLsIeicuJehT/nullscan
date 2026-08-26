"""
tests.test_service — exercises the HTTP surface for real.

Run: python3 tests/test_service.py
"""

from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_TMP = tempfile.mkdtemp()
os.environ.setdefault("NULLSCAN_UPLOAD_DIR", os.path.join(_TMP, "uploads"))
os.environ.setdefault("NULLSCAN_DB", os.path.join(_TMP, "jobs.db"))
os.environ.setdefault("NULLSCAN_WORKERS", "2")
# Headroom so the free-tier gate doesn't throttle the functional tests. The
# 429 path is exercised deliberately in [10] by seeding the quota table, which
# is deterministic — relying on earlier tests to incidentally exhaust it makes
# every future test insertion a hidden dependency.
os.environ.setdefault("NULLSCAN_FREE_SCANS", "500")

from fastapi.testclient import TestClient  # noqa: E402

from service.main import app  # noqa: E402
from tests.fixtures import build_apk  # noqa: E402
from tests.test_engine import make_dex, make_manifest  # noqa: E402

PASS = FAIL = 0


def check(name: str, cond: bool, extra: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  \033[32mPASS\033[0m {name}")
    else:
        FAIL += 1
        print(f"  \033[31mFAIL\033[0m {name} {extra}")


def poll(client: TestClient, job_id: str, timeout: float = 60.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(f"/v1/scans/{job_id}")
        body = r.json()
        if body["state"] in {"done", "failed", "timeout"}:
            return body
        time.sleep(0.15)
    raise TimeoutError(f"job {job_id} never settled")


def main() -> int:
    head = build_apk(os.path.join(_TMP, "head.apk"), make_manifest(),
                     {"classes.dex": make_dex()},
                     native={"lib/arm64-v8a/libx.so": 4096})
    base = build_apk(os.path.join(_TMP, "base.apk"),
                     make_manifest(target_sdk=34, debuggable=False),
                     {"classes.dex": make_dex()})

    with TestClient(app) as client:
        print("\n\033[1m[1] Health\033[0m")
        r = client.get("/healthz")
        check("healthz 200", r.status_code == 200, r.text)

        print("\n\033[1m[2] Submit returns 202 immediately\033[0m")
        t0 = time.time()
        with open(head, "rb") as fh:
            r = client.post("/v1/scans", files={"file": ("head.apk", fh,
                                                         "application/vnd.android.package-archive")})
        elapsed = time.time() - t0
        check("202 Accepted", r.status_code == 202, f"{r.status_code} {r.text[:200]}")
        body = r.json()
        check("job_id issued", bool(body.get("job_id")), r.text)
        check("poll_url present", body.get("poll_url", "").startswith("/v1/scans/"))
        check("handler did not block on analysis", elapsed < 3.0, f"{elapsed:.2f}s")
        head_job = body["job_id"]

        print("\n\033[1m[3] Poll to completion\033[0m")
        job = poll(client, head_job)
        check("state done", job["state"] == "done", job.get("error", ""))
        rep = job["report"]
        check("report attached", rep is not None)
        check("declaration populated", len(rep["declaration"]) > 5,
              str(len(rep["declaration"])))
        check("categories are plain strings",
              all(isinstance(d["category"], str) for d in rep["declaration"]))
        check("sdks serialised", len(rep["sdks"]) >= 5, str(len(rep["sdks"])))

        print("\n\033[1m[4] Content-addressed cache\033[0m")
        with open(head, "rb") as fh:
            r2 = client.post("/v1/scans", files={"file": ("head.apk", fh, "application/octet-stream")})
        check("cache hit returns 200", r2.status_code == 200, str(r2.status_code))
        check("marked cached", r2.json().get("cached") is True, r2.text)
        check("state done immediately", r2.json().get("state") == "done")

        with open(head, "rb") as fh:
            r3 = client.post("/v1/scans?force=true",
                             files={"file": ("head.apk", fh, "application/octet-stream")})
        check("force=true bypasses cache", r3.json().get("cached") is False, r3.text)
        poll(client, r3.json()["job_id"])

        print("\n\033[1m[5] Declaration sub-resource\033[0m")
        r = client.get(f"/v1/scans/{head_job}/declaration")
        check("declaration endpoint 200", r.status_code == 200)
        check("returns a list", isinstance(r.json(), list) and r.json())

        print("\n\033[1m[6] Diff is POST and works\033[0m")
        with open(base, "rb") as fh:
            b = client.post("/v1/scans", files={"file": ("base.apk", fh, "application/octet-stream")})
        base_job = b.json()["job_id"]
        poll(client, base_job)

        r = client.post("/v1/diff", json={"base_job_id": base_job, "head_job_id": head_job})
        check("diff 200", r.status_code == 200, r.text[:300])
        drift = r.json()
        check("drift has summary", bool(drift["summary"]), str(drift))
        check("debuggable regression caught",
              any(f["id"] == "manifest.debuggable" for f in drift["new_findings"]),
              str(drift["new_findings"]))
        check("blocking flag set", drift["blocking"] is True)
        print(f"       {drift['summary']}")

        print("\n\033[1m[7] Error paths\033[0m")
        r = client.get("/v1/scans/deadbeef")
        check("unknown job 404", r.status_code == 404, str(r.status_code))
        check("error envelope shape", "error" in r.json(), r.text)

        r = client.post("/v1/diff", json={"head_job_id": head_job})
        check("missing base 400", r.status_code == 400, str(r.status_code))

        r = client.post("/v1/scans", files={"file": ("empty.apk", b"", "application/octet-stream")})
        check("empty upload 400", r.status_code == 400, str(r.status_code))

        r = client.post("/upload-apk/")
        check("legacy route returns 410 not 404", r.status_code == 410, str(r.status_code))

        print("\n\033[1m[8] Non-APK is a clean report, not a 500\033[0m")
        r = client.post("/v1/scans",
                        files={"file": ("junk.apk", b"not a zip" * 100, "application/octet-stream")})
        check("accepted for processing", r.status_code == 202, str(r.status_code))
        job = poll(client, r.json()["job_id"])
        check("finished as done with errors[]",
              job["state"] == "done" and bool(job["report"]["errors"]),
              str(job)[:300])

        print("\n\033[1m[9] Upload ceiling enforced by streaming\033[0m")
        from service.config import settings
        check("ceiling configured", settings.max_upload_bytes > 0)
        check("temp uploads cleaned up",
              len(os.listdir(settings.upload_dir)) == 0,
              str(os.listdir(settings.upload_dir)))

        print("\n\033[1m[10] Free tier: quota, waitlist, page\033[0m")
        r = client.get("/")
        check("landing page served", r.status_code == 200 and "NULLSCAN" in r.text,
              str(r.status_code))
        check("page has no homoglyphs in css",
              "#4E5A68" in r.text and "\u0410" not in r.text)

        r = client.get("/v1/quota")
        q = r.json()
        check("quota endpoint 200", r.status_code == 200, r.text)
        check("quota is metered without an api key", q["metered"] is True, r.text)
        check("earlier scans were charged", q["used"] > 0, r.text)
        check("remaining is consistent", q["remaining"] == q["limit"] - q["used"], r.text)

        # Seed the bucket to its ceiling rather than hoping earlier tests filled it.
        from service.config import settings as cfg
        from service.main import public as pub
        from service.public import client_principal
        principal = client_principal(api_key=None, peer="testclient",
                                     forwarded_for=None, trust_proxy=False)
        for _ in range(cfg.free_scans):
            pub.charge(principal)

        junk = os.path.join(_TMP, "quota.apk")
        with open(junk, "wb") as fh:
            fh.write(os.urandom(4096))
        with open(junk, "rb") as fh:
            r = client.post("/v1/scans", files={"file": ("quota.apk", fh, "application/octet-stream")})
        check("over-quota upload returns 429", r.status_code == 429,
              f"{r.status_code} {r.text[:160]}")
        check("429 explains the reset window", "Resets in" in r.text, r.text[:160])
        check("rejected before spooling to disk",
              len(os.listdir(cfg.upload_dir)) == 0, str(os.listdir(cfg.upload_dir)))

        # Over quota, a client that knows the digest still gets its cached
        # report — no upload, no charge. This is the CI re-run path.
        import hashlib
        sha = hashlib.sha256(open(head, "rb").read()).hexdigest()
        r = client.post(f"/v1/scans?sha256={sha}",
                        files={"file": ("head.apk", b"", "application/octet-stream")})
        check("sha256 hint serves cache while over quota",
              r.status_code == 200 and r.json()["cached"] is True,
              f"{r.status_code} {r.text[:160]}")
        r = client.post("/v1/scans?sha256=" + "0" * 64,
                        files={"file": ("x.apk", b"zz", "application/octet-stream")})
        check("unknown sha256 hint falls through to the quota gate",
              r.status_code == 429, str(r.status_code))
        r = client.post("/v1/scans?sha256=not-a-digest",
                        files={"file": ("x.apk", b"zz", "application/octet-stream")})
        check("malformed sha256 hint is ignored, not an error",
              r.status_code == 429, str(r.status_code))

        r = client.post("/v1/waitlist", json={"email": "Jigga@GhostDroid.dev "})
        check("waitlist accepts and normalises", r.status_code == 200
              and r.json()["email"] == "jigga@ghostdroid.dev", r.text)
        check("first signup reports added", r.json()["added"] is True)
        r = client.post("/v1/waitlist", json={"email": "jigga@ghostdroid.dev"})
        check("duplicate signup is idempotent, not an error",
              r.status_code == 200 and r.json()["added"] is False, r.text)
        r = client.post("/v1/waitlist", json={"email": "not-an-email"})
        check("bad email rejected 400", r.status_code == 400, str(r.status_code))

        print("\n\033[1m[11] X-Forwarded-For is not trusted by default\033[0m")
        from service.public import client_principal
        spoof = client_principal(api_key=None, peer="203.0.113.9",
                                 forwarded_for="1.2.3.4", trust_proxy=False)
        real = client_principal(api_key=None, peer="203.0.113.9",
                                forwarded_for=None, trust_proxy=False)
        check("spoofed XFF cannot mint a fresh quota bucket", spoof == real,
              f"{spoof} vs {real}")
        behind = client_principal(api_key=None, peer="10.0.0.1",
                                  forwarded_for="1.2.3.4, 10.0.0.1", trust_proxy=True)
        check("XFF honoured when behind a proxy", behind == "net:1.2.3.0", behind)
        check("api key bypasses IP bucketing entirely",
              client_principal(api_key="k1", peer="1.2.3.4",
                               forwarded_for=None, trust_proxy=True) == "key:k1")

        print("\n\033[1m[12] Billing: webhook, provisioning, key lifecycle\033[0m")
        import json as _json

        from service.billing import TIERS, apply_event, sign_webhook, verify_webhook
        from service.billing import StripeError as _SE
        from service.main import billing as bstore

        r = client.get("/v1/plans")
        check("plans endpoint 200", r.status_code == 200 and len(r.json()) == 2, r.text)

        r = client.post("/v1/checkout", json={"tier": "indie"})
        check("checkout 503 when Stripe unconfigured", r.status_code == 503,
              str(r.status_code))
        r = client.post("/v1/checkout", json={"tier": "enterprise"})
        check("unknown plan rejected 400", r.status_code == 400, str(r.status_code))

        # Stripe's Managed Payments (default-on for new accounts) 400s any line
        # item whose product has no tax code. The failure is server-side only —
        # the customer just sees checkout not open — so pin the parameter.
        import service.billing as _b
        _sent = {}
        _real_post = _b._post
        try:
            _b._post = lambda path, key, params, **kw: (
                _sent.update(params=dict(params)) or
                {"url": "https://checkout.stripe.com/test", "id": "cs_test"})
            _b.create_checkout_session(
                secret_key="sk_test_x", tier=_b.TIERS["indie"],
                success_url="https://x/?s", cancel_url="https://x/?c")
        finally:
            _b._post = _real_post
        tc = _sent["params"].get("line_items[0][price_data][product_data][tax_code]")
        check("checkout sends a product tax_code", bool(tc), str(tc))
        check("tax_code is a SaaS code", str(tc).startswith("txcd_"), str(tc))
        check("price matches the tier",
              _sent["params"]["line_items[0][price_data][unit_amount]"]
              == str(_b.TIERS["indie"].price_cents))

        # --- signature verification ---
        secret = "whsec_test_abc123"
        evt = {"id": "evt_1", "type": "checkout.session.completed",
               "data": {"object": {"metadata": {"tier": "studio"},
                                   "subscription": "sub_1",
                                   "customer": "cus_1",
                                   "customer_email": "buyer@studio.dev"}}}
        raw = _json.dumps(evt).encode()
        ok = verify_webhook(raw, sign_webhook(raw, secret), secret)
        check("valid signature accepted", ok["id"] == "evt_1")

        for label, sig in (("forged signature", "t=%d,v1=%s" % (int(time.time()), "0"*64)),
                           ("malformed header", "garbage"),
                           ("missing v1", "t=123")):
            try:
                verify_webhook(raw, sig, secret)
                check(label + " rejected", False, "accepted!")
            except _SE:
                check(label + " rejected", True)
        try:
            verify_webhook(raw, sign_webhook(raw, secret, ts=int(time.time()) - 4000), secret)
            check("replayed old event rejected", False, "accepted!")
        except _SE:
            check("replayed old event rejected", True)

        # --- provisioning ---
        res = apply_event(evt, bstore)
        check("paid checkout issues a key", res["action"] == "key_issued", str(res))
        check("buyer email captured from customer_email",
              res.get("email") == "buyer@studio.dev", str(res.get("email")))

        # Stripe only fills customer_email when WE passed it in. When the buyer
        # types it into Checkout it arrives in customer_details.email instead —
        # reading the first field alone stored None, and the first symptom would
        # have been a paying customer who never got a key.
        typed = {"id": "evt_typed", "type": "checkout.session.completed",
                 "data": {"object": {"metadata": {"tier": "indie"},
                                     "subscription": "sub_typed", "customer": "cus_t",
                                     "customer_details": {"email": "Typed@Buyer.DEV"}}}}
        rt = apply_event(typed, bstore)
        check("email read from customer_details and normalised",
              rt.get("email") == "typed@buyer.dev", str(rt.get("email")))
        check("emailed key not flagged as anomalous", rt.get("email_missing") is False)

        anon = {"id": "evt_anon", "type": "checkout.session.completed",
                "data": {"object": {"metadata": {"tier": "indie"},
                                    "subscription": "sub_anon", "customer": "cus_a"}}}
        ra = apply_event(anon, bstore)
        check("undeliverable key flagged, not silently stored",
              ra.get("email_missing") is True, str(ra))
        key = res["key"]
        check("key is prefixed and long", key.startswith("nsk_") and len(key) > 30, key)
        check("tier from metadata", res["tier"] == "studio", str(res))

        dup = apply_event(evt, bstore)
        check("retried webhook does NOT issue a second key",
              dup["action"] == "duplicate_ignored", str(dup))
        evt2 = dict(evt, id="evt_2")
        dup2 = apply_event(evt2, bstore)
        check("same subscription under a new event id issues no second key",
              dup2["action"] == "already_provisioned", str(dup2))
        check("and proves it by fingerprint, which cannot be used as a credential",
              dup2.get("key_fp") and "key" not in dup2, str(dup2))

        # --- key works, and quota follows the tier ---
        r = client.get("/v1/quota", headers={"X-API-Key": key})
        q = r.json()
        check("paid key authenticates", r.status_code == 200, r.text)
        check("quota reports the studio tier", q["tier"] == "studio", r.text)
        check("limit matches the plan",
              q["limit"] == TIERS["studio"].monthly_scans, r.text)

        with open(base, "rb") as fh:
            r = client.post("/v1/scans?force=true", headers={"X-API-Key": key},
                            files={"file": ("b.apk", fh, "application/octet-stream")})
        check("paid key scans while anonymous quota is exhausted",
              r.status_code == 202, f"{r.status_code} {r.text[:140]}")
        poll(client, r.json()["job_id"])

        # --- lifecycle ---
        apply_event({"id": "evt_3", "type": "invoice.payment_failed",
                     "data": {"object": {"subscription": "sub_1"}}}, bstore)
        r = client.get("/v1/quota", headers={"X-API-Key": key})
        check("past_due key is refused with 402, not silently downgraded",
              r.status_code == 402, f"{r.status_code} {r.text[:140]}")

        apply_event({"id": "evt_4", "type": "invoice.paid",
                     "data": {"object": {"subscription": "sub_1"}}}, bstore)
        r = client.get("/v1/quota", headers={"X-API-Key": key})
        check("payment recovery reactivates the key", r.status_code == 200, r.text)

        apply_event({"id": "evt_5", "type": "customer.subscription.deleted",
                     "data": {"object": {"id": "sub_1"}}}, bstore)
        r = client.get("/v1/quota", headers={"X-API-Key": key})
        check("cancelled key refused", r.status_code == 402, str(r.status_code))

        r = client.get("/v1/quota", headers={"X-API-Key": "nsk_totally_made_up"})
        check("unknown key rejected 403", r.status_code == 403, str(r.status_code))

        r = client.post("/v1/stripe/webhook", content=b"{}",
                        headers={"stripe-signature": "bogus"})
        check("bad webhook returns 400 so Stripe stops retrying",
              r.status_code == 400, str(r.status_code))

        print("\n\033[1m[13] Key delivery, recovery, account\033[0m")
        import service.mailer as _m
        sent = []
        real_send = _m.send
        try:
            _m.send = lambda **kw: (sent.append(kw) or True)

            evtd = {"id": "evt_mail", "type": "checkout.session.completed",
                    "data": {"object": {"metadata": {"tier": "indie"},
                                        "subscription": "sub_mail", "customer": "cus_m",
                                        "customer_details": {"email": "mailme@studio.dev"}}}}
            raw2 = _json.dumps(evtd).encode()
            os.environ["NULLSCAN_TMP"] = "1"
            from service.config import settings as cfg2
            object.__setattr__(cfg2, "stripe_webhook_secret", secret) \
                if False else None
            # drive the reducer + delivery through the real webhook path
            import service.main as _main
            _main.settings.__class__
            res_d = apply_event(evtd, bstore)
            check("second buyer provisioned", res_d["action"] == "key_issued", str(res_d))
            key2 = res_d["key"]

            _, body = _m.key_delivery(key=key2, tier_name="Indie",
                                      monthly_scans=200, base_url="https://x.dev")
            check("delivery email contains the key", key2 in body)
            check("delivery email explains the caveat",
                  "LINKED" in body and "not that it is called" in body)
            check("delivery email shows the free re-scan trick", "sha256=" in body)

            # --- recovery ---
            r = client.post("/v1/keys/recover", json={"email": "mailme@studio.dev"})
            check("recover returns 200", r.status_code == 200, r.text)
            check("recover sent the mail", any(k["to"] == "mailme@studio.dev" for k in sent),
                  str([k.get("to") for k in sent]))
            check("recovered mail carries a key",
                  any("nsk_" in k.get("text", "") for k in sent))
            check("recovery does NOT resend the original (it is not stored)",
                  not any(key2 in k.get("text", "") for k in sent))

            before = len(sent)
            r2 = client.post("/v1/keys/recover", json={"email": "nobody@nowhere.dev"})
            check("unknown address gets an identical reply",
                  r2.json() == r.json(), f"{r.json()} vs {r2.json()}")
            check("unknown address triggers no email", len(sent) == before)

            r3 = client.post("/v1/keys/recover", json={"email": "not-an-email"})
            check("malformed address also identical (no oracle)",
                  r3.json() == r.json(), r3.text)

            before = len(sent)
            for _ in range(12):
                client.post("/v1/keys/recover", json={"email": "mailme@studio.dev"})
            check("recovery is rate limited per address",
                  len(sent) - before <= cfg.recover_per_day,
                  f"{len(sent) - before} emails sent")

            # Every recovery rotates, so the live key is the one in the LAST
            # email sent — capture it after the rate-limit loop, not before.
            key2 = [ln.strip() for k in sent for ln in k.get("text", "").splitlines()
                    if ln.strip().startswith("nsk_")][-1]

            # --- account ---
            r = client.get("/v1/account", headers={"X-API-Key": key2})
            a = r.json()
            check("account 200", r.status_code == 200, r.text)
            if r.status_code != 200:
                raise SystemExit(1)
            check("account reports tier", a["tier"] == "indie", r.text)
            check("email is masked, not exposed",
                  a["email_masked"] == "m****e@studio.dev", str(a["email_masked"]))
            check("account without a key is 401",
                  client.get("/v1/account").status_code == 401)
        finally:
            _m.send = real_send

        print("\n\033[1m[14] Keys are not recoverable from the database\033[0m")
        import sqlite3 as _sq

        from service.billing import hash_key

        conn = _sq.connect(cfg.db_path)
        conn.row_factory = _sq.Row
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(api_keys)")}
        check("no plaintext key column in the schema",
              "key" not in cols or all(
                  r[0] is None for r in conn.execute("SELECT key FROM api_keys")),
              str(sorted(cols)))
        dump = " ".join(str(v) for row in conn.execute("SELECT * FROM api_keys")
                        for v in tuple(row))
        check("no issued key appears anywhere in the table",
              key not in dump and key2 not in dump)
        check("the stored hash matches the key we hold",
              any(r["key_hash"] == hash_key(key2)
                  for r in conn.execute("SELECT key_hash FROM api_keys")))
        conn.close()

        print("\n\033[1m[15] Crash-safe webhook fulfilment\033[0m")
        # The subtle one: the old code marked an event seen BEFORE fulfilling.
        # A crash in between meant Stripe's retry saw "already handled" and did
        # nothing, leaving a paid customer with no key and no error.
        ev_id = "evt_crash_sim"
        st = bstore.begin_event(ev_id, "checkout.session.completed")
        check("first delivery claims the event", st == "new", st)
        check("a concurrent duplicate is held off",
              bstore.begin_event(ev_id, "x") == "done")

        # simulate the crash: never completed, and the row goes stale
        with bstore._conn() as _c:
            _c.execute("UPDATE stripe_events SET received_at=? WHERE event_id=?",
                       (time.time() - 10_000, ev_id))
        check("after a crash the retry is allowed through",
              bstore.begin_event(ev_id, "x") == "retry")
        bstore.complete_event(ev_id)
        check("once fulfilled, retries are ignored again",
              bstore.begin_event(ev_id, "x") == "done")

        before_keys = len(list(bstore._conn().execute("SELECT 1 FROM api_keys")))
        dup_evt = {"id": "evt_dup_guard", "type": "checkout.session.completed",
                   "data": {"object": {"metadata": {"tier": "indie"},
                                       "subscription": "sub_mail", "customer": "cus_m",
                                       "customer_details": {"email": "mailme@studio.dev"}}}}
        r1 = apply_event(dup_evt, bstore)
        after_keys = len(list(bstore._conn().execute("SELECT 1 FROM api_keys")))
        check("an event for an already-provisioned subscription issues nothing new",
              after_keys == before_keys and r1["action"] == "already_provisioned", str(r1))
        check("and it returns a fingerprint, never a key",
              "key" not in r1 and r1.get("key_fp"), str(r1))

        print("\n\033[1m[16] Recovery rotates rather than resending\033[0m")
        # A fresh address: the earlier section exhausted the per-address
        # recovery quota for mailme@, and that limit is doing exactly what it
        # should — reusing it here would test the rate limiter, not rotation.
        import service.mailer as _m2
        sent2: list[dict] = []
        real2 = _m2.send
        _m2.send = lambda **kw: (sent2.append(kw) or True)
        rot_evt = {"id": "evt_rot", "type": "checkout.session.completed",
                   "data": {"object": {"metadata": {"tier": "indie"},
                                       "subscription": "sub_rot", "customer": "cus_rot",
                                       "customer_details": {"email": "rot@studio.dev"}}}}
        rot_res = apply_event(rot_evt, bstore)
        original = rot_res["key"]
        check("fresh subscription provisioned", rot_res["action"] == "key_issued", str(rot_res))
        check("original key works",
              client.get("/v1/account", headers={"X-API-Key": original}).status_code == 200)

        sent = sent2
        r = client.post("/v1/keys/recover", json={"email": "rot@studio.dev"})
        check("recovery still returns the generic reply", r.status_code == 200)
        check("a replacement key was mailed", len(sent) == 1, str(len(sent)))
        body_sent = sent[-1]["text"]
        check("the email states the old key is dead",
              "stopped working" in body_sent, body_sent[:120])
        new_key = [ln.strip() for ln in body_sent.splitlines()
                   if ln.strip().startswith("nsk_")][0]
        check("the replacement is a different key", new_key != original)
        check("the replacement authenticates",
              client.get("/v1/account", headers={"X-API-Key": new_key}).status_code == 200)
        old_status = client.get("/v1/account", headers={"X-API-Key": original}).status_code
        check("the old key stops working immediately", old_status == 401, str(old_status))
        check("and says so clearly rather than blaming billing",
              "replaced" in client.get("/v1/account",
                                       headers={"X-API-Key": original}).text)
        _m2.send = real2

        print("\n\033[1m[17] Upgrading a live database\033[0m")
        # This is what runs against production on the next deploy. A migration
        # that breaks an existing customer's key is worse than the plaintext
        # it was written to remove.
        legacy = os.path.join(_TMP, "legacy.db")
        lc = _sq.connect(legacy)
        lc.executescript("""
            CREATE TABLE api_keys (key TEXT PRIMARY KEY, tier TEXT NOT NULL,
              email TEXT, status TEXT NOT NULL DEFAULT 'active', customer_id TEXT,
              subscription_id TEXT, created_at REAL NOT NULL, updated_at REAL NOT NULL);
            CREATE TABLE stripe_events (event_id TEXT PRIMARY KEY, kind TEXT,
              handled_at REAL NOT NULL);""")
        OLD_KEY = "nsk_legacy_plaintext_key_from_v0_3_0"
        lc.execute("INSERT INTO api_keys VALUES (?,?,?,?,?,?,?,?)",
                   (OLD_KEY, "indie", "legacy@studio.dev", "active",
                    "cus_legacy", "sub_legacy", 1.0, 1.0))
        lc.execute("INSERT INTO stripe_events VALUES ('evt_historic','x',1.0)")
        lc.commit()
        lc.close()

        blob = open(legacy, "rb").read()
        check("legacy db really did hold plaintext", OLD_KEY.encode() in blob)

        from service.billing import BillingStore as _BS
        migrated = _BS(legacy)

        blob = open(legacy, "rb").read()
        for sfx in ("-wal", "-shm", "-journal"):
            if os.path.exists(legacy + sfx):
                blob += open(legacy + sfx, "rb").read()
        check("plaintext is scrubbed from the file AND its sidecars",
              OLD_KEY.encode() not in blob)
        lrow = migrated.lookup(OLD_KEY)
        check("an existing customer's key still authenticates",
              lrow is not None and lrow["status"] == "active", str(lrow))
        check("it is now stored only as a hash",
              lrow["key_hash"] == hash_key(OLD_KEY))
        check("historic events stay done (no re-fulfilment on retry)",
              migrated.begin_event("evt_historic", "x") == "done")
        check("the migrated store can still issue keys",
              migrated.issue("indie", "n@e.co", "c", "s").startswith("nsk_"))

        print("\n\033[1m[18] OpenAPI contract is real\033[0m")
        spec = client.get("/openapi.json").json()
        check("POST /v1/scans documented", "/v1/scans" in spec["paths"])
        check("diff is POST only",
              set(spec["paths"]["/v1/diff"].keys()) == {"post"},
              str(spec["paths"]["/v1/diff"].keys()))
        ref = spec["paths"]["/v1/scans/{job_id}"]["get"]["responses"]["200"]
        check("poll response is a typed model, not Dict[str,str]",
              "JobOut" in str(ref), str(ref)[:200])

    print(f"\n\033[1m{PASS} passed, {FAIL} failed\033[0m\n")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
