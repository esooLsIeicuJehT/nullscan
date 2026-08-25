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

from fastapi.testclient import TestClient          # noqa: E402

from service.main import app                       # noqa: E402
from tests.fixtures import build_apk               # noqa: E402
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
        key = res["key"]
        check("key is prefixed and long", key.startswith("nsk_") and len(key) > 30, key)
        check("tier from metadata", res["tier"] == "studio", str(res))

        dup = apply_event(evt, bstore)
        check("retried webhook does NOT issue a second key",
              dup["action"] == "duplicate_ignored", str(dup))
        evt2 = dict(evt, id="evt_2")
        dup2 = apply_event(evt2, bstore)
        check("same subscription under a new event id reuses the key",
              dup2.get("key") == key, str(dup2))

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

        print("\n\033[1m[13] OpenAPI contract is real\033[0m")
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
