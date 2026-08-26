"""
tests.test_engine — runnable without pytest: `python3 tests/test_engine.py`
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import Policy, PolicyError, analyze_path, diff_reports
from core.policy import DEFAULT_POLICY_TOML
from core.axml import parse_axml
from core.dex import parse_dex
from tests.fixtures import AxmlBuilder, build_apk, build_dex

PASS = FAIL = 0


def check(name: str, cond: bool, extra: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  \033[32mPASS\033[0m {name}")
    else:
        FAIL += 1
        print(f"  \033[31mFAIL\033[0m {name} {extra}")


def make_manifest(*, target_sdk: int = 33, debuggable: bool = True) -> bytes:
    b = AxmlBuilder()
    b.start("manifest", {"package": "com.ghostdroid.demo",
                         "android:versionCode": 47,
                         "android:versionName": "1.4.7"})
    b.element("uses-sdk", {"android:minSdkVersion": 24,
                           "android:targetSdkVersion": target_sdk})
    for p in ("android.permission.INTERNET",
              "android.permission.ACCESS_FINE_LOCATION",
              "android.permission.READ_CONTACTS",
              "android.permission.QUERY_ALL_PACKAGES",
              "android.permission.CAMERA"):
        b.element("uses-permission", {"android:name": p})
    b.start("application", {"android:label": "Demo",
                            "android:debuggable": debuggable,
                            "android:usesCleartextTraffic": True})
    b.start("activity", {"android:name": ".MainActivity", "android:exported": True})
    b.element("intent-filter")
    b.end("activity")
    b.element("service", {"android:name": ".SyncService", "android:exported": True})
    b.element("receiver", {"android:name": ".BootRx", "android:exported": False})
    b.end("application")
    b.end("manifest")
    return b.build()


def make_dex() -> bytes:
    return build_dex(
        class_descriptors=["Lcom/ghostdroid/demo/MainActivity;",
                           "Lcom/ghostdroid/demo/SyncService;"],
        methods=[
            ("Landroid/telephony/TelephonyManager;", "getDeviceId"),
            ("Lcom/google/android/gms/location/FusedLocationProviderClient;",
             "getLastLocation"),
            ("Landroid/content/pm/PackageManager;", "getInstalledPackages"),
            ("Landroid/webkit/WebView;", "addJavascriptInterface"),
            ("Lcom/google/firebase/analytics/FirebaseAnalytics;", "logEvent"),
            ("Lcom/facebook/appevents/AppEventsLogger;", "logEvent"),
            ("Lcom/appsflyer/AppsFlyerLib;", "start"),
            ("Lcom/stripe/android/Stripe;", "confirmPayment"),
            ("Lokhttp3/OkHttpClient;", "newCall"),
        ],
        extra_strings=[
            "http://api.ghostdroid.dev/v1/track",
            "AIzaSyD-1234567890abcdefghijklmnopqrstu",
            "https://secure.example.com/ok",
        ],
    )


def main() -> int:
    print("\n\033[1m[1] AXML round-trip\033[0m")
    root = parse_axml(make_manifest())
    check("root tag is <manifest>", root.tag == "manifest", root.tag)
    check("package attribute", root.attrs.get("package") == "com.ghostdroid.demo",
          str(root.attrs))
    check("versionCode int decoded", root.get("versionCode") == "47", root.get("versionCode"))
    perms = [n.get("name") for n in root.find_all("uses-permission")]
    check("5 permissions", len(perms) == 5, str(perms))
    check("FINE_LOCATION present",
          "android.permission.ACCESS_FINE_LOCATION" in perms)
    app = root.find_all("application")[0]
    check("boolean attr decoded", app.get("debuggable") == "true", app.get("debuggable"))
    check("nested intent-filter found", len(root.find_all("intent-filter")) == 1)

    print("\n\033[1m[2] DEX round-trip\033[0m")
    tables = parse_dex(make_dex())
    check("types parsed", len(tables.types) >= 9, str(len(tables.types)))
    check("method ref shape",
          "Landroid/telephony/TelephonyManager;->getDeviceId" in tables.method_refs)
    check("defined classes only", len(tables.defined_classes) == 2,
          str(tables.defined_classes))
    check("string blob intact",
          "http://api.ghostdroid.dev/v1/track" in tables.strings)

    print("\n\033[1m[3] Full pipeline\033[0m")
    tmp = tempfile.mkdtemp()
    apk = build_apk(os.path.join(tmp, "head.apk"), make_manifest(),
                    {"classes.dex": make_dex()},
                    native={"lib/arm64-v8a/libnative.so": 2048})
    rep = analyze_path(apk)
    check("no engine errors", not rep["errors"], str(rep["errors"]))
    check("sha256 computed", len(rep["apk_sha256"]) == 64)

    slugs = {s["slug"] for s in rep["sdks"]}
    check("firebase detected", "firebase-analytics" in slugs, str(slugs))
    check("facebook detected", "facebook" in slugs, str(slugs))
    check("appsflyer detected", "appsflyer" in slugs, str(slugs))
    check("stripe detected", "stripe" in slugs, str(slugs))
    check("okhttp (non-collecting) detected", "okhttp" in slugs, str(slugs))

    fids = {f["id"] for f in rep["findings"]}
    check("device id sink", "sink.device_id" in fids, str(sorted(fids)))
    check("location sink", "sink.location" in fids)
    check("installed apps sink", "sink.installed_apps" in fids)
    check("webview js bridge", "sink.webview_js" in fids)
    check("debuggable flagged", "manifest.debuggable" in fids)
    check("sensitive perms flagged", "manifest.sensitive_permissions" in fids)
    check("exported unguarded service", "manifest.exported_unguarded" in fids)
    check("cleartext manifest flag", "manifest.cleartext_allowed" in fids)
    check("target sdk stale (33 < 34)", "manifest.target_sdk_stale" in fids)
    check("google api key found", "secret.google_api_key" in fids, str(sorted(fids)))
    check("cleartext endpoint found", "net.cleartext_endpoint" in fids)
    check("native surface noted", "native.surface_present" in fids)

    cats = {d["category"] for d in rep["declaration"]}
    check("precise location declared (FINE present)", "location.precise" in cats, str(cats))
    check("contacts declared", "contacts" in cats, str(cats))
    check("financial declared (stripe)", "financial" in cats, str(cats))
    check("device ids declared", "device_or_other_ids" in cats, str(cats))
    shared = {d["category"] for d in rep["declaration"] if d["shared"]}
    check("device ids marked shared", "device_or_other_ids" in shared, str(shared))
    justified = all(d["justification"] for d in rep["declaration"])
    check("every declaration row has evidence", justified)

    print("\n\033[1m[4] Location downgrade heuristic\033[0m")
    b = AxmlBuilder()
    b.start("manifest", {"package": "com.ghostdroid.coarse"})
    b.element("uses-sdk", {"android:minSdkVersion": 24, "android:targetSdkVersion": 34})
    b.element("uses-permission", {"android:name": "android.permission.ACCESS_COARSE_LOCATION"})
    b.start("application", {"android:label": "Coarse"})
    b.end("application")
    b.end("manifest")
    coarse_apk = build_apk(
        os.path.join(tmp, "coarse.apk"), b.build(),
        {"classes.dex": build_dex(
            class_descriptors=["Lcom/ghostdroid/coarse/App;"],
            methods=[("Lcom/google/android/gms/location/FusedLocationProviderClient;",
                      "getLastLocation")])},
    )
    crep = analyze_path(coarse_apk)
    ccats = {d["category"] for d in crep["declaration"]}
    check("precise downgraded to approximate",
          "location.precise" not in ccats and "location.approximate" in ccats, str(ccats))

    print("\n\033[1m[5] Compliance drift\033[0m")
    base_apk = build_apk(
        os.path.join(tmp, "base.apk"),
        make_manifest(target_sdk=34, debuggable=False),
        {"classes.dex": build_dex(
            class_descriptors=["Lcom/ghostdroid/demo/MainActivity;"],
            methods=[("Lokhttp3/OkHttpClient;", "newCall")])},
    )
    base = analyze_path(base_apk)
    drift = diff_reports(base, rep).to_dict()
    check("new SDKs detected", len(drift["new_sdks"]) >= 4, str(drift["new_sdks"]))
    check("new categories detected", len(drift["new_categories"]) > 0,
          str(drift["new_categories"]))
    check("marked blocking", drift["blocking"] is True)
    check("summary non-empty", bool(drift["summary"]), drift["summary"])
    print(f"       drift: {drift['summary']}")

    idem = diff_reports(rep, rep).to_dict()
    check("self-diff is clean", not idem["blocking"] and not idem["new_categories"])

    print("\n\033[1m[6] Container hardening\033[0m")
    import zipfile
    bomb = os.path.join(tmp, "bomb.apk")
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", make_manifest())
        zf.writestr("payload.bin", b"\x00" * (80 * 1024 * 1024))
    brep = analyze_path(bomb)
    check("zip bomb rejected", bool(brep["errors"]) and "bomb" in brep["errors"][0],
          str(brep["errors"]))

    notapk = os.path.join(tmp, "nope.apk")
    with open(notapk, "wb") as fh:
        fh.write(b"this is not a zip at all")
    nrep = analyze_path(notapk)
    check("non-zip rejected gracefully", bool(nrep["errors"]))

    plainzip = os.path.join(tmp, "plain.zip")
    with zipfile.ZipFile(plainzip, "w") as zf:
        zf.writestr("readme.txt", "hello")
    prep = analyze_path(plainzip)
    check("zip without manifest rejected", "no AndroidManifest.xml" in prep["errors"][0],
          str(prep["errors"]))

    print("\n\033[1m[7] Corrupt-DEX resilience\033[0m")
    broken = build_apk(os.path.join(tmp, "broken.apk"), make_manifest(),
                       {"classes.dex": make_dex(),
                        "classes2.dex": b"dex\n035\x00" + b"\xff" * 200})
    brep2 = analyze_path(broken)
    check("bad dex recorded as error, not crash", any("classes2" in e for e in brep2["errors"]),
          str(brep2["errors"]))
    check("good dex still analysed", len(brep2["sdks"]) >= 4, str(len(brep2["sdks"])))

    print("\n\033[1m[8] Policy engine\033[0m")
    import tomllib as _toml

    pol = Policy.from_dict(_toml.loads(DEFAULT_POLICY_TOML))
    check("shipped default policy parses", len(pol.rules) == 8, str(len(pol.rules)))

    # The shipped policy contains drift rules. A first scan has no baseline, so
    # if those raised instead of skipping, the default config would fail on the
    # very first run a customer ever does.
    d0 = pol.evaluate(rep).to_dict()
    check("drift rules skip without a baseline", len(d0["skipped"]) == 3, str(d0["skipped"]))
    check("non-drift rules still enforce",
          any(r["matched"] for r in d0["results"]), str(d0["summary"]))
    check("debuggable build is blocked",
          any(r["rule_id"] == "no-debuggable-release" and r["matched"]
              for r in d0["results"]), str(d0["results"]))
    check("blocked implies exit-worthy", d0["blocked"] is True)

    d1 = pol.evaluate(rep, drift).to_dict()
    check("with a baseline, drift rules run", not d1["skipped"], str(d1["skipped"]))

    clean = pol.evaluate(base).to_dict()
    check("clean build passes the policy", clean["blocked"] is False, clean["summary"])

    # waivers
    waiver = Policy.from_dict({
        "meta": {"name": "w"},
        "rule": [
            {"id": "block-dev-id", "action": "block", "when": {"finding": "sink.device_id"}},
            {"id": "accept", "action": "ignore", "expires": "2099-01-01",
             "when": {"finding": "sink.device_id"}},
        ]})
    wd = waiver.evaluate(rep).to_dict()
    check("live waiver suppresses the block", wd["blocked"] is False, str(wd["summary"]))
    check("waiver is reported, not silent", "accept" in wd["waived"], str(wd["waived"]))

    stale = Policy.from_dict({
        "meta": {"name": "w2"},
        "rule": [
            {"id": "block-dev-id", "action": "block", "when": {"finding": "sink.device_id"}},
            {"id": "old", "action": "ignore", "expires": "2020-01-01",
             "when": {"finding": "sink.device_id"}},
        ]})
    sd = stale.evaluate(rep).to_dict()
    check("expired waiver stops suppressing", sd["blocked"] is True, str(sd["summary"]))
    check("expired waiver is announced", sd["expired_waivers"], str(sd["expired_waivers"]))

    # validation
    for label, bad in (
        ("waiver without an expiry",
         {"meta": {}, "rule": [{"id": "x", "action": "ignore", "when": {"finding": "a"}}]}),
        ("unknown condition",
         {"meta": {}, "rule": [{"id": "x", "action": "block", "when": {"findings": "a"}}]}),
        ("unknown action",
         {"meta": {}, "rule": [{"id": "x", "action": "explode", "when": {"finding": "a"}}]}),
        ("duplicate rule id",
         {"meta": {}, "rule": [{"id": "x", "action": "block", "when": {"finding": "a"}},
                               {"id": "x", "action": "warn", "when": {"finding": "b"}}]}),
        ("empty when block",
         {"meta": {}, "rule": [{"id": "x", "action": "block", "when": {}}]}),
        ("no rules at all", {"meta": {}, "rule": []}),
    ):
        try:
            Policy.from_dict(bad)
            check(label + " rejected", False, "accepted!")
        except PolicyError:
            check(label + " rejected", True)

    # glob + allowlist, the conditions agencies actually use
    globbed = Policy.from_dict({"meta": {}, "rule": [
        {"id": "g", "action": "block", "when": {"finding": "manifest.*"}}]})
    check("glob matches a finding family",
          globbed.evaluate(rep).to_dict()["blocked"] is True)

    allow = Policy.from_dict({"meta": {}, "rule": [
        {"id": "a", "action": "block",
         "when": {"sdk_not_in": [s["slug"] for s in rep["sdks"]]}}]})
    check("allowlist covering every SDK does not fire",
          allow.evaluate(rep).to_dict()["blocked"] is False)
    allow2 = Policy.from_dict({"meta": {}, "rule": [
        {"id": "a", "action": "block", "when": {"sdk_not_in": ["okhttp"]}}]})
    check("allowlist catches an unapproved SDK",
          allow2.evaluate(rep).to_dict()["blocked"] is True)

    # ANDed conditions
    anded = Policy.from_dict({"meta": {}, "rule": [
        {"id": "and", "action": "block",
         "when": {"debuggable": True, "finding": "no.such.finding"}}]})
    check("all conditions must hold (AND, not OR)",
          anded.evaluate(rep).to_dict()["blocked"] is False)

    print("\n\033[1m[9] Ambiguous-namespace false positives\033[0m")
    # com/facebook/common and com/facebook/bolts are shared between Meta's
    # tracking SDK, Fresco (image loading) and standalone Bolts-Android. A
    # corpus run tempted me into matching them; that would declare "shares data
    # with Meta" for any app that merely loads images. Wrong legal declaration
    # is the worst failure mode this product has, so it is pinned here.
    fb = AxmlBuilder()
    fb.start("manifest", {"package": "com.photos.app"})
    fb.element("uses-sdk", {"android:minSdkVersion": 24, "android:targetSdkVersion": 34})
    fb.start("application", {"android:label": "P"})
    fb.end("application")
    fb.end("manifest")
    fresco_apk = build_apk(
        os.path.join(tmp, "fresco.apk"), fb.build(),
        {"classes.dex": build_dex(
            class_descriptors=["Lcom/photos/app/Main;"],
            methods=[("Lcom/facebook/common/logging/FLog;", "d"),
                     ("Lcom/facebook/imagepipeline/core/ImagePipeline;", "fetch"),
                     ("Lcom/facebook/drawee/view/SimpleDraweeView;", "setImageURI"),
                     ("Lcom/facebook/soloader/SoLoader;", "init"),
                     ("Lcom/facebook/bolts/Task;", "call")])})
    frep = analyze_path(fresco_apk)
    fslugs = {s["slug"] for s in frep["sdks"]}
    check("Fresco-only app not flagged as Meta tracking SDK",
          "facebook" not in fslugs, str(fslugs))
    check("Fresco-only app declares nothing",
          not frep["declaration"], str(frep["declaration"]))

    print("\n\033[1m[10] Architecture boundary\033[0m")
    import subprocess
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    r = subprocess.run(
        ["grep", "-rnE", r"^\s*(from|import)\s+(fastapi|starlette|pydantic|service)",
         os.path.join(root_dir, "core")],
        capture_output=True, text=True,
    )
    check("core/ imports no web framework", r.returncode != 0, r.stdout.strip())

    print(f"\n\033[1m{PASS} passed, {FAIL} failed\033[0m\n")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
