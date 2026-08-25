"""
core.signatures — the knowledge base.

FLOW POSITION: static data + pure matchers. This file is the product's actual
moat: anyone can write a zip reader, almost nobody maintains a curated map of
"this class prefix means this vendor collects this data category."

Treat this as versioned content, not code. When you move to a database, keep
this shape as the seed fixture and the loader signature identical.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Confidence, DataCategory, Evidence, Finding, SdkHit, Severity

DC = DataCategory


@dataclass(frozen=True, slots=True)
class SdkSignature:
    slug: str
    name: str
    vendor: str
    class_prefixes: tuple[str, ...]
    collects: tuple[DataCategory, ...]
    shares_with_third_party: bool
    privacy_url: str = ""


# --- SDK fingerprints --------------------------------------------------------
# Prefixes are DEX descriptors WITHOUT the leading 'L' for readability;
# matching normalises both sides.
SDK_SIGNATURES: tuple[SdkSignature, ...] = (
    SdkSignature("admob", "Google AdMob", "Google",
                 ("com/google/android/gms/ads", "com/google/ads"),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY, DC.LOCATION_APPROX), True,
                 "https://policies.google.com/privacy"),
    SdkSignature("firebase-analytics", "Firebase Analytics", "Google",
                 ("com/google/firebase/analytics", "com/google/android/gms/measurement"),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY, DC.APP_INFO_PERF), True),
    SdkSignature("crashlytics", "Firebase Crashlytics", "Google",
                 ("com/google/firebase/crashlytics",),
                 (DC.APP_INFO_PERF, DC.DEVICE_IDS), True),
    SdkSignature("firebase-messaging", "Firebase Cloud Messaging", "Google",
                 ("com/google/firebase/messaging",),
                 (DC.DEVICE_IDS,), True),
    SdkSignature("play-location", "Play Services Location", "Google",
                 ("com/google/android/gms/location",),
                 (DC.LOCATION_PRECISE, DC.LOCATION_APPROX), False),
    # Widened after the corpus run: com/facebook/{core,common,share,bolts,
    # applinks,ads,gamingservices} each appeared in 9-15 apps that the narrow
    # appevents/login/internal triple missed completely.
    SdkSignature("facebook", "Meta Android SDK", "Meta",
                 # NOT com/facebook/common and NOT com/facebook/bolts: those are
                 # shared with Fresco (image loading) and standalone Bolts-Android.
                 # Matching them would declare "shares data with Meta" for apps
                 # that only load images — a wrong LEGAL declaration, which is
                 # the single worst failure this product can have.
                 ("com/facebook/appevents", "com/facebook/login",
                  "com/facebook/internal", "com/facebook/core",
                  "com/facebook/share", "com/facebook/applinks",
                  "com/facebook/ads", "com/facebook/gamingservices",
                  "com/facebook/devicerequests"),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY, DC.PERSONAL_INFO, DC.PERSONAL_EMAIL), True,
                 "https://www.facebook.com/privacy/policy"),
    SdkSignature("appsflyer", "AppsFlyer", "AppsFlyer",
                 ("com/appsflyer",),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY, DC.LOCATION_APPROX), True),
    SdkSignature("adjust", "Adjust", "Adjust",
                 ("com/adjust/sdk",),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY), True),
    SdkSignature("branch", "Branch Metrics", "Branch",
                 ("io/branch/referral",),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY), True),
    SdkSignature("amplitude", "Amplitude", "Amplitude",
                 ("com/amplitude/api", "com/amplitude/android"),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY), True),
    SdkSignature("mixpanel", "Mixpanel", "Mixpanel",
                 ("com/mixpanel/android",),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY), True),
    SdkSignature("segment", "Segment Analytics", "Twilio",
                 ("com/segment/analytics",),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY), True),
    SdkSignature("onesignal", "OneSignal", "OneSignal",
                 ("com/onesignal",),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY), True),
    SdkSignature("unity-ads", "Unity Ads", "Unity",
                 ("com/unity3d/ads", "com/unity3d/services"),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY), True),
    SdkSignature("ironsource", "ironSource / LevelPlay", "Unity",
                 ("com/ironsource/mediationsdk", "com/ironsource/sdk",
                  "com/ironsource/adqualitysdk"),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY, DC.LOCATION_APPROX), True),
    SdkSignature("applovin", "AppLovin MAX", "AppLovin",
                 ("com/applovin",),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY, DC.LOCATION_APPROX), True),
    SdkSignature("vungle", "Vungle / Liftoff", "Liftoff",
                 ("com/vungle/warren", "com/vungle/ads"),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY), True),
    SdkSignature("chartboost", "Chartboost", "Chartboost",
                 ("com/chartboost/sdk",),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY), True),
    SdkSignature("mopub-pangle", "Pangle / TikTok Ads", "ByteDance",
                 ("com/bytedance/sdk/openadsdk", "com/bykv/vk"),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY, DC.LOCATION_APPROX), True),
    SdkSignature("tiktok-business", "TikTok Business SDK", "ByteDance",
                 ("com/tiktok/appevents", "com/tiktok/TikTokBusinessSdk"),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY), True),
    SdkSignature("sentry", "Sentry", "Sentry",
                 ("io/sentry",),
                 (DC.APP_INFO_PERF, DC.DEVICE_IDS), True),
    SdkSignature("bugsnag", "Bugsnag", "SmartBear",
                 ("com/bugsnag/android",),
                 (DC.APP_INFO_PERF, DC.DEVICE_IDS), True),
    SdkSignature("braze", "Braze", "Braze",
                 ("com/braze", "com/appboy"),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY, DC.PERSONAL_EMAIL), True),
    SdkSignature("intercom", "Intercom", "Intercom",
                 ("io/intercom/android",),
                 (DC.PERSONAL_EMAIL, DC.MESSAGES, DC.DEVICE_IDS), True),
    SdkSignature("stripe", "Stripe Android", "Stripe",
                 ("com/stripe/android",),
                 (DC.FINANCIAL, DC.PERSONAL_INFO), True),
    SdkSignature("braintree", "Braintree", "PayPal",
                 ("com/braintreepayments",),
                 (DC.FINANCIAL, DC.PERSONAL_INFO), True),
    SdkSignature("play-billing", "Play Billing", "Google",
                 ("com/android/billingclient",),
                 (DC.FINANCIAL,), False),
    SdkSignature("okhttp", "OkHttp", "Square",
                 ("okhttp3",), (), False),
    SdkSignature("retrofit", "Retrofit", "Square",
                 ("retrofit2",), (), False),
    SdkSignature("glide", "Glide", "Bump", ("com/bumptech/glide",), (), False),
    SdkSignature("exoplayer", "ExoPlayer / Media3", "Google",
                 ("com/google/android/exoplayer2", "androidx/media3"), (), False),
    SdkSignature("realm", "Realm", "MongoDB", ("io/realm",), (), False),
    SdkSignature("mapbox", "Mapbox", "Mapbox",
                 ("com/mapbox",), (DC.LOCATION_PRECISE, DC.DEVICE_IDS), True),
    SdkSignature("flurry", "Flurry", "Yahoo",
                 ("com/flurry/android",), (DC.DEVICE_IDS, DC.APP_ACTIVITY), True),
    SdkSignature("smaato", "Smaato", "Smaato",
                 ("com/smaato/sdk",), (DC.DEVICE_IDS, DC.LOCATION_APPROX), True),
    SdkSignature("inmobi", "InMobi", "InMobi",
                 ("com/inmobi",), (DC.DEVICE_IDS, DC.LOCATION_APPROX, DC.APP_ACTIVITY), True),

    # ---------------------------------------------------------------------
    # Mined from a 40-APK corpus of production Play builds (WhatsApp, PayPal,
    # Cash App, USAA, Coinbase, Facebook + 34 others), ranked by how many
    # distinct apps contained each prefix. These are what actually ships in
    # the wild, not a list copied off a blog.
    #
    # `collects` is deliberately conservative: a wrong entry here produces a
    # wrong LEGAL declaration, so anything unverified is omitted, not guessed.
    # ---------------------------------------------------------------------
    SdkSignature("install-referrer", "Play Install Referrer", "Google",
                 ("com/android/installreferrer",),
                 (DC.APP_ACTIVITY, DC.DEVICE_IDS), True),          # 24 of 40 apps
    SdkSignature("samsung-sdk", "Samsung Android SDK", "Samsung",
                 ("com/samsung/android",),
                 (DC.DEVICE_IDS,), False),                          # 16 of 40
    SdkSignature("miui-referrer", "Xiaomi Install Referrer", "Xiaomi",
                 ("com/miui/referrer",),
                 (DC.APP_ACTIVITY, DC.DEVICE_IDS), True),          # 15 of 40
    SdkSignature("iab-omid", "IAB Open Measurement (OMID)", "IAB Tech Lab",
                 ("com/iab/omid",),
                 (DC.APP_ACTIVITY, DC.DEVICE_IDS), True),          # 10 of 40
    SdkSignature("amazon-aps", "Amazon Publisher Services", "Amazon",
                 ("com/amazon/device/ads", "com/amazon/aps"),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY, DC.LOCATION_APPROX), True),
    SdkSignature("mintegral", "Mintegral", "Mintegral",
                 ("com/mbridge/msdk", "com/mintegral/msdk"),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY, DC.LOCATION_APPROX), True),
    SdkSignature("fyber", "Fyber / DT Exchange", "Digital Turbine",
                 ("com/fyber/inneractive", "com/fyber/fairbid"),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY, DC.LOCATION_APPROX), True),
    SdkSignature("bidmachine", "BidMachine / Appodeal", "Appodeal",
                 ("io/bidmachine", "com/explorestack"),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY, DC.LOCATION_APPROX), True),
    SdkSignature("moloco", "Moloco Ads", "Moloco",
                 ("com/moloco/sdk",),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY), True),
    SdkSignature("tapjoy", "Tapjoy", "ironSource",
                 ("com/tapjoy",),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY), True),
    SdkSignature("unity-mediation", "Unity LevelPlay Mediation", "Unity",
                 ("com/unity3d/mediation",),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY), True),
    SdkSignature("ogury", "Ogury", "Ogury",
                 ("com/ogury",),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY), True),
    SdkSignature("pubnative", "PubNative / Verve", "Verve Group",
                 ("net/pubnative",),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY, DC.LOCATION_APPROX), True),
    SdkSignature("datadog", "Datadog RUM", "Datadog",
                 ("com/datadog/android",),
                 (DC.APP_INFO_PERF, DC.DEVICE_IDS, DC.APP_ACTIVITY), True),
    SdkSignature("huawei-hms", "Huawei Mobile Services", "Huawei",
                 ("com/huawei/hms", "com/huawei/agconnect", "com/huawei/appgallery"),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY), True),
    SdkSignature("digitalturbine", "Digital Turbine", "Digital Turbine",
                 ("com/digitalturbine",),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY), True),
    SdkSignature("liftoff", "Liftoff Monetize", "Liftoff",
                 ("com/liftoff",),
                 (DC.DEVICE_IDS, DC.APP_ACTIVITY), True),
    SdkSignature("smartlook", "Smartlook session replay", "Cisco",
                 ("com/smartlook",),
                 (DC.APP_ACTIVITY, DC.DEVICE_IDS), True),
)


# --- API sinks ---------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class SinkRule:
    id: str
    title: str
    method_patterns: tuple[str, ...]     # substring match against "Lcls;->name"
    categories: tuple[DataCategory, ...]
    severity: Severity
    remediation: str = ""


SINK_RULES: tuple[SinkRule, ...] = (
    SinkRule("sink.device_id", "Hardware / subscriber identifier read",
             ("TelephonyManager;->getDeviceId", "TelephonyManager;->getImei",
              "TelephonyManager;->getMeid", "TelephonyManager;->getSubscriberId",
              "TelephonyManager;->getSimSerialNumber"),
             (DC.DEVICE_IDS,), Severity.HIGH,
             "Non-resettable IDs are restricted on API 29+. Use an app-set ID "
             "or the advertising ID and declare Device IDs as collected."),
    SinkRule("sink.android_id", "Settings.Secure ANDROID_ID read",
             ("Settings$Secure;->getString",),
             (DC.DEVICE_IDS,), Severity.MEDIUM,
             "Declare Device or other IDs if ANDROID_ID leaves the device."),
    SinkRule("sink.ad_id", "Advertising ID read",
             ("AdvertisingIdClient;->getAdvertisingIdInfo", "AdvertisingIdClient$Info;->getId"),
             (DC.DEVICE_IDS,), Severity.MEDIUM,
             "Requires the com.google.android.gms.permission.AD_ID permission on target 33+."),
    SinkRule("sink.location", "Location API usage",
             ("LocationManager;->getLastKnownLocation", "LocationManager;->requestLocationUpdates",
              "FusedLocationProviderClient;->getLastLocation",
              "FusedLocationProviderClient;->requestLocationUpdates"),
             (DC.LOCATION_PRECISE, DC.LOCATION_APPROX), Severity.HIGH,
             "Declare Location. Precise vs approximate follows your manifest permission."),
    SinkRule("sink.contacts", "Contacts provider access",
             ("ContactsContract", "CommonDataKinds$Phone"),
             (DC.CONTACTS, DC.PERSONAL_PHONE), Severity.HIGH,
             "Declare Contacts. Consider the Contact Picker to avoid the permission."),
    SinkRule("sink.accounts", "Device account enumeration",
             ("AccountManager;->getAccounts", "AccountManager;->getAccountsByType"),
             (DC.PERSONAL_EMAIL, DC.PERSONAL_INFO), Severity.HIGH,
             "GET_ACCOUNTS is heavily restricted. Prefer Credential Manager."),
    SinkRule("sink.sms", "SMS access",
             ("SmsManager;->", "Telephony$Sms"),
             (DC.MESSAGES,), Severity.HIGH,
             "SMS permissions require a Play Console declaration and an approved use case."),
    SinkRule("sink.camera", "Camera capture",
             ("Landroid/hardware/Camera;->", "CameraManager;->openCamera",
              "androidx/camera/core/ImageCapture;->"),
             (DC.PHOTOS_VIDEOS,), Severity.MEDIUM),
    SinkRule("sink.mic", "Microphone capture",
             ("Landroid/media/AudioRecord;-><init>", "MediaRecorder;->setAudioSource"),
             (DC.AUDIO,), Severity.HIGH,
             "Declare Audio. Background recording triggers extra Play review."),
    SinkRule("sink.installed_apps", "Installed-app enumeration",
             ("PackageManager;->getInstalledPackages",
              "PackageManager;->getInstalledApplications",
              "PackageManager;->queryIntentActivities"),
             (DC.APP_ACTIVITY,), Severity.HIGH,
             "QUERY_ALL_PACKAGES requires a sensitive-permission declaration. "
             "Use a <queries> manifest element instead where possible."),
    SinkRule("sink.clipboard", "Clipboard read",
             ("ClipboardManager;->getPrimaryClip",),
             (DC.PERSONAL_INFO,), Severity.MEDIUM,
             "Background clipboard reads are blocked on API 29+ and flagged by reviewers."),
    SinkRule("sink.calendar", "Calendar provider access",
             ("CalendarContract",), (DC.CALENDAR,), Severity.MEDIUM),
    SinkRule("sink.health", "Health data access",
             ("androidx/health/connect", "com/google/android/gms/fitness"),
             (DC.HEALTH,), Severity.HIGH,
             "Health Connect requires a separate Play data-use declaration."),
    SinkRule("sink.dynamic_code", "Dynamic code loading",
             ("DexClassLoader;-><init>", "PathClassLoader;-><init>",
              "InMemoryDexClassLoader;-><init>"),
             (), Severity.HIGH,
             "Loading code not shipped in the APK violates the Device and Network "
             "Abuse policy and is a common rejection cause."),
    SinkRule("sink.reflection_hidden_api", "Reflection into hidden APIs",
             ("Ljava/lang/reflect/Method;->invoke", "Class;->getDeclaredMethod"),
             (), Severity.LOW,
             "Common in libraries; only a problem when paired with hidden-API strings."),
    SinkRule("sink.root_check", "Root / integrity probing",
             ("Runtime;->exec", "Ljava/lang/ProcessBuilder;->start"),
             (), Severity.LOW),
    SinkRule("sink.webview_js", "WebView JavaScript bridge",
             ("WebView;->addJavascriptInterface",),
             (DC.WEB_BROWSING,), Severity.MEDIUM,
             "addJavascriptInterface over http is a remote-code-execution surface."),
)


# --- permission -> category --------------------------------------------------
PERMISSION_CATEGORIES: dict[str, tuple[DataCategory, ...]] = {
    "android.permission.ACCESS_FINE_LOCATION": (DC.LOCATION_PRECISE,),
    "android.permission.ACCESS_COARSE_LOCATION": (DC.LOCATION_APPROX,),
    "android.permission.ACCESS_BACKGROUND_LOCATION": (DC.LOCATION_PRECISE,),
    "android.permission.READ_CONTACTS": (DC.CONTACTS,),
    "android.permission.WRITE_CONTACTS": (DC.CONTACTS,),
    "android.permission.GET_ACCOUNTS": (DC.PERSONAL_EMAIL,),
    "android.permission.READ_CALENDAR": (DC.CALENDAR,),
    "android.permission.READ_SMS": (DC.MESSAGES,),
    "android.permission.RECEIVE_SMS": (DC.MESSAGES,),
    "android.permission.SEND_SMS": (DC.MESSAGES,),
    "android.permission.READ_CALL_LOG": (DC.PERSONAL_PHONE,),
    "android.permission.READ_PHONE_NUMBERS": (DC.PERSONAL_PHONE,),
    "android.permission.READ_PHONE_STATE": (DC.DEVICE_IDS,),
    "android.permission.CAMERA": (DC.PHOTOS_VIDEOS,),
    "android.permission.RECORD_AUDIO": (DC.AUDIO,),
    "android.permission.READ_MEDIA_IMAGES": (DC.PHOTOS_VIDEOS,),
    "android.permission.READ_MEDIA_VIDEO": (DC.PHOTOS_VIDEOS,),
    "android.permission.READ_MEDIA_AUDIO": (DC.AUDIO,),
    "android.permission.READ_EXTERNAL_STORAGE": (DC.FILES_DOCS, DC.PHOTOS_VIDEOS),
    "android.permission.MANAGE_EXTERNAL_STORAGE": (DC.FILES_DOCS,),
    "android.permission.QUERY_ALL_PACKAGES": (DC.APP_ACTIVITY,),
    "android.permission.BODY_SENSORS": (DC.HEALTH,),
    "android.permission.ACTIVITY_RECOGNITION": (DC.HEALTH,),
    "com.google.android.gms.permission.AD_ID": (DC.DEVICE_IDS,),
}

# Permissions Play treats as sensitive: presence alone slows or blocks review.
HIGH_RISK_PERMISSIONS = frozenset({
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
})

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("Stripe live key", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
)

_CLEARTEXT_URL = re.compile(r"^http://(?!localhost|127\.0\.0\.1|schemas\.android\.com)[\w.\-]+")


def _norm(prefix: str) -> str:
    return "L" + prefix.strip("/") + "/"


def match_sdks(all_types: set[str], dex_name: str) -> list[SdkHit]:
    """Fingerprint SDKs by class-descriptor prefix. O(types x sigs) but sigs is small."""
    hits: list[SdkHit] = []
    for sig in SDK_SIGNATURES:
        needles = tuple(_norm(p) for p in sig.class_prefixes)
        sample = next((t for t in all_types if t.startswith(needles)), None)
        if sample is None:
            continue
        hits.append(SdkHit(
            slug=sig.slug, name=sig.name, vendor=sig.vendor,
            collects=sig.collects, shares_with_third_party=sig.shares_with_third_party,
            evidence=(Evidence("dex_type", dex_name, sample),),
            privacy_url=sig.privacy_url,
        ))
    return hits


def match_sinks(method_refs: list[str], dex_name: str) -> list[Finding]:
    """Flag privacy-relevant API references. Dedupes to one finding per rule."""
    joined_index: dict[str, str] = {}
    for ref in method_refs:
        for rule in SINK_RULES:
            if rule.id in joined_index:
                continue
            if any(pat in ref for pat in rule.method_patterns):
                joined_index[rule.id] = ref

    out: list[Finding] = []
    by_id = {r.id: r for r in SINK_RULES}
    for rule_id, ref in joined_index.items():
        rule = by_id[rule_id]
        out.append(Finding(
            id=rule.id, title=rule.title, severity=rule.severity,
            confidence=Confidence.STRONG, categories=rule.categories,
            evidence=(Evidence("dex_method", dex_name, ref),),
            remediation=rule.remediation,
        ))
    return out


def scan_strings(strings: list[str], dex_name: str) -> list[Finding]:
    """Secret material and cleartext endpoints. Heuristic by definition."""
    out: list[Finding] = []
    seen_secret: set[str] = set()
    cleartext: list[str] = []

    for sv in strings:
        if not sv or len(sv) > 4096:
            continue
        for label, pat in _SECRET_PATTERNS:
            if label in seen_secret:
                continue
            if pat.search(sv):
                seen_secret.add(label)
                redacted = sv[:8] + "…" + str(len(sv)) + "ch"
                out.append(Finding(
                    id=f"secret.{label.lower().replace(' ', '_')}",
                    title=f"Possible {label} embedded in the APK",
                    severity=Severity.HIGH, confidence=Confidence.HEURISTIC,
                    categories=(), evidence=(Evidence("dex_string", dex_name, redacted),),
                    remediation="Move to a server-side proxy or Play Integrity-gated fetch. "
                                "Anything in the APK is public.",
                ))
        if len(cleartext) < 12 and _CLEARTEXT_URL.match(sv):
            cleartext.append(sv)

    if cleartext:
        out.append(Finding(
            id="net.cleartext_endpoint",
            title=f"{len(cleartext)} cleartext http:// endpoint(s) referenced",
            severity=Severity.MEDIUM, confidence=Confidence.HEURISTIC,
            categories=(),
            evidence=tuple(Evidence("dex_string", dex_name, u) for u in cleartext[:5]),
            remediation="Set android:usesCleartextTraffic=\"false\" and migrate to HTTPS.",
        ))
    return out
