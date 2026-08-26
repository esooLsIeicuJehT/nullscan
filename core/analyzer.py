"""
core.analyzer — the one and only entry point into the engine.

FLOW MAP
--------
    path
      -> container.open_apk           [trust boundary: validate zip]
      -> axml.parse_axml              [AndroidManifest.xml -> XmlNode]
      -> _manifest_facts              [XmlNode -> ManifestFacts]
      -> dex.parse_dex (xN)           [classes*.dex -> DexTables]
      -> signatures.match_sdks        [types    -> SdkHit[]]
      -> signatures.match_sinks       [methods  -> Finding[]]
      -> signatures.scan_strings      [strings  -> Finding[]]
      -> _manifest_findings           [facts    -> Finding[]]
      -> datasafety.build_declaration [merge    -> DeclarationLine[]]
      -> ScanReport

Every stage is total: a failure in one produces an entry in `errors` and the
pipeline continues. A partial report beats a 500.

`analyze_path` is module-level and takes/returns picklable values so it can be
handed to a ProcessPoolExecutor without ceremony.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

from . import axml, container, dex, signatures
from .datasafety import build_declaration
from .models import (
    Component,
    Confidence,
    DataCategory,
    Evidence,
    Finding,
    ManifestFacts,
    NativeSurface,
    ScanReport,
    Severity,
)

ENGINE_VERSION = "0.3.0"
SCHEMA_VERSION = "1"

_COMPONENT_TAGS = {
    "activity": "activity",
    "activity-alias": "activity",
    "service": "service",
    "receiver": "receiver",
    "provider": "provider",
}


def _truthy(v: str | None) -> bool:
    return str(v).strip().lower() in {"true", "1", "-1"}


def _manifest_facts(root: axml.XmlNode) -> ManifestFacts:
    app_nodes = root.find_all("application")
    app = app_nodes[0] if app_nodes else axml.XmlNode(tag="application")

    perms = sorted({
        n.get("name") or "" for n in root.find_all("uses-permission")
    } | {
        n.get("name") or "" for n in root.find_all("uses-permission-sdk-23")
    } - {""})

    sdk_nodes = root.find_all("uses-sdk")
    sdk = sdk_nodes[0] if sdk_nodes else axml.XmlNode(tag="uses-sdk")

    components: list[Component] = []
    for tag, kind in _COMPONENT_TAGS.items():
        for node in root.find_all(tag):
            has_filter = bool(node.find_all("intent-filter"))
            explicit = node.get("exported")
            # Legacy implicit-export rule: no android:exported but an intent
            # filter present == exported on target < 31.
            exported = _truthy(explicit) if explicit is not None else has_filter
            components.append(Component(
                kind=kind,
                name=node.get("name") or "<unnamed>",
                exported=exported,
                permission=node.get("permission"),
                has_intent_filter=has_filter,
            ))

    cleartext_raw = app.get("usesCleartextTraffic")
    return ManifestFacts(
        package=root.attrs.get("package", ""),
        version_code=root.get("versionCode") or "",
        version_name=root.get("versionName") or "",
        min_sdk=sdk.get("minSdkVersion") or "",
        target_sdk=sdk.get("targetSdkVersion") or "",
        permissions=tuple(perms),
        components=tuple(components),
        uses_cleartext_traffic=None if cleartext_raw is None else _truthy(cleartext_raw),
        debuggable=_truthy(app.get("debuggable")),
        network_security_config=app.get("networkSecurityConfig"),
    )


def _manifest_findings(facts: ManifestFacts) -> list[Finding]:
    out: list[Finding] = []

    if facts.debuggable:
        out.append(Finding(
            "manifest.debuggable", "Application is marked debuggable",
            Severity.HIGH, Confidence.CERTAIN, (),
            (Evidence("manifest", "AndroidManifest.xml", "android:debuggable=true"),),
            "Play rejects debuggable release builds. Check your build type.",
        ))

    risky = sorted(set(facts.permissions) & signatures.HIGH_RISK_PERMISSIONS)
    if risky:
        out.append(Finding(
            "manifest.sensitive_permissions",
            f"{len(risky)} permission(s) requiring a Play Console declaration",
            Severity.HIGH, Confidence.CERTAIN,
            tuple(dict.fromkeys(
                c for p in risky for c in signatures.PERMISSION_CATEGORIES.get(p, ())
            )),
            tuple(Evidence("manifest", "AndroidManifest.xml", p) for p in risky),
            "Each of these needs an approved use case in the Play Console or the "
            "release will be blocked.",
        ))

    unguarded = [
        c for c in facts.components
        if c.exported and not c.permission and c.kind in {"service", "receiver", "provider"}
    ]
    if unguarded:
        out.append(Finding(
            "manifest.exported_unguarded",
            f"{len(unguarded)} exported component(s) with no permission guard",
            Severity.MEDIUM, Confidence.CERTAIN, (),
            tuple(Evidence("manifest", "AndroidManifest.xml", f"{c.kind}:{c.name}")
                  for c in unguarded[:8]),
            "Set android:exported=\"false\" or gate with a signature-level permission.",
        ))

    if facts.uses_cleartext_traffic and not facts.network_security_config:
        out.append(Finding(
            "manifest.cleartext_allowed", "Cleartext HTTP traffic is permitted app-wide",
            Severity.MEDIUM, Confidence.CERTAIN, (),
            (Evidence("manifest", "AndroidManifest.xml", "usesCleartextTraffic=true"),),
            "Ship a network security config that pins cleartext to specific domains.",
        ))

    if facts.target_sdk.isdigit() and int(facts.target_sdk) < 34:
        out.append(Finding(
            "manifest.target_sdk_stale",
            f"targetSdkVersion {facts.target_sdk} is below the current Play floor",
            Severity.HIGH, Confidence.CERTAIN, (),
            (Evidence("manifest", "AndroidManifest.xml", f"targetSdk={facts.target_sdk}"),),
            "Play blocks new releases below its rolling target-API requirement.",
        ))

    if ("com.google.android.gms.permission.AD_ID" not in facts.permissions
            and facts.target_sdk.isdigit() and int(facts.target_sdk) >= 33):
        out.append(Finding(
            "manifest.ad_id_missing", "AD_ID permission absent on target 33+",
            Severity.INFO, Confidence.CERTAIN, (),
            (Evidence("manifest", "AndroidManifest.xml", "no AD_ID permission"),),
            "Only an issue if an ad SDK is linked — cross-check the SDK list.",
        ))

    return out


def analyze_path(path: str, *, deep_strings: bool = True) -> dict[str, Any]:
    """Analyse an APK at `path`. Returns a plain dict (picklable across processes)."""
    errors: list[str] = []
    manifest: ManifestFacts | None = None
    sdks: list = []
    findings: list[Finding] = []
    native: list[NativeSurface] = []

    try:
        apk = container.open_apk(path)
    except container.ContainerError as exc:
        return ScanReport(
            schema_version=SCHEMA_VERSION, apk_sha256="", apk_size_bytes=0,
            scanned_at=_now(), engine_version=ENGINE_VERSION, manifest=None,
            sdks=(), findings=(), native=(), declaration=(), errors=(str(exc),),
        ).to_dict()

    with apk:
        # --- manifest stage --------------------------------------------------
        try:
            manifest = _manifest_facts(axml.parse_axml(apk.read("AndroidManifest.xml")))
            findings.extend(_manifest_findings(manifest))
        except (axml.AxmlError, KeyError, Exception) as exc:
            errors.append(f"manifest: {type(exc).__name__}: {exc}")

        # --- dex stage -------------------------------------------------------
        seen_sdk_slugs: set[str] = set()
        seen_finding_ids: set[str] = {f.id for f in findings}

        for dex_name in apk.dex_names():
            try:
                tables = dex.parse_dex(apk.read(dex_name), dex_name)
            except Exception as exc:
                errors.append(f"{dex_name}: {type(exc).__name__}: {exc}")
                continue

            for hit in signatures.match_sdks(tables.type_set, dex_name):
                if hit.slug not in seen_sdk_slugs:
                    seen_sdk_slugs.add(hit.slug)
                    sdks.append(hit)

            for f in signatures.match_sinks(tables.method_refs, dex_name):
                if f.id not in seen_finding_ids:
                    seen_finding_ids.add(f.id)
                    findings.append(f)

            if deep_strings:
                for f in signatures.scan_strings(tables.strings, dex_name):
                    if f.id not in seen_finding_ids:
                        seen_finding_ids.add(f.id)
                        findings.append(f)

        # --- native stage ----------------------------------------------------
        for lib_path, abi, size in apk.native_libs():
            native.append(NativeSurface(lib=lib_path, abi=abi, size_bytes=size))
        if native:
            findings.append(Finding(
                "native.surface_present",
                f"{len(native)} native library/libraries present — not statically analysed",
                Severity.INFO, Confidence.HEURISTIC, (),
                tuple(Evidence("native", n.lib, n.abi) for n in native[:6]),
                "Native code can collect data invisibly to this scan. Declare manually "
                "if your .so files touch user data.",
            ))

        sha, size_bytes = apk.sha256, apk.size_bytes

    findings.sort(key=lambda f: (_SEV_ORDER[f.severity], f.id))
    declaration = build_declaration(manifest, tuple(sdks), tuple(findings))

    return ScanReport(
        schema_version=SCHEMA_VERSION,
        apk_sha256=sha,
        apk_size_bytes=size_bytes,
        scanned_at=_now(),
        engine_version=ENGINE_VERSION,
        manifest=manifest,
        sdks=tuple(sdks),
        findings=tuple(findings),
        native=tuple(native),
        declaration=declaration,
        errors=tuple(errors),
    ).to_dict()


_SEV_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2, Severity.INFO: 3}


def _now() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")


__all__ = ["ENGINE_VERSION", "SCHEMA_VERSION", "DataCategory", "analyze_path"]
