"""
core.sbom — CycloneDX SBOM from a scan.

FLOW POSITION: ScanReport -> CycloneDX 1.5 JSON. Pure transform, no new analysis.

WHY THIS IS NEARLY FREE
    An SBOM is a list of components with identity and provenance. The scan
    already produces exactly that: fingerprinted SDKs, native libraries, and
    the package itself. This module is a projection, not a second engine.

WHY IT MATTERS COMMERCIALLY
    "Send us your SBOM" is a purchase-order checkbox at any company large
    enough to have a security team, and Android tooling largely does not
    answer it. CycloneDX is the format those teams' scanners already ingest.

HONESTY IN THE OUTPUT
    Every component carries the evidence that produced it and a confidence
    property. An SBOM that silently mixes "we saw this class" with "we know the
    version" is worse than none — downstream tools treat it as ground truth.
    We do not extract versions, so we do not claim them.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from typing import Any

from .analyzer import ENGINE_VERSION

_SAFE = re.compile(r"[^a-zA-Z0-9._-]")


def _purl(vendor: str, name: str) -> str:
    """A package URL that is honest about what we know.

    `pkg:generic/` rather than `pkg:maven/` on purpose: we fingerprint class
    prefixes, so we know the library is present but not its Maven coordinates
    or version. Emitting a maven purl would invite a downstream scanner to
    look up CVEs against a coordinate we never actually established.
    """
    v = _SAFE.sub("-", vendor.lower()) or "unknown"
    n = _SAFE.sub("-", name.lower()) or "unknown"
    return f"pkg:generic/{v}/{n}"


def build_sbom(report: dict[str, Any], *, app_name: str = "") -> dict[str, Any]:
    manifest = report.get("manifest") or {}
    pkg = manifest.get("package") or app_name or "unknown.package"
    version = manifest.get("version_name") or ""

    components: list[dict[str, Any]] = []

    for sdk in report.get("sdks") or []:
        ev = (sdk.get("evidence") or [{}])[0]
        collects = list(sdk.get("collects") or [])
        components.append({
            "type": "library",
            "bom-ref": f"sdk/{sdk['slug']}",
            "name": sdk["name"],
            "publisher": sdk.get("vendor") or "",
            "purl": _purl(sdk.get("vendor", ""), sdk["slug"]),
            "scope": "required",
            "properties": [
                {"name": "nullscan:detection", "value": "class-prefix fingerprint"},
                {"name": "nullscan:confidence", "value": "strong"},
                {"name": "nullscan:evidence", "value": str(ev.get("detail", ""))},
                {"name": "nullscan:shares_with_third_party",
                 "value": str(bool(sdk.get("shares_with_third_party"))).lower()},
                {"name": "nullscan:data_categories", "value": ", ".join(collects) or "none"},
            ],
        })

    for lib in report.get("native") or []:
        name = lib["lib"].rsplit("/", 1)[-1]
        components.append({
            "type": "library",
            "bom-ref": f"native/{lib['abi']}/{name}",
            "name": name,
            "purl": _purl("native", name),
            "scope": "required",
            "properties": [
                {"name": "nullscan:abi", "value": lib["abi"]},
                {"name": "nullscan:size_bytes", "value": str(lib["size_bytes"])},
                # Stated plainly: an SBOM consumer must not assume a listed
                # native library was inspected. It was enumerated, not analysed.
                {"name": "nullscan:detection", "value": "file enumeration only"},
                {"name": "nullscan:confidence", "value": "heuristic"},
            ],
        })

    signing = report.get("signing") or {}
    props = [
        {"name": "nullscan:engine_version", "value": ENGINE_VERSION},
        {"name": "nullscan:apk_sha256", "value": report.get("apk_sha256", "")},
        {"name": "nullscan:target_sdk", "value": str(manifest.get("target_sdk", ""))},
        {"name": "nullscan:permissions",
         "value": str(len(manifest.get("permissions") or []))},
    ]
    if signing.get("schemes"):
        props.append({"name": "nullscan:signature_schemes",
                      "value": ", ".join(signing["schemes"])})
    for i, s in enumerate(signing.get("signers") or []):
        props.append({"name": f"nullscan:signer_{i}_sha256", "value": s["sha256"]})
        if s.get("subject_cn"):
            props.append({"name": f"nullscan:signer_{i}_cn", "value": s["subject_cn"]})

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds"),
            "tools": [{"vendor": "NULLSCAN", "name": "nullscan",
                       "version": ENGINE_VERSION}],
            "component": {
                "type": "application",
                "bom-ref": f"app/{pkg}",
                "name": pkg,
                "version": version,
                "purl": f"pkg:generic/android/{_SAFE.sub('-', pkg)}"
                        + (f"@{_SAFE.sub('-', version)}" if version else ""),
                "hashes": [{"alg": "SHA-256", "content": report.get("apk_sha256", "")}]
                          if report.get("apk_sha256") else [],
                "properties": props,
            },
        },
        "components": components,
    }


def to_json(report: dict[str, Any], *, indent: int = 2) -> str:
    return json.dumps(build_sbom(report), indent=indent)
