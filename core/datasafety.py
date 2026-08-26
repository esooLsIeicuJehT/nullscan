"""
core.datasafety — the correlation stage.

FLOW POSITION: (ManifestFacts, SdkHit[], Finding[]) -> DeclarationLine[]

This is where the product stops being a scanner and becomes an answer. Raw
findings are a list of scary strings; a declaration is the thing the developer
copies into the Play Console. Keep this module pure and deterministic — its
output is the customer-facing artifact and must be diffable byte-for-byte.
"""

from __future__ import annotations

from .models import DataCategory, DeclarationLine, Finding, ManifestFacts, SdkHit
from .signatures import PERMISSION_CATEGORIES

DC = DataCategory

_PURPOSE_BY_CATEGORY: dict[DataCategory, tuple[str, ...]] = {
    DC.DEVICE_IDS: ("Analytics", "Advertising or marketing", "Fraud prevention"),
    DC.APP_ACTIVITY: ("Analytics", "App functionality"),
    DC.APP_INFO_PERF: ("Analytics", "App functionality"),
    DC.LOCATION_PRECISE: ("App functionality",),
    DC.LOCATION_APPROX: ("App functionality", "Advertising or marketing"),
    DC.FINANCIAL: ("App functionality",),
    DC.CONTACTS: ("App functionality",),
    DC.PERSONAL_EMAIL: ("Account management", "App functionality"),
    DC.PERSONAL_PHONE: ("Account management",),
    DC.PERSONAL_INFO: ("Account management", "App functionality"),
    DC.MESSAGES: ("App functionality",),
    DC.PHOTOS_VIDEOS: ("App functionality",),
    DC.AUDIO: ("App functionality",),
    DC.FILES_DOCS: ("App functionality",),
    DC.CALENDAR: ("App functionality",),
    DC.HEALTH: ("App functionality",),
    DC.WEB_BROWSING: ("Analytics",),
}

# Categories where the manifest permission is what upgrades approximate->precise.
_LOCATION_PAIR = (DC.LOCATION_PRECISE, DC.LOCATION_APPROX)


def build_declaration(
    manifest: ManifestFacts | None,
    sdks: tuple[SdkHit, ...],
    findings: tuple[Finding, ...],
) -> tuple[DeclarationLine, ...]:
    """Merge three independent evidence streams into one row per data category."""
    collected: dict[DataCategory, list[str]] = {}
    shared: set[DataCategory] = set()
    required: set[DataCategory] = set()

    def add(cat: DataCategory, why: str) -> None:
        collected.setdefault(cat, [])
        if why not in collected[cat]:
            collected[cat].append(why)

    # stream 1: declared permissions (highest confidence — it's a structural fact)
    if manifest:
        for perm in manifest.permissions:
            for cat in PERMISSION_CATEGORIES.get(perm, ()):
                add(cat, f"manifest permission {perm}")
                required.add(cat)

    # stream 2: linked SDKs (these are also the *sharing* signal)
    for sdk in sdks:
        for cat in sdk.collects:
            # "Meta Android SDK SDK is linked" — several vendor names already
            # end in SDK, and this string is customer-facing on the declaration.
            label = sdk.name if sdk.name.upper().endswith("SDK") else f"{sdk.name} SDK"
            add(cat, f"{label} is linked")
            if sdk.shares_with_third_party:
                shared.add(cat)

    # stream 3: direct API sinks in first-party or library code
    for f in findings:
        for cat in f.categories:
            add(cat, f"{f.title} ({f.evidence[0].detail if f.evidence else 'n/a'})")

    # Precise location without ACCESS_FINE_LOCATION is a false positive from the
    # fused-location SDK signature. Downgrade rather than over-declare.
    if (manifest and DC.LOCATION_PRECISE in collected
            and "android.permission.ACCESS_FINE_LOCATION" not in manifest.permissions):
        reasons = collected.pop(DC.LOCATION_PRECISE)
        for r in reasons:
            add(DC.LOCATION_APPROX, r + " [downgraded: no FINE_LOCATION permission]")
        shared.discard(DC.LOCATION_PRECISE)
        required.discard(DC.LOCATION_PRECISE)

    lines = [
        DeclarationLine(
            category=cat,
            collected=True,
            shared=cat in shared,
            ephemeral=False,
            required=cat in required,
            purposes=_PURPOSE_BY_CATEGORY.get(cat, ("App functionality",)),
            justification=tuple(reasons),
        )
        for cat, reasons in collected.items()
    ]
    lines.sort(key=lambda d: d.category.value)
    return tuple(lines)
