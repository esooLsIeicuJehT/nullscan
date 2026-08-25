"""
core.models — the contract of the analysis engine.

FLOW POSITION: terminal. Everything upstream produces these; everything
downstream (service, cli, diff) consumes them. Nothing in this file may
import from `service/`. Nothing here does I/O.

These are plain dataclasses, not Pydantic models, on purpose: the core must
stay importable without a web framework installed. `service.schemas` mirrors
them for the HTTP contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class DataCategory(str, Enum):
    """Google Play Data Safety taxonomy (the subset that is machine-detectable)."""

    LOCATION_PRECISE = "location.precise"
    LOCATION_APPROX = "location.approximate"
    PERSONAL_INFO = "personal.info"
    PERSONAL_EMAIL = "personal.email"
    PERSONAL_PHONE = "personal.phone"
    FINANCIAL = "financial"
    HEALTH = "health"
    MESSAGES = "messages"
    PHOTOS_VIDEOS = "photos_videos"
    AUDIO = "audio"
    FILES_DOCS = "files_docs"
    CALENDAR = "calendar"
    CONTACTS = "contacts"
    APP_ACTIVITY = "app_activity"
    WEB_BROWSING = "web_browsing"
    APP_INFO_PERF = "app_info_performance"
    DEVICE_IDS = "device_or_other_ids"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Confidence(str, Enum):
    """How much the finding should be trusted without human review."""

    CERTAIN = "certain"      # structural fact (permission in manifest)
    STRONG = "strong"        # direct method reference in DEX
    HEURISTIC = "heuristic"  # string match / native surface inference


@dataclass(frozen=True, slots=True)
class Evidence:
    """Where a finding came from. Required — a finding without evidence is a guess."""

    kind: str            # "manifest" | "dex_method" | "dex_string" | "dex_type" | "native"
    locator: str         # dex file, manifest path, or .so name
    detail: str          # the actual matched token


@dataclass(frozen=True, slots=True)
class Finding:
    id: str
    title: str
    severity: Severity
    confidence: Confidence
    categories: tuple[DataCategory, ...]
    evidence: tuple[Evidence, ...]
    remediation: str = ""

    def key(self) -> str:
        """Stable identity for diffing across builds."""
        return self.id


@dataclass(frozen=True, slots=True)
class SdkHit:
    slug: str
    name: str
    vendor: str
    collects: tuple[DataCategory, ...]
    shares_with_third_party: bool
    evidence: tuple[Evidence, ...]
    privacy_url: str = ""


@dataclass(frozen=True, slots=True)
class Component:
    kind: str            # activity | service | receiver | provider
    name: str
    exported: bool
    permission: str | None
    has_intent_filter: bool


@dataclass(frozen=True, slots=True)
class ManifestFacts:
    package: str
    version_code: str
    version_name: str
    min_sdk: str
    target_sdk: str
    permissions: tuple[str, ...]
    components: tuple[Component, ...]
    uses_cleartext_traffic: bool | None
    debuggable: bool
    network_security_config: str | None


@dataclass(frozen=True, slots=True)
class NativeSurface:
    lib: str
    abi: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class DeclarationLine:
    """One row of the generated Play Data Safety form."""

    category: DataCategory
    collected: bool
    shared: bool
    ephemeral: bool
    required: bool
    purposes: tuple[str, ...]
    justification: tuple[str, ...]   # human-readable evidence trail


@dataclass(frozen=True, slots=True)
class ScanReport:
    schema_version: str
    apk_sha256: str
    apk_size_bytes: int
    scanned_at: str
    engine_version: str
    manifest: ManifestFacts | None
    sdks: tuple[SdkHit, ...]
    findings: tuple[Finding, ...]
    native: tuple[NativeSurface, ...]
    declaration: tuple[DeclarationLine, ...]
    errors: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        """Pure-JSON projection.

        `asdict` leaves str-Enum members in place. They compare equal to their
        value but hash by NAME, so `"financial" in {DataCategory.FINANCIAL}` is
        False. That silently breaks every set operation downstream — including
        the diff engine. Normalise once, here, at the boundary.
        """
        return _plain(asdict(self))


def _plain(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value
