"""
service.schemas — the HTTP contract.

Your original handlers annotated `-> Dict[str, str]`. That is not a type, it's
a wish: the real payload is deeply nested and half the values are lists and
bools. FastAPI silently believed the annotation and generated an OpenAPI schema
that lies to every client you'll ever have.

These models mirror `core.models` deliberately rather than importing them.
The core must never gain a Pydantic dependency, and the wire format must be
free to version independently of the engine's internals.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class SubmitAccepted(BaseModel):
    job_id: str
    state: Literal["queued", "done"]
    poll_url: str
    cached: bool = Field(False, description="True when this SHA-256 was already scanned")


class EvidenceOut(BaseModel):
    kind: str
    locator: str
    detail: str


class FindingOut(BaseModel):
    id: str
    title: str
    severity: str
    confidence: str
    categories: list[str]
    evidence: list[EvidenceOut]
    remediation: str = ""


class SdkOut(BaseModel):
    slug: str
    name: str
    vendor: str
    collects: list[str]
    shares_with_third_party: bool
    evidence: list[EvidenceOut]
    privacy_url: str = ""


class ComponentOut(BaseModel):
    kind: str
    name: str
    exported: bool
    permission: str | None
    has_intent_filter: bool


class ManifestOut(BaseModel):
    package: str
    version_code: str
    version_name: str
    min_sdk: str
    target_sdk: str
    permissions: list[str]
    components: list[ComponentOut]
    uses_cleartext_traffic: bool | None
    debuggable: bool
    network_security_config: str | None


class NativeOut(BaseModel):
    lib: str
    abi: str
    size_bytes: int


class DeclarationOut(BaseModel):
    category: str
    collected: bool
    shared: bool
    ephemeral: bool
    required: bool
    purposes: list[str]
    justification: list[str]


class ReportOut(BaseModel):
    schema_version: str
    apk_sha256: str
    apk_size_bytes: int
    scanned_at: str
    engine_version: str
    manifest: ManifestOut | None
    sdks: list[SdkOut]
    findings: list[FindingOut]
    native: list[NativeOut]
    declaration: list[DeclarationOut]
    errors: list[str] = []


class JobOut(BaseModel):
    id: str
    state: str
    filename: str | None
    apk_sha256: str | None
    created_at: float
    started_at: float | None = None
    finished_at: float | None = None
    error: str | None = None
    report: ReportOut | None = None


class DiffRequest(BaseModel):
    """POST, not GET. See main.py for why your GET /api-scan/ could never work."""

    base_job_id: str | None = None
    head_job_id: str | None = None
    base_report: dict[str, Any] | None = None
    head_report: dict[str, Any] | None = None


class DriftOut(BaseModel):
    base_sha256: str
    head_sha256: str
    new_sdks: list[dict[str, str]]
    removed_sdks: list[dict[str, str]]
    new_findings: list[dict[str, str]]
    resolved_findings: list[dict[str, str]]
    new_permissions: list[str]
    removed_permissions: list[str]
    new_categories: list[str]
    removed_categories: list[str]
    declaration_changed: bool
    blocking: bool
    summary: str


class ErrorOut(BaseModel):
    error: str
    detail: str | None = None


class QuotaOut(BaseModel):
    """Scan allowance for the caller. `limit: -1` means unmetered."""

    limit: int
    used: int
    remaining: int
    resets_in_s: int
    metered: bool
    tier: str = "free"


class TierOut(BaseModel):
    slug: str
    name: str
    price_cents: int
    monthly_scans: int
    blurb: str


class CheckoutIn(BaseModel):
    tier: str
    email: str | None = None


class CheckoutOut(BaseModel):
    url: str
    session_id: str


class WaitlistIn(BaseModel):
    email: str = Field(max_length=254)
    source: str | None = Field(default="web", max_length=40)


class WaitlistOut(BaseModel):
    email: str
    added: bool = Field(description="False when the address was already on the list")
