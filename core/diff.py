"""
core.diff — report-vs-report comparison.

FLOW POSITION: ScanReport(dict) x ScanReport(dict) -> ComplianceDrift

WHY THIS MODULE IS THE BUSINESS: a scan is a one-time purchase. A diff is a
subscription. "Build 47 added an SDK that reads coarse location and your live
Data Safety declaration says you don't collect location" is the sentence that
gets a card charged every month.

Operates on dicts, not dataclasses, so it can compare a live scan against a
stored JSON report from six months ago without version-locking the models.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class ComplianceDrift:
    base_sha256: str
    head_sha256: str
    new_sdks: list[dict[str, str]] = field(default_factory=list)
    removed_sdks: list[dict[str, str]] = field(default_factory=list)
    new_findings: list[dict[str, str]] = field(default_factory=list)
    resolved_findings: list[dict[str, str]] = field(default_factory=list)
    new_permissions: list[str] = field(default_factory=list)
    removed_permissions: list[str] = field(default_factory=list)
    new_categories: list[str] = field(default_factory=list)
    removed_categories: list[str] = field(default_factory=list)
    declaration_changed: bool = False
    blocking: bool = False
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _cat_set(report: dict[str, Any]) -> set[str]:
    return {d["category"] for d in report.get("declaration", [])}


def _perm_set(report: dict[str, Any]) -> set[str]:
    m = report.get("manifest")
    return set(m["permissions"]) if m else set()


def _sdk_map(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {s["slug"]: s for s in report.get("sdks", [])}


def _finding_map(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {f["id"]: f for f in report.get("findings", [])}


def diff_reports(base: dict[str, Any], head: dict[str, Any]) -> ComplianceDrift:
    """base = previously shipped build, head = candidate build."""
    b_sdk, h_sdk = _sdk_map(base), _sdk_map(head)
    b_find, h_find = _finding_map(base), _finding_map(head)
    b_perm, h_perm = _perm_set(base), _perm_set(head)
    b_cat, h_cat = _cat_set(base), _cat_set(head)

    drift = ComplianceDrift(
        base_sha256=base.get("apk_sha256", ""),
        head_sha256=head.get("apk_sha256", ""),
        new_sdks=[{"slug": k, "name": v["name"], "vendor": v["vendor"]}
                  for k, v in h_sdk.items() if k not in b_sdk],
        removed_sdks=[{"slug": k, "name": v["name"], "vendor": v["vendor"]}
                      for k, v in b_sdk.items() if k not in h_sdk],
        new_findings=[{"id": k, "title": v["title"], "severity": v["severity"]}
                      for k, v in h_find.items() if k not in b_find],
        resolved_findings=[{"id": k, "title": v["title"], "severity": v["severity"]}
                           for k, v in b_find.items() if k not in h_find],
        new_permissions=sorted(h_perm - b_perm),
        removed_permissions=sorted(b_perm - h_perm),
        new_categories=sorted(h_cat - b_cat),
        removed_categories=sorted(b_cat - h_cat),
    )

    drift.declaration_changed = bool(drift.new_categories or drift.removed_categories)

    # "Blocking" == this build would make a previously-accurate Data Safety form
    # wrong, or introduces a HIGH finding. That's the CI exit-code-1 condition.
    drift.blocking = bool(
        drift.new_categories
        or any(f["severity"] == "high" for f in drift.new_findings)
    )

    bits: list[str] = []
    if drift.new_categories:
        bits.append(
            f"declaration must be updated: +{', '.join(drift.new_categories)}"
        )
    if drift.new_sdks:
        bits.append(f"{len(drift.new_sdks)} new SDK(s): "
                    + ", ".join(s["name"] for s in drift.new_sdks[:4]))
    if drift.new_permissions:
        bits.append(f"{len(drift.new_permissions)} new permission(s)")
    high_new = [f for f in drift.new_findings if f["severity"] == "high"]
    if high_new:
        bits.append(f"{len(high_new)} new high-severity finding(s)")
    if drift.resolved_findings:
        bits.append(f"{len(drift.resolved_findings)} finding(s) resolved")

    drift.summary = "; ".join(bits) if bits else "no compliance-relevant drift"
    return drift
