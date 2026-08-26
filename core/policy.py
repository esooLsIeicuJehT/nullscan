"""
core.policy — rules a team owns, evaluated against a scan.

FLOW POSITION
    ScanReport (+ optional ComplianceDrift)
        -> Policy.evaluate()
        -> PolicyDecision  ->  CI exit code

WHY THIS IS THE FEATURE, NOT A FEATURE
    Until now the CI gate hardcoded one opinion: "block on new data categories
    or new high findings". That is my opinion, shipped to everyone. A games
    studio linking eleven ad networks on purpose does not want to be told about
    it every build; a bank wants to fail on a single new SDK. Neither can be
    served by a constant.

    A policy file moves that judgement to the team that owns the release, and
    turns the scanner into something they configure rather than something they
    argue with.

WHY TOML AND NOT YAML
    `core/` is stdlib-only by contract, and `tomllib` ships with Python 3.11+.
    PyYAML would put a dependency in the engine and break the CLI, the CI
    binary and the on-prem wheel all at once. JSON is accepted too, for
    machine-generated policies.

WAIVERS EXPIRE, ON PURPOSE
    `action = "ignore"` is how a team accepts a known finding. Every waiver
    REQUIRES an `expires` date. A permanent waiver is not a decision, it is a
    blind spot that outlives the person who added it — and the whole product is
    about finding the things nobody remembered.
"""

from __future__ import annotations

import datetime as _dt
import fnmatch
import json
import tomllib
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
VALID_ACTIONS = {"block", "warn", "ignore"}


class PolicyError(ValueError):
    """Raised for a malformed policy. Never for a rule that merely matched."""


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    action: str
    when: dict[str, Any]
    description: str = ""
    expires: str | None = None

    def expired(self, today: _dt.date) -> bool:
        if not self.expires:
            return False
        try:
            return _dt.date.fromisoformat(self.expires) < today
        except ValueError:
            return False


@dataclass(frozen=True, slots=True)
class RuleResult:
    rule_id: str
    action: str
    matched: bool
    reason: str
    evidence: tuple[str, ...] = ()


@dataclass(slots=True)
class PolicyDecision:
    policy_name: str
    blocked: bool
    results: list[RuleResult] = field(default_factory=list)
    waived: list[str] = field(default_factory=list)
    expired_waivers: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def blocking(self) -> list[RuleResult]:
        return [r for r in self.results if r.matched and r.action == "block"]

    @property
    def warnings(self) -> list[RuleResult]:
        return [r for r in self.results if r.matched and r.action == "warn"]


# --- condition predicates ----------------------------------------------------
# Each returns (matched, evidence). Kept as small pure functions so a new
# condition is one entry here plus one line in the dispatch table, and so each
# can be unit-tested without constructing a policy.

def _findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    return report.get("findings") or []


def _sdks(report: dict[str, Any]) -> list[dict[str, Any]]:
    return report.get("sdks") or []


def _c_finding(val: Any, report: dict, drift: dict | None) -> tuple[bool, list[str]]:
    """Finding id, glob-aware: `manifest.*` matches every manifest finding."""
    pats = val if isinstance(val, list) else [val]
    hits = [f["id"] for f in _findings(report)
            if any(fnmatch.fnmatch(f["id"], str(p)) for p in pats)]
    return bool(hits), hits


def _c_severity_at_least(val: Any, report: dict, drift: dict | None) -> tuple[bool, list[str]]:
    floor = SEVERITY_ORDER.get(str(val).lower())
    if floor is None:
        raise PolicyError(f"unknown severity: {val!r}")
    hits = [f"{f['severity']}: {f['title']}" for f in _findings(report)
            if SEVERITY_ORDER.get(f["severity"], 0) >= floor]
    return bool(hits), hits


def _c_sdk(val: Any, report: dict, drift: dict | None) -> tuple[bool, list[str]]:
    pats = val if isinstance(val, list) else [val]
    hits = [s["name"] for s in _sdks(report)
            if any(fnmatch.fnmatch(s["slug"], str(p)) for p in pats)]
    return bool(hits), hits


def _c_sdk_not_in(val: Any, report: dict, drift: dict | None) -> tuple[bool, list[str]]:
    """Allowlist. Matches when ANY linked SDK is outside the approved set.

    This is the condition agencies actually want: not "is X present" but
    "did anything arrive that we never approved" — which is how an ad SDK
    three levels deep in a transitive dependency gets caught.
    """
    allowed = {str(v) for v in (val if isinstance(val, list) else [val])}
    hits = [f"{s['name']} ({s['slug']})" for s in _sdks(report)
            if s["slug"] not in allowed]
    return bool(hits), hits


def _c_sdk_shares(val: Any, report: dict, drift: dict | None) -> tuple[bool, list[str]]:
    want = bool(val)
    hits = [s["name"] for s in _sdks(report) if bool(s.get("shares_with_third_party")) == want]
    return bool(hits) if want else False, hits


def _c_declares(val: Any, report: dict, drift: dict | None) -> tuple[bool, list[str]]:
    pats = val if isinstance(val, list) else [val]
    hits = [d["category"] for d in (report.get("declaration") or [])
            if any(fnmatch.fnmatch(d["category"], str(p)) for p in pats)]
    return bool(hits), hits


def _c_declares_shared(val: Any, report: dict, drift: dict | None) -> tuple[bool, list[str]]:
    pats = val if isinstance(val, list) else [val]
    hits = [d["category"] for d in (report.get("declaration") or [])
            if d.get("shared") and any(fnmatch.fnmatch(d["category"], str(p)) for p in pats)]
    return bool(hits), hits


def _c_permission(val: Any, report: dict, drift: dict | None) -> tuple[bool, list[str]]:
    m = report.get("manifest") or {}
    pats = val if isinstance(val, list) else [val]
    hits = [p for p in (m.get("permissions") or [])
            if any(fnmatch.fnmatch(p, str(q)) for q in pats)]
    return bool(hits), hits


def _c_target_sdk_below(val: Any, report: dict, drift: dict | None) -> tuple[bool, list[str]]:
    m = report.get("manifest") or {}
    raw = str(m.get("target_sdk") or "")
    if not raw.isdigit():
        return False, []
    below = int(raw) < int(val)
    return below, [f"targetSdk {raw} < {val}"] if below else []


def _c_debuggable(val: Any, report: dict, drift: dict | None) -> tuple[bool, list[str]]:
    m = report.get("manifest") or {}
    hit = bool(m.get("debuggable")) == bool(val) and bool(val)
    return hit, ["android:debuggable=true"] if hit else []


def _c_native_libs(val: Any, report: dict, drift: dict | None) -> tuple[bool, list[str]]:
    libs = report.get("native") or []
    hit = len(libs) > int(val)
    return hit, [f"{len(libs)} native lib(s)"] if hit else []


def _c_engine_errors(val: Any, report: dict, drift: dict | None) -> tuple[bool, list[str]]:
    """Fail closed. A build the scanner could not fully read is not a clean
    build — without this, an unparseable dex silently becomes a pass."""
    errs = report.get("errors") or []
    hit = bool(errs) == bool(val) and bool(val)
    return hit, list(errs)[:4] if hit else []


# --- drift conditions (require a baseline) -----------------------------------
class _NeedsBaseline(Exception):
    """Internal: a drift condition was evaluated with no baseline.

    Deliberately NOT a PolicyError. A missing baseline is a normal state (every
    first scan), not a malformed policy, and conflating them made the shipped
    default policy fail on first use.
    """


def _need_drift(drift: dict | None, cond: str) -> dict[str, Any]:
    if drift is None:
        raise _NeedsBaseline(f"'{cond}' needs a baseline — pass --baseline")
    return drift


def _c_new_sdk(val: Any, report: dict, drift: dict | None) -> tuple[bool, list[str]]:
    d = _need_drift(drift, "new_sdk")
    hits = [s["name"] for s in d.get("new_sdks", [])]
    return (bool(hits) if val else False), hits


def _c_new_sdk_shares(val: Any, report: dict, drift: dict | None) -> tuple[bool, list[str]]:
    d = _need_drift(drift, "new_sdk_shares_third_party")
    by_slug = {s["slug"]: s for s in _sdks(report)}
    hits = [s["name"] for s in d.get("new_sdks", [])
            if by_slug.get(s["slug"], {}).get("shares_with_third_party")]
    return (bool(hits) if val else False), hits


def _c_new_category(val: Any, report: dict, drift: dict | None) -> tuple[bool, list[str]]:
    d = _need_drift(drift, "new_category")
    hits = list(d.get("new_categories", []))
    return (bool(hits) if val else False), hits


def _c_new_permission(val: Any, report: dict, drift: dict | None) -> tuple[bool, list[str]]:
    d = _need_drift(drift, "new_permission")
    hits = list(d.get("new_permissions", []))
    return (bool(hits) if val else False), hits


def _c_new_finding_at_least(val: Any, report: dict, drift: dict | None) -> tuple[bool, list[str]]:
    d = _need_drift(drift, "new_finding_severity_at_least")
    floor = SEVERITY_ORDER.get(str(val).lower())
    if floor is None:
        raise PolicyError(f"unknown severity: {val!r}")
    hits = [f"{f['severity']}: {f['title']}" for f in d.get("new_findings", [])
            if SEVERITY_ORDER.get(f["severity"], 0) >= floor]
    return bool(hits), hits


def _c_signed_with_debug(val: Any, report: dict, drift: dict | None) -> tuple[bool, list[str]]:
    sg = report.get("signing") or {}
    hits = [s.get("subject_cn") or s["sha256"][:16]
            for s in sg.get("signers") or [] if s.get("is_debug")]
    return (bool(hits) if val else False), hits


def _c_unsigned(val: Any, report: dict, drift: dict | None) -> tuple[bool, list[str]]:
    sg = report.get("signing") or {}
    hit = bool(sg.get("unsigned")) and bool(val)
    return hit, ["no signature present"] if hit else []


def _c_signer_not_in(val: Any, report: dict, drift: dict | None) -> tuple[bool, list[str]]:
    """Pin the publisher. Matches when ANY signer is outside the approved set."""
    allowed = {str(v).lower() for v in (val if isinstance(val, list) else [val])}
    sg = report.get("signing") or {}
    hits = [s["sha256"] for s in sg.get("signers") or []
            if s["sha256"].lower() not in allowed]
    return bool(hits), hits


def _c_signer_changed(val: Any, report: dict, drift: dict | None) -> tuple[bool, list[str]]:
    d = _need_drift(drift, "signer_changed")
    hit = bool(d.get("signer_changed")) and bool(val)
    return hit, [f"{', '.join(d.get('signers_before', []))[:24]}… -> "
                 f"{', '.join(d.get('signers_after', []))[:24]}…"] if hit else []


CONDITIONS = {
    "signed_with_debug_certificate": _c_signed_with_debug,
    "unsigned": _c_unsigned,
    "signer_not_in": _c_signer_not_in,
    "signer_changed": _c_signer_changed,
    "finding": _c_finding,
    "finding_severity_at_least": _c_severity_at_least,
    "sdk": _c_sdk,
    "sdk_not_in": _c_sdk_not_in,
    "sdk_shares_third_party": _c_sdk_shares,
    "declares": _c_declares,
    "declares_shared": _c_declares_shared,
    "permission": _c_permission,
    "target_sdk_below": _c_target_sdk_below,
    "debuggable": _c_debuggable,
    "native_libs_over": _c_native_libs,
    "engine_errors": _c_engine_errors,
    "new_sdk": _c_new_sdk,
    "new_sdk_shares_third_party": _c_new_sdk_shares,
    "new_category": _c_new_category,
    "new_permission": _c_new_permission,
    "new_finding_severity_at_least": _c_new_finding_at_least,
}


@dataclass(slots=True)
class Policy:
    name: str
    rules: list[Rule]

    # --- loading -------------------------------------------------------------
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        name = str((data.get("meta") or {}).get("name") or "unnamed policy")
        raw_rules = data.get("rule") or data.get("rules") or []
        if not isinstance(raw_rules, list) or not raw_rules:
            raise PolicyError("policy defines no rules")

        rules: list[Rule] = []
        seen: set[str] = set()
        for i, r in enumerate(raw_rules):
            rid = str(r.get("id") or f"rule-{i}")
            if rid in seen:
                raise PolicyError(f"duplicate rule id: {rid}")
            seen.add(rid)

            action = str(r.get("action", "block")).lower()
            if action not in VALID_ACTIONS:
                raise PolicyError(
                    f"rule '{rid}': action must be one of {sorted(VALID_ACTIONS)}, got {action!r}"
                )

            when = r.get("when") or {}
            if not isinstance(when, dict) or not when:
                raise PolicyError(f"rule '{rid}': missing a 'when' block")
            for key in when:
                if key not in CONDITIONS:
                    raise PolicyError(
                        f"rule '{rid}': unknown condition {key!r}. "
                        f"Known: {', '.join(sorted(CONDITIONS))}"
                    )

            expires = r.get("expires")
            if action == "ignore" and not expires:
                # The single most important validation in this file. A waiver
                # with no end date is how a known problem becomes an unknown
                # one — it outlives the context that justified it.
                raise PolicyError(
                    f"rule '{rid}': a waiver (action = \"ignore\") must set an "
                    f"'expires' date, e.g. expires = \"2026-12-31\". Waivers that "
                    f"never expire become permanent blind spots."
                )
            rules.append(Rule(id=rid, action=action, when=when,
                              description=str(r.get("description", "")),
                              expires=str(expires) if expires else None))
        return cls(name=name, rules=rules)

    @classmethod
    def load(cls, path: str) -> Policy:
        with open(path, "rb") as fh:
            raw = fh.read()
        try:
            data = tomllib.loads(raw.decode("utf-8")) if not path.endswith(".json") \
                else json.loads(raw)
        except (tomllib.TOMLDecodeError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise PolicyError(f"{path}: {exc}") from exc
        return cls.from_dict(data)

    # --- evaluation ----------------------------------------------------------
    def evaluate(self, report: dict[str, Any], drift: dict[str, Any] | None = None,
                 today: _dt.date | None = None) -> PolicyDecision:
        today = today or _dt.date.today()
        decision = PolicyDecision(policy_name=self.name, blocked=False)

        # Pass 1: waivers. Applied first so a later block rule cannot fire on a
        # finding the team has explicitly accepted. Expired waivers are ignored
        # AND reported — silently re-enforcing would look like a new failure
        # appearing from nowhere.
        waived_ids: set[str] = set()
        for rule in self.rules:
            if rule.action != "ignore":
                continue
            if rule.expired(today):
                decision.expired_waivers.append(f"{rule.id} (expired {rule.expires})")
                continue
            try:
                matched, ev = self._match(rule, report, drift)
            except _NeedsBaseline as exc:
                decision.skipped.append(f"{rule.id} ({exc})")
                continue
            if matched:
                waived_ids.update(ev)
                decision.waived.append(rule.id)

        scoped = self._without(report, waived_ids)

        # Pass 2: block and warn
        for rule in self.rules:
            if rule.action == "ignore":
                continue
            if rule.expired(today):
                decision.expired_waivers.append(f"{rule.id} (expired {rule.expires})")
                continue
            try:
                matched, ev = self._match(rule, scoped, drift)
            except _NeedsBaseline as exc:
                # A first scan has no baseline, and the shipped policy contains
                # drift rules. Aborting the whole policy would mean the default
                # config fails on the very first run — so drift rules are
                # SKIPPED and reported, never silently treated as passing.
                decision.skipped.append(f"{rule.id} ({exc})")
                continue
            decision.results.append(RuleResult(
                rule_id=rule.id, action=rule.action, matched=matched,
                reason=rule.description or self._describe(rule),
                evidence=tuple(ev[:6]),
            ))

        decision.blocked = bool(decision.blocking)
        decision.summary = self._summarise(decision)
        return decision

    @staticmethod
    def _without(report: dict[str, Any], waived: set[str]) -> dict[str, Any]:
        if not waived:
            return report
        clone = dict(report)
        clone["findings"] = [f for f in (report.get("findings") or [])
                             if f["id"] not in waived]
        return clone

    @staticmethod
    def _match(rule: Rule, report: dict, drift: dict | None) -> tuple[bool, list[str]]:
        """ALL conditions in a `when` block must hold — they are ANDed.

        OR is expressible as two rules, and rules are cheap. Supporting both in
        one block would need nesting, and a policy language you need to debug
        is a policy nobody writes correctly.
        """
        evidence: list[str] = []
        for key, val in rule.when.items():
            matched, ev = CONDITIONS[key](val, report, drift)
            if not matched:
                return False, []
            evidence.extend(ev)
        return True, evidence

    @staticmethod
    def _describe(rule: Rule) -> str:
        return "; ".join(f"{k} = {v}" for k, v in rule.when.items())

    @staticmethod
    def _summarise(d: PolicyDecision) -> str:
        bits = []
        if d.blocking:
            bits.append(f"{len(d.blocking)} blocking: "
                        + ", ".join(r.rule_id for r in d.blocking[:4]))
        if d.warnings:
            bits.append(f"{len(d.warnings)} warning(s)")
        if d.waived:
            bits.append(f"{len(d.waived)} waived")
        if d.expired_waivers:
            bits.append(f"{len(d.expired_waivers)} EXPIRED waiver(s)")
        if d.skipped:
            bits.append(f"{len(d.skipped)} skipped (no baseline)")
        return "; ".join(bits) if bits else "policy satisfied"


DEFAULT_POLICY_TOML = '''# NULLSCAN policy. Copy to your repo and edit.
#   nullscan scan app.apk --policy nullscan.toml
#
# action = "block"  -> exit 1, fail the build
# action = "warn"   -> reported, exit 0
# action = "ignore" -> waiver; REQUIRES an expires date

[meta]
name = "Default release policy"

[[rule]]
id = "no-debuggable-release"
description = "Play rejects debuggable release builds outright."
action = "block"
when = { debuggable = true }

[[rule]]
id = "scanner-must-parse-the-build"
description = "A build we could not fully read is not a clean build."
action = "block"
when = { engine_errors = true }

[[rule]]
id = "declaration-must-stay-accurate"
description = "This build collects a data category your live Play listing does not declare."
action = "block"
when = { new_category = true }

[[rule]]
id = "no-new-tracking-sdk"
description = "A new SDK that shares data with third parties arrived in this build."
action = "block"
when = { new_sdk_shares_third_party = true }

[[rule]]
id = "no-dynamic-code-loading"
description = "Loading code not shipped in the APK violates Device and Network Abuse policy."
action = "block"
when = { finding = "sink.dynamic_code" }

[[rule]]
id = "stale-target-sdk"
description = "Below the Play target-API floor; new releases will be blocked."
action = "warn"
when = { target_sdk_below = 34 }

[[rule]]
id = "new-permissions-need-review"
action = "warn"
when = { new_permission = true }

[[rule]]
id = "no-debug-certificate"
description = "The debug key ships with every Android SDK — anyone can re-sign this."
action = "block"
when = { signed_with_debug_certificate = true }

[[rule]]
id = "publisher-must-not-change"
description = "The signing certificate changed between builds. Verify this was intentional."
action = "block"
when = { signer_changed = true }

[[rule]]
id = "secrets-in-the-apk"
description = "Anything shipped in the APK is public."
action = "block"
when = { finding = "secret.*" }

# Example waiver. Note the expiry — waivers without one are rejected.
# [[rule]]
# id = "accept-legacy-webview-bridge"
# description = "Tracked in JIRA-1234; removing in Q3."
# action = "ignore"
# expires = "2026-12-31"
# when = { finding = "sink.webview_js" }
'''
