#!/usr/bin/env python3
"""
nullscan CLI — the same engine, no server.

This exists because `core/` has no framework dependency. One codebase ships as
a hosted API, a CI gate, and an on-prem binary for customers whose legal team
will not let an APK leave the building. That third one is the enterprise tier
and it costs nothing extra to support, because the boundary was drawn on day one.

    python3 /home/claude/nullscan/cli.py scan app.apk
    python3 /home/claude/nullscan/cli.py scan app.apk --json > report.json
    python3 /home/claude/nullscan/cli.py diff baseline.json candidate.apk --fail-on-drift
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import (
    DEFAULT_POLICY_TOML,
    ENGINE_VERSION,
    Policy,
    PolicyError,
    analyze_path,
    diff_reports,
    sbom_json,
)

BOLD, DIM, RED, YEL, GRN, CYA, OFF = (
    "\033[1m", "\033[2m", "\033[31m", "\033[33m", "\033[32m", "\033[36m", "\033[0m"
)
SEV_COLOR = {"high": RED, "medium": YEL, "low": CYA, "info": DIM}


def _load(path: str) -> dict:
    """Accept either a stored JSON report or a live APK."""
    if path.endswith(".json"):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    return analyze_path(path)


def render(report: dict) -> None:
    m = report.get("manifest")
    print(f"\n{BOLD}NULLSCAN {ENGINE_VERSION}{OFF}  {DIM}{report['apk_sha256'][:16]}…{OFF}")
    if m:
        print(f"{BOLD}{m['package']}{OFF} v{m['version_name']} ({m['version_code']})  "
              f"{DIM}minSdk {m['min_sdk']} / targetSdk {m['target_sdk']}{OFF}")
    print(f"{DIM}{'─' * 68}{OFF}")

    if report["errors"]:
        print(f"{RED}errors:{OFF} " + "; ".join(report["errors"]))
        print(f"{DIM}{'─' * 68}{OFF}")

    findings = report["findings"]
    if findings:
        print(f"\n{BOLD}FINDINGS ({len(findings)}){OFF}")
        for f in findings:
            c = SEV_COLOR.get(f["severity"], "")
            print(f"  {c}{f['severity'].upper():<7}{OFF} {f['title']}")
            for e in f["evidence"][:2]:
                print(f"          {DIM}{e['kind']}: {e['detail'][:80]}{OFF}")
            if f["remediation"]:
                print(f"          {CYA}→ {f['remediation']}{OFF}")

    sdks = report["sdks"]
    if sdks:
        print(f"\n{BOLD}THIRD-PARTY SDKs ({len(sdks)}){OFF}")
        for s in sdks:
            tag = f"{YEL}shares{OFF}" if s["shares_with_third_party"] else f"{DIM}local{OFF}"
            cats = ", ".join(s["collects"]) or "no user data"
            print(f"  {s['name']:<28} {tag:<18} {DIM}{cats}{OFF}")

    decl = report["declaration"]
    if decl:
        print(f"\n{BOLD}PLAY DATA SAFETY DECLARATION ({len(decl)} categories){OFF}")
        print(f"  {DIM}{'category':<26}{'collected':<11}{'shared':<9}{'required'}{OFF}")
        for d in decl:
            print(f"  {d['category']:<26}"
                  f"{'yes':<11}"
                  f"{('yes' if d['shared'] else 'no'):<9}"
                  f"{'yes' if d['required'] else 'no'}")
            print(f"    {DIM}{d['justification'][0][:78]}{OFF}")

    sg = report.get("signing") or {}
    if sg.get("schemes") or sg.get("unsigned"):
        print(f"\n{BOLD}SIGNING{OFF}")
        if sg.get("unsigned"):
            print(f"  {RED}unsigned{OFF}  {DIM}no v1/v2/v3 signature present{OFF}")
        else:
            print(f"  schemes       {', '.join(sg['schemes'])}")
        for sn in sg.get("signers", []):
            tag = f" {RED}DEBUG KEY{OFF}" if sn["is_debug"] else ""
            who = sn["subject_cn"] or sn["organization"] or "unknown"
            print(f"  {who}{tag}")
            print(f"    {DIM}SHA-256 {sn['sha256']}{OFF}")
        if sg.get("note"):
            print(f"  {DIM}{sg['note']}{OFF}")

    if report["native"]:
        print(f"\n{BOLD}NATIVE ({len(report['native'])}){OFF}")
        for n in report["native"][:8]:
            print(f"  {n['abi']:<14} {n['lib']}  {DIM}{n['size_bytes']:,} B{OFF}")
    print()


def render_drift(d: dict) -> None:
    print(f"\n{BOLD}COMPLIANCE DRIFT{OFF}")
    print(f"{DIM}{d['base_sha256'][:12]}… → {d['head_sha256'][:12]}…{OFF}")
    print(f"{DIM}{'─' * 68}{OFF}")
    for label, items, color in (
        ("new SDK", d["new_sdks"], YEL),
        ("removed SDK", d["removed_sdks"], DIM),
    ):
        for s in items:
            print(f"  {color}{label:<14}{OFF} {s['name']} ({s['vendor']})")
    for f in d["new_findings"]:
        print(f"  {SEV_COLOR.get(f['severity'], '')}new finding{OFF}    "
              f"[{f['severity']}] {f['title']}")
    for f in d["resolved_findings"]:
        print(f"  {GRN}resolved{OFF}       {f['title']}")
    for p in d["new_permissions"]:
        print(f"  {YEL}new perm{OFF}       {p}")
    if d.get("signer_changed"):
        print(f"  {RED}SIGNER{OFF}         certificate changed between builds")
        for h in d.get("signers_before", []):
            print(f"    {DIM}was {h}{OFF}")
        for h in d.get("signers_after", []):
            print(f"    {YEL}now {h}{OFF}")
    for s_ in d.get("schemes_removed", []):
        print(f"  {YEL}scheme lost{OFF}    {s_}")
    for c in d["new_categories"]:
        print(f"  {RED}DECLARE{OFF}        {c} {DIM}(your Data Safety form is now wrong){OFF}")
    for c in d["removed_categories"]:
        print(f"  {GRN}undeclare{OFF}      {c}")
    print(f"\n  {BOLD}{d['summary']}{OFF}\n")


def render_policy(d: dict) -> None:
    print(f"\n{BOLD}POLICY{OFF}  {DIM}{d['policy_name']}{OFF}")
    print(f"{DIM}{'─' * 68}{OFF}")
    for r in d["results"]:
        if not r["matched"]:
            print(f"  {GRN}pass{OFF}      {DIM}{r['rule_id']}{OFF}")
            continue
        color = RED if r["action"] == "block" else YEL
        print(f"  {color}{r['action'].upper():<9}{OFF} {BOLD}{r['rule_id']}{OFF}")
        if r["reason"]:
            print(f"            {DIM}{r['reason']}{OFF}")
        for e in r["evidence"]:
            print(f"            {CYA}{e}{OFF}")
    for w in d["waived"]:
        print(f"  {DIM}waived    {w}{OFF}")
    for sk in d.get("skipped", []):
        print(f"  {DIM}skipped   {sk}{OFF}")
    for w in d["expired_waivers"]:
        # Loud on purpose: an expired waiver means a rule silently came back
        # on, and the resulting failure would otherwise look like it appeared
        # from nowhere.
        print(f"  {YEL}EXPIRED{OFF}   {w} {DIM}— this rule is enforcing again{OFF}")
    print(f"\n  {BOLD}{d['summary']}{OFF}\n")


def _apply_policy(path: str, report: dict, drift: dict | None) -> int:
    try:
        policy = Policy.load(path)
    except PolicyError as exc:
        print(f"{RED}policy error:{OFF} {exc}", file=sys.stderr)
        return 2
    try:
        decision = policy.evaluate(report, drift)
    except PolicyError as exc:
        print(f"{RED}policy error:{OFF} {exc}", file=sys.stderr)
        return 2
    render_policy(decision.to_dict())
    return 1 if decision.blocked else 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="nullscan")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="analyse one APK")
    s.add_argument("apk")
    s.add_argument("--json", action="store_true", help="machine output")
    s.add_argument("--fail-on", choices=["high", "medium", "low", "never"],
                   default="never", help="exit 1 when a finding at/above this level exists")
    s.add_argument("--sbom", metavar="FILE",
                   help="write a CycloneDX 1.5 SBOM alongside the report")
    s.add_argument("--policy", metavar="FILE",
                   help="evaluate a policy file; exit 1 if any block rule matches")
    s.add_argument("--baseline", metavar="FILE",
                   help="baseline report, so drift conditions can be evaluated")

    d = sub.add_parser("diff", help="compare a baseline against a candidate")
    d.add_argument("base", help="baseline .json report or .apk")
    d.add_argument("head", help="candidate .json report or .apk")
    d.add_argument("--json", action="store_true")
    d.add_argument("--fail-on-drift", action="store_true",
                   help="exit 1 when the Data Safety declaration would change")
    d.add_argument("--policy", metavar="FILE",
                   help="evaluate a policy file against the candidate and the drift")

    p = sub.add_parser("policy", help="create or check a policy file")
    p.add_argument("action", choices=["init", "check"])
    p.add_argument("file", nargs="?", default="nullscan.toml")

    a = ap.parse_args()

    if a.cmd == "policy":
        if a.action == "init":
            if os.path.exists(a.file):
                print(f"{a.file} already exists; not overwriting", file=sys.stderr)
                return 1
            with open(a.file, "w", encoding="utf-8") as fh:
                fh.write(DEFAULT_POLICY_TOML)
            print(f"wrote {a.file}")
            return 0
        try:
            pol = Policy.load(a.file)
        except PolicyError as exc:
            print(f"{RED}invalid:{OFF} {exc}", file=sys.stderr)
            return 1
        print(f"{GRN}valid{OFF}  {pol.name}  {len(pol.rules)} rule(s)")
        for r in pol.rules:
            exp = f"  expires {r.expires}" if r.expires else ""
            print(f"  {r.action:<6} {r.id}{DIM}{exp}{OFF}")
        return 0

    if a.cmd == "scan":
        rep = analyze_path(a.apk)
        print(json.dumps(rep, indent=2)) if a.json else render(rep)

        if a.sbom:
            with open(a.sbom, "w", encoding="utf-8") as fh:
                fh.write(sbom_json(rep))
            if not a.json:
                print(f"{DIM}SBOM written to {a.sbom}{OFF}\n")

        if a.policy:
            drift = None
            if a.baseline:
                drift = diff_reports(_load(a.baseline), rep).to_dict()
            code = _apply_policy(a.policy, rep, drift)
            if code:
                return code

        if a.fail_on != "never":
            order = {"high": 0, "medium": 1, "low": 2, "info": 3}
            worst = min((order[f["severity"]] for f in rep["findings"]), default=99)
            return 1 if worst <= order[a.fail_on] else 0
        return 0

    head_report = _load(a.head)
    drift = diff_reports(_load(a.base), head_report).to_dict()
    print(json.dumps(drift, indent=2)) if a.json else render_drift(drift)

    if a.policy:
        code = _apply_policy(a.policy, head_report, drift)
        if code:
            return code

    return 1 if (a.fail_on_drift and drift["blocking"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
