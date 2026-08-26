#!/usr/bin/env python3
"""
tools/harvest.py — run the engine across a corpus of real APKs and report back.

WHY THIS EXISTS
---------------
Everything in core/ was proven against synthetic APKs built from the format
spec. That proves the offset arithmetic. It does NOT prove the engine survives
an 80 MB R8-obfuscated app with six dex files and a manifest full of
`@0x7f0a0123` resource references. Nothing you can reason about tells you that.
You have to run it.

This does two jobs in one pass, because both need the same expensive walk:

  JOB 1 — ENGINE HEALTH
    Which APKs crash, time out, produce an empty manifest, or return zero SDKs
    (the silent failure — a "successful" scan that found nothing is worse than
    an exception, because it ships a wrong declaration).

  JOB 2 — SIGNATURE MINING
    Every class-package prefix in the corpus that NO signature matched, ranked
    by how many distinct apps contain it. That ranking is the correct one:
    a library in 40 of 50 apps is worth a signature; one in a single app is not.
    Output is a paste-ready stub block for core/signatures.py.

USAGE
    python3 /home/claude/nullscan/tools/harvest.py /path/to/apk/dir
    python3 /home/claude/nullscan/tools/harvest.py /path/to/apks --out /path/to/results
    python3 /home/claude/nullscan/tools/harvest.py /path/to/apks --jobs 4 --timeout 180
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
import traceback
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import analyze_path
from core.container import ContainerError, open_apk
from core.dex import parse_dex
from core.signatures import SDK_SIGNATURES

# Platform / language namespaces are never SDK candidates.
PLATFORM_PREFIXES = (
    "android/", "androidx/", "java/", "javax/", "kotlin/", "kotlinx/",
    "dalvik/", "sun/", "libcore/", "org/w3c/", "org/xml/", "org/xmlpull/",
    "org/json/", "org/apache/http/", "org/intellij/",
    "org/jetbrains/annotations/", "junit/", "org/junit/",
    "org/checkerframework/", "j$/", "org/chromium/", "internal/org/",
    "com/android/internal/", "com/android/org/",
)

# Utility libraries: real third-party code, but they collect nothing, so a
# signature for them would be noise in every report.
#
# This list was BUILT FROM THE FIRST CORPUS RUN. Without it the top of the
# backlog was Guava, protobuf, Conscrypt and OkIO — present in 20-36 apps each
# and worth exactly zero to a compliance product. Filtering them is what makes
# the ranking point at ad networks instead.
UTILITY_PREFIXES = (
    "com/google/common/", "com/google/gson/", "com/google/protobuf/",
    "com/google/errorprone/", "com/google/j2objc/", "com/google/thirdparty/",
    "com/google/crypto/", "com/google/auto/", "com/google/flatbuffers/",
    "com/google/accompanist/", "com/google/zxing/",
    "org/conscrypt/", "org/bouncycastle/", "org/spongycastle/",
    "org/apache/commons/", "org/slf4j/", "org/openjsse/", "org/fmod/",
    "okio/", "okhttp3/", "retrofit2/", "dagger/", "javax/inject/",
    "com/fasterxml/jackson/", "io/reactivex/", "io/ktor/",
    "com/squareup/moshi/", "com/squareup/picasso/", "com/squareup/wire/",
    "com/android/volley/", "com/airbnb/lottie/", "coil/", "coil3/",
    "com/caverock/androidsvg/", "com/bumptech/glide/",
    "bitter/jnibridge/", "gatewayprotocol/", "com/google/androidgamesdk/",
    "com/unity3d/player/", "com/google/mlkit/",
    # UI / support libraries that live under vendor namespaces
    "com/google/android/material/", "com/google/android/flexbox/",
    "com/google/android/datatransport/", "com/google/api/", "com/google/rpc/",
    "com/google/type/", "io/grpc/", "org/threeten/", "org/reactivestreams/",
    "com/jakewharton/", "org/greenrobot/", "io/noties/", "org/koin/",
    "org/objectweb/", "com/otaliastudios/", "org/tensorflow/",
    # Meta OSS that is NOT the tracking SDK — Fresco, SoLoader, Yoga, Bolts
    "com/facebook/soloader/", "com/facebook/imagepipeline/",
    "com/facebook/drawee/", "com/facebook/fresco/", "com/facebook/yoga/",
    "com/facebook/binaryresource/", "com/facebook/cache/",
    "com/facebook/bolts/", "com/facebook/common/",
)

KNOWN_PREFIXES = tuple(
    p.strip("/") + "/" for sig in SDK_SIGNATURES for p in sig.class_prefixes
)

# R8/ProGuard renames classes to a, b, aa, a1... Counting those tells us how
# obfuscated a build is, which predicts how much the string-based rules degrade.
_SHORT_NAME = re.compile(r"^[a-z]{1,2}[0-9]{0,2}$")


def _prefix_of(descriptor: str, depth: int = 3) -> str | None:
    """'Lcom/squareup/picasso/Picasso;' -> 'com/squareup/picasso'"""
    if not descriptor.startswith("L") or not descriptor.endswith(";"):
        return None
    path = descriptor[1:-1]
    parts = path.split("/")
    if len(parts) < 2:
        return None
    return "/".join(parts[: min(depth, len(parts) - 1)])


def _is_candidate(prefix: str, own_package: str) -> bool:
    p = prefix + "/"
    if p.startswith(PLATFORM_PREFIXES) or p.startswith(UTILITY_PREFIXES):
        return False
    # Bidirectional. A mined prefix is depth-3, but a signature may be deeper
    # ("com/google/firebase/analytics"), so the mined "com/google/firebase" is
    # an ANCESTOR of something we already know. Only checking one direction
    # floods the backlog with libraries that are already covered.
    if p.startswith(KNOWN_PREFIXES):
        return False
    if any(known.startswith(p) for known in KNOWN_PREFIXES):
        return False
    if own_package and prefix.replace("/", ".").startswith(own_package.rsplit(".", 1)[0]):
        return False
    segs = prefix.split("/")
    if len(segs) < 2:
        return False
    if all(_SHORT_NAME.match(s) for s in segs):
        return False
    return True


def probe(path: str) -> dict:
    """Analyse one APK and collect both health metrics and prefix candidates.

    Runs in a worker process, so it returns only plain picklable values and
    never raises — a crash here must be data, not a lost result.
    """
    row: dict = {
        "file": os.path.basename(path),
        "size_mb": round(os.path.getsize(path) / (1024 * 1024), 2),
        "status": "ok",
        "elapsed_s": 0.0,
        "package": "",
        "target_sdk": "",
        "dex_count": 0,
        "class_count": 0,
        "obfuscation_pct": 0,
        "sdk_count": 0,
        "finding_count": 0,
        "declaration_count": 0,
        "perm_count": 0,
        "native_count": 0,
        "engine_errors": "",
        "failure": "",
        "top_unmatched": "",
    }
    candidates: dict[str, int] = {}

    t0 = time.time()
    try:
        report = analyze_path(path)
        row["elapsed_s"] = round(time.time() - t0, 2)

        m = report.get("manifest")
        row["engine_errors"] = " | ".join(report.get("errors", []))[:400]
        row["sdk_count"] = len(report.get("sdks", []))
        row["finding_count"] = len(report.get("findings", []))
        row["declaration_count"] = len(report.get("declaration", []))
        row["native_count"] = len(report.get("native", []))

        if m is None:
            row["status"] = "manifest_failed"
        else:
            row["package"] = m["package"]
            row["target_sdk"] = m["target_sdk"]
            row["perm_count"] = len(m["permissions"])
            if not m["package"]:
                row["status"] = "manifest_empty_package"

        # second pass over the dex tables for prefix mining
        with open_apk(path) as apk:
            dex_names = apk.dex_names()
            row["dex_count"] = len(dex_names)
            short = total = 0
            for dn in dex_names:
                try:
                    tables = parse_dex(apk.read(dn), dn)
                except Exception:
                    continue
                for cls in tables.defined_classes:
                    total += 1
                    leaf = cls[1:-1].rsplit("/", 1)[-1] if cls.startswith("L") else ""
                    if _SHORT_NAME.match(leaf):
                        short += 1
                for t in tables.type_set:
                    p = _prefix_of(t)
                    if p and _is_candidate(p, row["package"]):
                        candidates[p] = candidates.get(p, 0) + 1
            row["class_count"] = total
            row["obfuscation_pct"] = round(100 * short / total) if total else 0

        # Zero SDKs is not automatically a miss. The first corpus run flagged
        # five apps; four were TRUE NEGATIVES — Termux, an F-Droid app, and two
        # Google system apps genuinely link no data-collecting SDKs. Treating
        # those as failures would have sent me hunting a bug that isn't there.
        #
        # The real signal is zero SDKs WHILE unmatched third-party prefixes are
        # present: something is in there and the table doesn't know it.
        if row["status"] == "ok" and row["sdk_count"] == 0 and row["class_count"] > 500:
            if row["obfuscation_pct"] >= 80:
                # Package names are gone. Nothing to fingerprint — a limit of
                # the approach, not a bug. Worth counting separately because if
                # this number climbs, prefix matching stops being viable.
                row["status"] = "obfuscated_beyond_detection"
            elif len(candidates) >= 4:
                row["status"] = "zero_sdk_suspicious"
                # Flagging a file without naming the evidence makes the operator
                # guess. Termux tripped this on Material Components and Fresco —
                # thirty seconds to dismiss WITH the list, an afternoon without it.
                row["top_unmatched"] = ", ".join(
                    p for p, _ in sorted(candidates.items(),
                                         key=lambda kv: -kv[1])[:6])
            else:
                row["status"] = "zero_sdk_true_negative"
        if report.get("errors"):
            row["status"] = "ok_with_errors" if row["status"] == "ok" else row["status"]

    except ContainerError as exc:
        row["status"] = "rejected"
        row["failure"] = str(exc)[:300]
        row["elapsed_s"] = round(time.time() - t0, 2)
    except Exception as exc:
        row["status"] = "CRASH"
        row["failure"] = f"{type(exc).__name__}: {exc}"[:300]
        row["trace"] = traceback.format_exc()[-1200:]
        row["elapsed_s"] = round(time.time() - t0, 2)

    return {"row": row, "candidates": candidates}


def find_apks(root: str) -> list[str]:
    if os.path.isfile(root):
        return [root]
    out = []
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            if f.lower().endswith((".apk", ".aab", ".apks")):
                out.append(os.path.join(dirpath, f))
    return sorted(out)


def write_candidate_stubs(path: str, ranked: list[tuple[str, int, int]]) -> None:
    lines = [
        '"""Auto-mined SDK candidates — fill in name/vendor/collects, then move',
        "into core/signatures.py::SDK_SIGNATURES.",
        "",
        "Ranked by APP FREQUENCY (how many distinct APKs contain the prefix), not",
        "class count. A library in 40 of 50 apps earns a signature; one in a single",
        "app does not. Delete rows you don't recognise rather than guessing —",
        "a wrong `collects` list produces a wrong legal declaration.",
        '"""',
        "",
        "from core.models import DataCategory as DC",
        "from core.signatures import SdkSignature",
        "",
        "MINED: tuple[SdkSignature, ...] = (",
    ]
    for prefix, app_count, class_count in ranked:
        slug = prefix.replace("/", "-")
        lines.append(
            f'    # seen in {app_count} app(s), {class_count} class refs\n'
            f'    SdkSignature("{slug}", "TODO", "TODO",\n'
            f'                 ("{prefix}",),\n'
            f'                 (), False),'
        )
    lines.append(")")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def write_report(out_dir: str, rows: list[dict], ranked: list[tuple[str, int, int]],
                 wall: float) -> str:
    by_status: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_status[r["status"]].append(r)

    total = len(rows)
    healthy = len(by_status["ok"]) + len(by_status["ok_with_errors"])
    crashes = by_status["CRASH"]
    obf = [r for r in rows if r["obfuscation_pct"] >= 40]

    L = [
        "# NULLSCAN corpus harvest",
        "",
        f"- **{total}** APK(s) in {wall:.1f}s",
        f"- **{healthy}** produced a usable report "
        f"({100 * healthy // total if total else 0}%)",
        f"- **{len(crashes)}** crashed",
        f"- **{len(by_status['manifest_failed'])}** manifest undecodable",
        f"- **{len(by_status['zero_sdk_suspicious'])}** zero SDKs *with* unmatched "
        "third-party prefixes (real miss — investigate first)",
        f"- **{len(by_status['zero_sdk_true_negative'])}** zero SDKs and nothing unmatched "
        "(true negative — app genuinely links none)",
        f"- **{len(by_status['obfuscated_beyond_detection'])}** obfuscated past the point "
        "package names exist (limit of the approach, not a bug)",
        f"- **{len(by_status['rejected'])}** rejected at the container boundary",
        f"- **{len(obf)}** heavily obfuscated (>=40% short class names)",
        "",
        "## Ship gate",
        "",
    ]
    # Two different verdicts, deliberately not collapsed into one.
    #   BLOCKED  = the engine is wrong (crash, unparseable manifest, timeout).
    #              Not shippable at any price.
    #   BACKLOG  = the engine is correct but the signature table has holes.
    #              Shippable, provided the gaps are disclosed rather than hidden.
    # Merging these would either hide crashes behind a soft pass or hold a
    # working engine hostage to a table that is never finished.
    broken = len(crashes) + len(by_status["manifest_failed"]) + len(by_status["TIMEOUT"])
    gaps = len(by_status["zero_sdk_suspicious"])
    if broken:
        L.append(f"**BLOCKED** — {broken} APK(s) the engine could not parse. "
                 "Not shippable. Fix these first; nothing else matters until they pass.")
    elif gaps:
        L.append(f"**PASS WITH BACKLOG** — engine parsed everything. {gaps} app(s) "
                 "returned no SDKs while unmatched prefixes were present, so the "
                 "table has holes. Shippable if you disclose coverage; work the "
                 "backlog below.")
    else:
        L.append("**PASS** — engine parsed everything and found no unexplained "
                 "coverage gaps. Move to widening the signature table for depth.")
    L.append("")

    if crashes:
        L += ["## Crashes (fix first)", ""]
        for r in crashes:
            L.append(f"### `{r['file']}` ({r['size_mb']} MB)")
            L.append(f"```\n{r['failure']}\n{r.get('trace', '')}\n```")
            L.append("")

    for label, key in (
        ("Manifest undecodable", "manifest_failed"),
        ("Empty package name", "manifest_empty_package"),
        ("Zero SDKs WITH unmatched prefixes — real miss", "zero_sdk_suspicious"),
        ("Zero SDKs, nothing unmatched — true negative", "zero_sdk_true_negative"),
        ("Obfuscated past detection", "obfuscated_beyond_detection"),
        ("Rejected by container", "rejected"),
    ):
        if by_status[key]:
            L += [f"## {label}", "", "| file | size | classes | obf% | note |", "|---|---|---|---|---|"]
            for r in by_status[key]:
                note = (r["failure"] or r["top_unmatched"]
                        or r["engine_errors"] or "-")[:110]
                L.append(f"| {r['file']} | {r['size_mb']} MB | {r['class_count']} | "
                         f"{r['obfuscation_pct']}% | {note} |")
            L.append("")

    with_errs = [r for r in rows if r["engine_errors"]]
    if with_errs:
        L += ["## Non-fatal engine errors", "", "| file | error |", "|---|---|"]
        for r in with_errs[:40]:
            L.append(f"| {r['file']} | {r['engine_errors'][:110]} |")
        L.append("")

    slow = sorted(rows, key=lambda r: -r["elapsed_s"])[:10]
    L += ["## Slowest (sets your job timeout)", "",
          "| file | size | dex | classes | seconds |", "|---|---|---|---|---|"]
    for r in slow:
        L.append(f"| {r['file']} | {r['size_mb']} MB | {r['dex_count']} | "
                 f"{r['class_count']} | {r['elapsed_s']} |")
    L.append("")

    L += ["## Detection coverage", "",
          "| file | package | SDKs | findings | declared cats | perms |", "|---|---|---|---|---|---|"]
    for r in sorted(rows, key=lambda r: -r["sdk_count"])[:40]:
        L.append(f"| {r['file']} | {r['package'] or '-'} | {r['sdk_count']} | "
                 f"{r['finding_count']} | {r['declaration_count']} | {r['perm_count']} |")
    L.append("")

    L += [f"## Top {len(ranked)} unmatched prefixes", "",
          "Ranked by number of distinct apps containing them. This is your "
          "signature backlog — work down it in order.", "",
          "| prefix | apps | class refs |", "|---|---|---|"]
    for prefix, app_count, class_count in ranked:
        L.append(f"| `{prefix}` | {app_count} | {class_count} |")
    L.append("")

    path = os.path.join(out_dir, "HARVEST.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")
    return path


def main() -> int:
    ap = argparse.ArgumentParser(prog="harvest")
    ap.add_argument("corpus", help="directory of APKs (or a single APK)")
    ap.add_argument("--out", default=None, help="output directory")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--timeout", type=int, default=300, help="per-APK seconds")
    ap.add_argument("--top", type=int, default=80, help="candidate prefixes to emit")
    ap.add_argument("--min-apps", type=int, default=2,
                    help="ignore prefixes appearing in fewer than N apps")
    a = ap.parse_args()

    apks = find_apks(a.corpus)
    if not apks:
        print(f"no APKs found under {a.corpus}", file=sys.stderr)
        return 2

    out_dir = a.out or os.path.join(os.path.dirname(os.path.abspath(a.corpus.rstrip("/"))),
                                    "nullscan-harvest")
    os.makedirs(out_dir, exist_ok=True)

    print(f"scanning {len(apks)} APK(s) with {a.jobs} worker(s) -> {out_dir}\n")

    rows: list[dict] = []
    app_freq: Counter[str] = Counter()
    class_freq: Counter[str] = Counter()
    t0 = time.time()

    with ProcessPoolExecutor(max_workers=a.jobs) as pool:
        futures = {pool.submit(probe, p): p for p in apks}
        for i, fut in enumerate(as_completed(futures), 1):
            src = futures[fut]
            try:
                res = fut.result(timeout=a.timeout)
            except Exception as exc:
                res = {"row": {"file": os.path.basename(src), "status": "TIMEOUT",
                               "failure": str(exc)[:200], "size_mb": 0, "elapsed_s": a.timeout,
                               "package": "", "target_sdk": "", "dex_count": 0,
                               "class_count": 0, "obfuscation_pct": 0, "sdk_count": 0,
                               "finding_count": 0, "declaration_count": 0,
                               "perm_count": 0, "native_count": 0, "engine_errors": ""},
                       "candidates": {}}
            row = res["row"]
            rows.append(row)
            for prefix, n in res["candidates"].items():
                app_freq[prefix] += 1
                class_freq[prefix] += n

            flag = {"ok": "\033[32m ok \033[0m", "ok_with_errors": "\033[33mwarn\033[0m",
                    "CRASH": "\033[31mCRSH\033[0m", "TIMEOUT": "\033[31mT/O \033[0m"}.get(
                        row["status"], "\033[33m??? \033[0m")
            print(f"[{i:>3}/{len(apks)}] {flag} {row['file'][:44]:<44} "
                  f"{row['sdk_count']:>3} sdk  {row['elapsed_s']:>6.2f}s  "
                  f"obf {row['obfuscation_pct']:>3}%")

    wall = time.time() - t0

    ranked = [(p, app_freq[p], class_freq[p])
              for p in app_freq
              if app_freq[p] >= a.min_apps]
    ranked.sort(key=lambda x: (-x[1], -x[2]))
    ranked = ranked[: a.top]

    csv_path = os.path.join(out_dir, "engine_health.csv")
    fields = [k for k in rows[0] if k != "trace"]
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    stub_path = os.path.join(out_dir, "candidate_signatures.py")
    write_candidate_stubs(stub_path, ranked)

    json_path = os.path.join(out_dir, "harvest.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump({"rows": rows, "candidates": ranked, "wall_s": wall}, fh, indent=2)

    md_path = write_report(out_dir, rows, ranked, wall)

    bad = sum(1 for r in rows if r["status"] in
              {"CRASH", "TIMEOUT", "manifest_failed", "zero_sdk_suspicious"})
    print(f"\n\033[1m{len(rows)} scanned, {bad} need attention, {wall:.1f}s\033[0m")
    print(f"  report     {md_path}")
    print(f"  csv        {csv_path}")
    print(f"  candidates {stub_path}\n")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
