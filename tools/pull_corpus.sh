#!/usr/bin/env bash
# tools/pull_corpus.sh — build an APK corpus from a device over adb.
#
# Use this from a desktop with the phone on USB, or from Termux after pairing
# wireless debugging to 127.0.0.1. To pull on-device with no adb at all, use
# tools/pull_corpus_termux.sh instead.
#
#   bash /home/jigga/nullscan/tools/pull_corpus.sh
#   bash /home/jigga/nullscan/tools/pull_corpus.sh /home/jigga/apk-corpus 60 200
#         args: <dest dir> <max apks> <max MB per apk>
#
# SPLIT APKs: we take base.apk only. It carries AndroidManifest.xml and the
# primary dex — everything the scanner reads. Config splits are resources and
# native libs, so native_count reads 0 for those apps in the harvest. That is a
# corpus artefact, not an engine bug.

set -uo pipefail

DEST="${1:-/home/jigga/apk-corpus}"
LIMIT="${2:-40}"
MAX_MB="${3:-200}"

command -v adb >/dev/null 2>&1 || {
    echo "adb not found. Fedora: sudo dnf install android-tools" >&2; exit 1; }

if ! adb devices | awk 'NR>1 && $2=="device"{f=1} END{exit !f}'; then
    echo "No authorised device. Enable USB debugging, accept the prompt, then: adb devices" >&2
    adb devices >&2
    exit 1
fi

mkdir -p "$DEST"

# Read the package list into an array FIRST. Piping into `while read` runs the
# loop in a subshell, so every counter increment is discarded when it exits —
# a classic and very quiet shell bug.
mapfile -t pkgs < <(adb shell pm list packages -3 | tr -d '\r' | sed 's/^package://' | sort)

if [ "${#pkgs[@]}" -eq 0 ]; then
    echo "no third-party packages returned by pm" >&2
    exit 1
fi

echo "found ${#pkgs[@]} third-party package(s); pulling up to $LIMIT -> $DEST"
echo

count=0; split_count=0; skipped_big=0; failed=0

for pkg in "${pkgs[@]}"; do
    [ "$count" -ge "$LIMIT" ] && break
    [ -z "$pkg" ] && continue

    out="$DEST/${pkg}.apk"
    if [ -f "$out" ]; then
        printf '  %-8s %s\n' "have" "$pkg"
        count=$((count + 1))
        continue
    fi

    mapfile -t paths < <(adb shell pm path "$pkg" | tr -d '\r' | sed 's/^package://' | grep .)
    [ "${#paths[@]}" -eq 0 ] && { failed=$((failed + 1)); continue; }

    base=""
    for p in "${paths[@]}"; do
        case "$p" in */base.apk) base="$p"; break ;; esac
    done
    [ -z "$base" ] && base="${paths[0]}"
    [ "${#paths[@]}" -gt 1 ] && split_count=$((split_count + 1))

    bytes=$(adb shell stat -c %s "$base" 2>/dev/null | tr -d '\r')
    case "$bytes" in ''|*[!0-9]*) bytes=0 ;; esac
    mb=$(( bytes / 1048576 ))
    if [ "$mb" -gt "$MAX_MB" ]; then
        printf '  %-8s %s (%s MB)\n' "too big" "$pkg" "$mb"
        skipped_big=$((skipped_big + 1))
        continue
    fi

    if adb pull "$base" "$out" >/dev/null 2>&1; then
        tag="single"
        [ "${#paths[@]}" -gt 1 ] && tag="split:${#paths[@]}"
        printf '  %-8s %-46s %4s MB  %s\n' "pulled" "$pkg" "$mb" "$tag"
        count=$((count + 1))
    else
        printf '  %-8s %s\n' "FAILED" "$pkg"
        failed=$((failed + 1))
    fi
done

have=$(ls -1 "$DEST"/*.apk 2>/dev/null | wc -l)
echo
echo "corpus: $have APK(s) in $DEST"
echo "  $split_count from split bundles (base.apk only)"
echo "  $skipped_big skipped as >${MAX_MB} MB"
echo "  $failed failed"
echo
echo "next:"
echo "  python3 $(dirname "$0")/harvest.py $DEST --out ${DEST}-results"
