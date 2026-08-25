#!/data/data/com.termux/files/usr/bin/bash
# tools/pull_corpus_termux.sh — build an APK corpus ON the device, from Termux.
#
# Tries the no-adb path first (`pm` + `cp`). On Android 11+ that is frequently
# blocked, so this script DIAGNOSES the failure and prints the exact fallback
# rather than producing a silent empty corpus.
#
#   bash $HOME/nullscan/tools/pull_corpus_termux.sh
#   bash $HOME/nullscan/tools/pull_corpus_termux.sh $HOME/apk-corpus 40 150
#         args: <dest dir> <max apks> <max MB per apk>

set -uo pipefail

DEST="${1:-$HOME/apk-corpus}"
LIMIT="${2:-40}"
MAX_MB="${3:-150}"

mkdir -p "$DEST"

print_fallbacks() {
cat >&2 <<MSG

────────────────────────────────────────────────────────────────
On-device \`pm\` is blocked. Android 11+ refuses \`cmd package\` from a
normal app UID; Termux is not the shell user. Nothing you can fix in
this script — use one of these instead.

OPTION 1 — wireless debugging, still no PC (recommended)

    pkg install android-tools
    bash \$HOME/nullscan/tools/adb_wireless.sh

  That prompts you for the two port numbers, pairs, connects, and
  offers to pull the corpus. Nothing to copy with angle brackets in
  it — in zsh those are input redirections and blow up the paste.

  adb runs as the shell UID and sees every package.

OPTION 2 — USB to the Fedora box

    bash /home/jigga/nullscan/tools/pull_corpus.sh /home/jigga/apk-corpus 40

OPTION 3 — download APKs in a browser (no debugging at all)

    termux-setup-storage
    # download 20-30 APKs from APKMirror in your browser, then:
    python3 \$HOME/nullscan/tools/harvest.py ~/storage/downloads \\
            --out \$HOME/apk-corpus-results --jobs 1

  harvest.py walks any directory. Prefer APKMirror over F-Droid — F-Droid
  builds are open source and carry almost no ad or analytics SDKs, which
  is exactly the thing you're trying to test detection against.
────────────────────────────────────────────────────────────────
MSG
}

# --- probe pm, and actually validate what came back ----------------------
# A previous version counted lines and word-split the result. When pm returned
#   cmd: Failure calling service package: Failed transaction (2147483646)
# that became "8 packages" and eight bogus rows. Anything that is not a
# `package:` line is an error, not data.
raw=$(pm list packages -3 2>&1)
rc=$?

if [ $rc -ne 0 ] || ! printf '%s\n' "$raw" | grep -q '^package:'; then
    echo "pm did not return a package list." >&2
    echo "  raw output: $(printf '%s' "$raw" | head -c 200)" >&2
    print_fallbacks
    exit 1
fi

mapfile -t pkgs < <(printf '%s\n' "$raw" \
    | grep '^package:' | sed 's/^package://' | tr -d '\r' | grep . | sort)

if [ "${#pkgs[@]}" -eq 0 ]; then
    echo "pm returned zero third-party packages." >&2
    print_fallbacks
    exit 1
fi

# --- space check ---------------------------------------------------------
avail_mb=$(df -Pm "$DEST" 2>/dev/null | awk 'NR==2{print $4}')
need_mb=$(( LIMIT * 40 ))
if [ -n "${avail_mb:-}" ] && [ "$avail_mb" -lt "$need_mb" ]; then
    echo "Only ${avail_mb} MB free at $DEST; ~${need_mb} MB recommended for $LIMIT apps."
    printf "continue anyway? [y/N] "
    read -r yn
    case "$yn" in [Yy]*) ;; *) exit 1 ;; esac
fi

echo "found ${#pkgs[@]} third-party package(s); pulling up to $LIMIT -> $DEST"
echo

count=0; split_count=0; skipped_big=0; unreadable=0

# Quote the expansion. Unquoted $pkgs word-splits on spaces, which is how one
# error line became eight fake package names.
for pkg in "${pkgs[@]}"; do
    [ "$count" -ge "$LIMIT" ] && break
    [ -z "$pkg" ] && continue

    out="$DEST/${pkg}.apk"
    if [ -f "$out" ]; then
        printf '  %-9s %s\n' "have" "$pkg"
        count=$((count + 1))
        continue
    fi

    mapfile -t paths < <(pm path "$pkg" 2>/dev/null \
        | grep '^package:' | sed 's/^package://' | tr -d '\r' | grep .)
    if [ "${#paths[@]}" -eq 0 ]; then
        printf '  %-9s %s\n' "nopath" "$pkg"
        unreadable=$((unreadable + 1))
        continue
    fi

    base=""
    for p in "${paths[@]}"; do
        case "$p" in */base.apk) base="$p"; break ;; esac
    done
    [ -z "$base" ] && base="${paths[0]}"
    [ "${#paths[@]}" -gt 1 ] && split_count=$((split_count + 1))

    if [ ! -r "$base" ]; then
        printf '  %-9s %s\n' "noread" "$pkg"
        unreadable=$((unreadable + 1))
        continue
    fi

    bytes=$(stat -c %s "$base" 2>/dev/null || echo 0)
    case "$bytes" in ''|*[!0-9]*) bytes=0 ;; esac
    mb=$(( bytes / 1048576 ))
    if [ "$mb" -gt "$MAX_MB" ]; then
        printf '  %-9s %s (%s MB)\n' "too big" "$pkg" "$mb"
        skipped_big=$((skipped_big + 1))
        continue
    fi

    if cp "$base" "$out" 2>/dev/null; then
        tag="single"; [ "${#paths[@]}" -gt 1 ] && tag="split:${#paths[@]}"
        printf '  %-9s %-44s %4s MB  %s\n' "pulled" "$pkg" "$mb" "$tag"
        count=$((count + 1))
    else
        printf '  %-9s %s\n' "FAILED" "$pkg"
        unreadable=$((unreadable + 1))
    fi
done

have=$(ls -1 "$DEST"/*.apk 2>/dev/null | wc -l)
echo
echo "corpus: $have APK(s) in $DEST"
echo "  $split_count from split bundles (base.apk only)"
echo "  $skipped_big skipped as >${MAX_MB} MB"
echo "  $unreadable unreadable"

if [ "$have" -eq 0 ]; then
    echo
    echo "Nothing was pulled." >&2
    print_fallbacks
    exit 1
fi

echo
echo "next:"
echo "  python3 \$HOME/nullscan/tools/harvest.py $DEST --out ${DEST}-results --jobs 1"
