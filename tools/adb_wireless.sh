#!/data/data/com.termux/files/usr/bin/bash
# tools/adb_wireless.sh — pair Termux's adb with this same device, interactively.
#
# WHY THIS EXISTS
#   Documentation for this normally looks like:
#       adb pair 127.0.0.1:<PAIRING_PORT>
#   Pasted into zsh, `<PAIRING_PORT>` is an input redirection from a file that
#   does not exist, and you get "parse error near \n'". The placeholder itself
#   is the bug. This script asks for the numbers instead, so nothing with an
#   angle bracket ever reaches your shell.
#
#   bash $HOME/nullscan/tools/adb_wireless.sh

set -uo pipefail

HOST=127.0.0.1

echo
echo "══════════════════════════════════════════════════════════════"
echo " Pair Termux adb with this phone"
echo "══════════════════════════════════════════════════════════════"
echo
echo " Android gives you TWO DIFFERENT PORTS. Mixing them up is the"
echo " single most common failure here."
echo
echo "   PAIRING port + 6-digit code"
echo "     appear together in the popup after you tap"
echo "     'Pair device with pairing code'"
echo
echo "   CONNECT port"
echo "     shown on the main Wireless debugging screen, under the"
echo "     IP address. A different number. Changes on every toggle."
echo

if ! command -v adb >/dev/null 2>&1; then
    echo "adb not installed. Run this first, then re-run me:"
    echo
    echo "  pkg install android-tools"
    echo
    exit 1
fi

cat <<'STEPS'
Do this now, then come back:

  1. Settings -> Developer options -> Wireless debugging -> ON
  2. Tap "Pair device with pairing code"
  3. Leave that popup OPEN

STEPS

printf "PAIRING port (the number in the popup, e.g. 41234): "
read -r pair_port
printf "6-digit pairing CODE (e.g. 668417): "
read -r pair_code

case "$pair_port" in ''|*[!0-9]*)
    echo "  '$pair_port' is not a number. Ports are 5 digits." >&2; exit 1 ;;
esac
case "$pair_code" in ''|*[!0-9]*)
    echo "  '$pair_code' is not a number. The code is 6 digits." >&2; exit 1 ;;
esac
if [ "${#pair_code}" -ne 6 ]; then
    echo
    echo "  Heads up: '$pair_code' is ${#pair_code} digits, not 6."
    echo "  If you swapped the port and the code, ctrl-C and start over."
    echo
fi

echo
echo "  adb pair $HOST:$pair_port"
adb pair "$HOST:$pair_port" "$pair_code" || {
    echo
    echo "Pairing failed. Usual causes:" >&2
    echo "  - the popup closed (its port dies with it — reopen for a fresh one)" >&2
    echo "  - the port and the code got swapped" >&2
    echo "  - Wireless debugging was toggled off and on (all ports change)" >&2
    exit 1
}

echo
echo "Paired. Now close the popup and look at the main"
echo "Wireless debugging screen for the CONNECT port."
echo
printf "CONNECT port (under 'IP address & Port'): "
read -r conn_port
case "$conn_port" in ''|*[!0-9]*)
    echo "  '$conn_port' is not a number." >&2; exit 1 ;;
esac
if [ "$conn_port" = "$pair_port" ]; then
    echo
    echo "  That's the same as the pairing port. They're almost never equal —" >&2
    echo "  double-check you read the main screen, not the popup." >&2
    echo
fi

echo
echo "  adb connect $HOST:$conn_port"
adb connect "$HOST:$conn_port"

echo
if adb devices | awk 'NR>1 && $2=="device"{f=1} END{exit !f}'; then
    echo "══════════════════════════════════════════════════════════════"
    adb devices
    echo "══════════════════════════════════════════════════════════════"
    echo
    echo "Connected. Next:"
    echo
    echo "  bash \$HOME/nullscan/tools/pull_corpus.sh \$HOME/apk-corpus 40"
    echo
    printf "Run that now? [Y/n] "
    read -r yn
    case "${yn:-y}" in
        [Yy]*|"") exec bash "$(dirname "$0")/pull_corpus.sh" "$HOME/apk-corpus" 40 ;;
    esac
else
    echo "adb still shows no authorised device:" >&2
    adb devices >&2
    echo >&2
    echo "Toggle Wireless debugging off and on, then re-run this script." >&2
    echo "Both ports change every time it's toggled." >&2
    exit 1
fi
