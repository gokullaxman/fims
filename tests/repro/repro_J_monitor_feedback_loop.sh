#!/usr/bin/env bash
# Reproduction J: Monitor feedback loop with data/logs inside tree
# Bug: inotify IN_MODIFY + logging to internal files triggers feedback loop of continuous events.
# Requirement: 5s run with data/logs inside tree and 1 file write produces exactly 1 FILE_MODIFIED alert, 0 false alerts on data/logs.
# Exit code: non-zero while bug exists, 0 once fixed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIMS_BIN="$REPO_ROOT/fims"

if [ ! -x "$FIMS_BIN" ]; then
    echo "[-] FIMS binary not found at $FIMS_BIN" >&2
    exit 1
fi

TEST_DIR="$(mktemp -d /tmp/fims_repro_J_XXXXXX)"
trap 'rm -rf "$TEST_DIR"' EXIT

mkdir -p "$TEST_DIR/mon/data" "$TEST_DIR/mon/logs"
echo "version 1" > "$TEST_DIR/mon/monitored.txt"

cd "$TEST_DIR/mon"
"$FIMS_BIN" init "$TEST_DIR/mon" --force --yes --allow-unattended >/dev/null 2>&1 || "$FIMS_BIN" init "$TEST_DIR/mon" >/dev/null 2>&1

"$FIMS_BIN" monitor --duration 5 > "$TEST_DIR/mon_output.log" 2>&1 &
MON_PID=$!

sleep 1
# Perform exactly one write
echo "version 2" > "$TEST_DIR/mon/monitored.txt"

wait "$MON_PID" || true

ALERTS=$(grep "\[ALERT\]" "$TEST_DIR/mon_output.log" || true)
MOD_COUNT=$(echo "$ALERTS" | grep -c "FILE_MODIFIED:.*monitored\.txt" || true)
FALSE_DATA_LOGS=$(echo "$ALERTS" | grep -E "(data/|logs/)" || true)

if [ "$MOD_COUNT" -eq 1 ] && [ -z "$FALSE_DATA_LOGS" ]; then
    echo "[+] Repro J PASS: Exactly 1 FILE_MODIFIED alert and 0 false alerts on internal data/logs"
    exit 0
else
    echo "[-] Repro J FAIL (Bug Present): Feedback loop or false alerts on internal files"
    echo "$ALERTS"
    exit 1
fi
