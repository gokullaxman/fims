#!/usr/bin/env bash
# Reproduction C: Filenames with tab/newline break baseline
# Bug: Unescaped tab/newline corrupts baseline format.
# Requirement: Create file "we\tird" and "a\nb"; init + scan must succeed with 0 alerts.
# Exit code: non-zero while bug exists, 0 once fixed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIMS_BIN="$REPO_ROOT/fims"

if [ ! -x "$FIMS_BIN" ]; then
    echo "[-] FIMS binary not found at $FIMS_BIN" >&2
    exit 1
fi

TEST_DIR="$(mktemp -d /tmp/fims_repro_C_XXXXXX)"
trap 'rm -rf "$TEST_DIR"' EXIT

mkdir -p "$TEST_DIR/mon"
printf "tab content" > "$TEST_DIR/mon/we"$'\t'"ird"
printf "newline content" > "$TEST_DIR/mon/a"$'\n'"b"

INIT_STATUS=0
"$FIMS_BIN" init "$TEST_DIR/mon" --force --yes --allow-unattended >/dev/null 2>&1 || INIT_STATUS=$?

if [ $INIT_STATUS -ne 0 ]; then
    echo "[-] Repro C FAIL (Bug Present): init failed on tab/newline filenames"
    exit 1
fi

SCAN_STATUS=0
SCAN_OUTPUT="$("$FIMS_BIN" scan 2>&1)" || SCAN_STATUS=$?

if [ $SCAN_STATUS -eq 0 ] && echo "$SCAN_OUTPUT" | grep -qi "0 changes detected"; then
    echo "[+] Repro C PASS: Baseline successfully handled tab and newline filenames with 0 alerts"
    exit 0
else
    echo "[-] Repro C FAIL (Bug Present): Baseline corrupted or scan failed"
    echo "$SCAN_OUTPUT"
    exit 1
fi
