#!/usr/bin/env bash
# Reproduction A: Default excludes vs absolute paths
# Bug: Default exclusions are relative ("data/baseline.dat", "logs/fims.log"),
# but scanner traverses absolute paths. Scanning immediately after init reports false alerts.
# Exit code: non-zero while bug exists, 0 once fixed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIMS_BIN="$REPO_ROOT/fims"

if [ ! -x "$FIMS_BIN" ]; then
    echo "[-] FIMS binary not found at $FIMS_BIN" >&2
    exit 1
fi

TEST_DIR="$(mktemp -d /tmp/fims_repro_A_XXXXXX)"
trap 'rm -rf "$TEST_DIR"' EXIT

mkdir -p "$TEST_DIR/data" "$TEST_DIR/logs"
echo "sample file content" > "$TEST_DIR/sample.txt"

cd "$TEST_DIR"
"$FIMS_BIN" init "$TEST_DIR" --force --yes --allow-unattended >/dev/null 2>&1 || "$FIMS_BIN" init "$TEST_DIR" >/dev/null 2>&1

SCAN_OUTPUT="$("$FIMS_BIN" scan 2>&1 || true)"
SCAN_EXIT=0
"$FIMS_BIN" scan >/dev/null 2>&1 || SCAN_EXIT=$?

if [ $SCAN_EXIT -eq 0 ] && echo "$SCAN_OUTPUT" | grep -qi "0 changes detected"; then
    echo "[+] Repro A PASS: 0 alerts on immediate scan with data/ and logs/"
    exit 0
else
    echo "[-] Repro A FAIL (Bug Present): False alerts detected on internal data/ or logs/"
    echo "$SCAN_OUTPUT"
    exit 1
fi
