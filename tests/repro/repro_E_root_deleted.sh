#!/usr/bin/env bash
# Reproduction E: Monitored root directory deleted
# Bug: Scanner aborts with error code 1 when root is missing instead of treating it as empty.
# Requirement: Init, rm -rf root, scan; expect deleted alerts and exit 3.
# Exit code: non-zero while bug exists, 0 once fixed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIMS_BIN="$REPO_ROOT/fims"

if [ ! -x "$FIMS_BIN" ]; then
    echo "[-] FIMS binary not found at $FIMS_BIN" >&2
    exit 1
fi

TEST_DIR="$(mktemp -d /tmp/fims_repro_E_XXXXXX)"
trap 'rm -rf "$TEST_DIR"' EXIT

MON_DIR="$TEST_DIR/mon"
mkdir -p "$MON_DIR"
echo "file 1" > "$MON_DIR/alpha.txt"
echo "file 2" > "$MON_DIR/beta.txt"

"$FIMS_BIN" init "$MON_DIR" --force --yes --allow-unattended >/dev/null 2>&1 || "$FIMS_BIN" init "$MON_DIR" >/dev/null 2>&1

# Completely delete the monitored root directory
rm -rf "$MON_DIR"

SCAN_EXIT=0
SCAN_OUTPUT="$("$FIMS_BIN" scan 2>&1)" || SCAN_EXIT=$?

HAS_DELETED=$(echo "$SCAN_OUTPUT" | grep -i "FILE_DELETED" || true)

if [ $SCAN_EXIT -eq 3 ] && [ -n "$HAS_DELETED" ]; then
    echo "[+] Repro E PASS: Missing root treated as empty, emitted FILE_DELETED, exited 3"
    exit 0
else
    echo "[-] Repro E FAIL (Bug Present): Scan failed with exit $SCAN_EXIT or omitted FILE_DELETED alerts"
    echo "$SCAN_OUTPUT"
    exit 1
fi
