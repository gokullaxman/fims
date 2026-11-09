#!/usr/bin/env bash
# Reproduction D: Scan exit code with detected changes
# Bug: fims scan exits 0 instead of 3 when integrity changes are detected.
# Requirement: Must exit 3 on detected changes (0 on clean, 2 on corrupt, 1 on error).
# Exit code: non-zero while bug exists, 0 once fixed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIMS_BIN="$REPO_ROOT/fims"

if [ ! -x "$FIMS_BIN" ]; then
    echo "[-] FIMS binary not found at $FIMS_BIN" >&2
    exit 1
fi

TEST_DIR="$(mktemp -d /tmp/fims_repro_D_XXXXXX)"
trap 'rm -rf "$TEST_DIR"' EXIT

mkdir -p "$TEST_DIR/mon"
echo "clean baseline content" > "$TEST_DIR/mon/target.txt"

"$FIMS_BIN" init "$TEST_DIR/mon" --force --yes --allow-unattended >/dev/null 2>&1 || "$FIMS_BIN" init "$TEST_DIR/mon" >/dev/null 2>&1

CLEAN_EXIT=0
"$FIMS_BIN" scan >/dev/null 2>&1 || CLEAN_EXIT=$?
if [ $CLEAN_EXIT -ne 0 ]; then
    echo "[-] Repro D FAIL: Clean scan did not return 0 (got $CLEAN_EXIT)"
    exit 1
fi

# Modify file to trigger changes
echo "tampered content" >> "$TEST_DIR/mon/target.txt"

CHANGE_EXIT=0
"$FIMS_BIN" scan >/dev/null 2>&1 || CHANGE_EXIT=$?

if [ $CHANGE_EXIT -eq 3 ]; then
    echo "[+] Repro D PASS: fims scan returned exit code 3 on detected changes"
    exit 0
else
    echo "[-] Repro D FAIL (Bug Present): fims scan returned exit code $CHANGE_EXIT (expected 3)"
    exit 1
fi
