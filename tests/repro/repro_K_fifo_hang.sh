#!/usr/bin/env bash
# Reproduction K: FIFO swapped in hangs the hasher
# Bug: open() without O_NONBLOCK in fims_hash_file_sha256 blocks indefinitely on FIFO.
# Requirement: FIFO in place of file must return error within 1 second without hanging.
# Exit code: non-zero while bug exists, 0 once fixed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIMS_BIN="$REPO_ROOT/fims"

if [ ! -x "$FIMS_BIN" ]; then
    echo "[-] FIMS binary not found at $FIMS_BIN" >&2
    exit 1
fi

TEST_DIR="$(mktemp -d /tmp/fims_repro_K_XXXXXX)"
trap 'rm -rf "$TEST_DIR"' EXIT

mkdir -p "$TEST_DIR/mon"
echo "initial regular file" > "$TEST_DIR/mon/target.txt"

"$FIMS_BIN" init "$TEST_DIR/mon" --force --yes --allow-unattended >/dev/null 2>&1 || "$FIMS_BIN" init "$TEST_DIR/mon" >/dev/null 2>&1

# Replace file with FIFO
rm -f "$TEST_DIR/mon/target.txt"
mkfifo "$TEST_DIR/mon/target.txt"

SCAN_STATUS=0
timeout 1s "$FIMS_BIN" scan >/dev/null 2>&1 || SCAN_STATUS=$?

if [ $SCAN_STATUS -eq 124 ]; then
    echo "[-] Repro K FAIL (Bug Present): fims scan hung on FIFO and timed out after 1s"
    exit 1
else
    echo "[+] Repro K PASS: fims scan returned without hanging on FIFO"
    exit 0
fi
