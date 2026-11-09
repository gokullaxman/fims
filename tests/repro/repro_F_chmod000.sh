#!/usr/bin/env bash
# Reproduction F: Unreadable chmod 000 file reported as UNREADABLE or PERMISSION_CHANGED, never FILE_DELETED
# Bug: EACCES during scan causes file to be omitted from scan results and reported as FILE_DELETED.
# Requirement: Non-root chmod 000 file reported as EVENT_UNREADABLE or PERMISSION_CHANGED, NEVER as FILE_DELETED.
# Exit code: non-zero while bug exists, 0 once fixed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIMS_BIN="$REPO_ROOT/fims"

if [ ! -x "$FIMS_BIN" ]; then
    echo "[-] FIMS binary not found at $FIMS_BIN" >&2
    exit 1
fi

if [ "$(id -u)" -eq 0 ]; then
    echo "[*] Skip: Running as root bypasses chmod 000 EACCES restrictions"
    exit 0
fi

TEST_DIR="$(mktemp -d /tmp/fims_repro_F_XXXXXX)"
trap 'chmod -R 700 "$TEST_DIR" 2>/dev/null || true; rm -rf "$TEST_DIR"' EXIT

mkdir -p "$TEST_DIR/mon"
echo "confidential" > "$TEST_DIR/mon/secret.txt"

"$FIMS_BIN" init "$TEST_DIR/mon" --force --yes --allow-unattended >/dev/null 2>&1 || "$FIMS_BIN" init "$TEST_DIR/mon" >/dev/null 2>&1

chmod 000 "$TEST_DIR/mon/secret.txt"

SCAN_OUTPUT="$("$FIMS_BIN" scan 2>&1 || true)"

if echo "$SCAN_OUTPUT" | grep -qi "FILE_DELETED"; then
    echo "[-] Repro F FAIL (Bug Present): chmod 000 unreadable file was erroneously reported as FILE_DELETED"
    echo "$SCAN_OUTPUT"
    exit 1
fi

if echo "$SCAN_OUTPUT" | grep -Eqi "(UNREADABLE|PERMISSION_CHANGED)"; then
    echo "[+] Repro F PASS: Unreadable file correctly reported as UNREADABLE or PERMISSION_CHANGED"
    exit 0
else
    echo "[-] Repro F FAIL: Expected UNREADABLE or PERMISSION_CHANGED alert"
    echo "$SCAN_OUTPUT"
    exit 1
fi
