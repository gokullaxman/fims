#!/usr/bin/env bash
# Reproduction B: .git evasion hole
# Bug: Basename matching on ".git" in fims_config_is_excluded excludes any file/dir named .git in subtrees.
# Requirement: Add mon/.git/payload and mon/x/.git after init; scan must report both as FILE_ADDED.
# Exit code: non-zero while bug exists, 0 once fixed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIMS_BIN="$REPO_ROOT/fims"

if [ ! -x "$FIMS_BIN" ]; then
    echo "[-] FIMS binary not found at $FIMS_BIN" >&2
    exit 1
fi

TEST_DIR="$(mktemp -d /tmp/fims_repro_B_XXXXXX)"
trap 'rm -rf "$TEST_DIR"' EXIT

mkdir -p "$TEST_DIR/mon/x"
echo "initial file" > "$TEST_DIR/mon/init.txt"

"$FIMS_BIN" init "$TEST_DIR/mon" --force --yes --allow-unattended >/dev/null 2>&1 || "$FIMS_BIN" init "$TEST_DIR/mon" >/dev/null 2>&1

mkdir -p "$TEST_DIR/mon/.git"
echo "payload data 1" > "$TEST_DIR/mon/.git/payload"
echo "payload data 2" > "$TEST_DIR/mon/x/.git"

SCAN_OUTPUT="$("$FIMS_BIN" scan 2>&1 || true)"

HAS_PAYLOAD1=$(echo "$SCAN_OUTPUT" | grep -E "FILE_ADDED.*(\.git/payload)" || true)
HAS_PAYLOAD2=$(echo "$SCAN_OUTPUT" | grep -E "FILE_ADDED.*(x/\.git)" || true)

if [ -n "$HAS_PAYLOAD1" ] && [ -n "$HAS_PAYLOAD2" ]; then
    echo "[+] Repro B PASS: Both .git evasion files detected as FILE_ADDED"
    exit 0
else
    echo "[-] Repro B FAIL (Bug Present): .git evasion files were silently excluded"
    echo "$SCAN_OUTPUT"
    exit 1
fi
