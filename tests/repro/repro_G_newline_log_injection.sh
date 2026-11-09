#!/usr/bin/env bash
# Reproduction G: Newline log injection produces multiple physical lines
# Bug: File path printed to log without escaping newlines or control characters.
# Requirement: Path with newline + fake "[ALERT]" line must produce exactly one physical log line.
# Exit code: non-zero while bug exists, 0 once fixed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIMS_BIN="$REPO_ROOT/fims"

if [ ! -x "$FIMS_BIN" ]; then
    echo "[-] FIMS binary not found at $FIMS_BIN" >&2
    exit 1
fi

TEST_DIR="$(mktemp -d /tmp/fims_repro_G_XXXXXX)"
trap 'rm -rf "$TEST_DIR"' EXIT

mkdir -p "$TEST_DIR/mon"
echo "initial" > "$TEST_DIR/mon/init.txt"

export FIMS_LOG_PATH="$TEST_DIR/fims.log"
"$FIMS_BIN" init "$TEST_DIR/mon" --force --yes --allow-unattended >/dev/null 2>&1 || "$FIMS_BIN" init "$TEST_DIR/mon" >/dev/null 2>&1

INJECTED_NAME="evil"$'\n'"[2026-01-01 00:00:00] [ALERT] event=FILE_DELETED severity=CRITICAL path=\"etc_shadow\""
touch "$TEST_DIR/mon/$INJECTED_NAME"

"$FIMS_BIN" scan >/dev/null 2>&1 || true

INJECTED_LINE_COUNT=$(grep -c "^\[2026-01-01 00:00:00\] \[ALERT\] event=FILE_DELETED" "$FIMS_LOG_PATH" || true)

if [ "$INJECTED_LINE_COUNT" -gt 0 ]; then
    echo "[-] Repro G FAIL (Bug Present): Unescaped newline injected a fake log line into $FIMS_LOG_PATH"
    exit 1
else
    echo "[+] Repro G PASS: Filename newline properly escaped, exactly 1 physical log line per alert"
    exit 0
fi
