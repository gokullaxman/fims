#!/usr/bin/env bash
# Reproduction H: Chown/chgrp + chmod hides uid/gid change
# Bug: In integrity checker, FIMS_FLAG_PERMISSION_CHANGED suppresses EVENT_METADATA_CHANGED.
# Requirement: uid/gid change must always report METADATA_CHANGED.
# Exit code: non-zero while bug exists, 0 once fixed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIMS_BIN="$REPO_ROOT/fims"

if [ ! -x "$FIMS_BIN" ]; then
    echo "[-] FIMS binary not found at $FIMS_BIN" >&2
    exit 1
fi

TEST_DIR="$(mktemp -d /tmp/fims_repro_H_XXXXXX)"
trap 'rm -rf "$TEST_DIR"' EXIT

mkdir -p "$TEST_DIR/mon"
echo "data" > "$TEST_DIR/mon/target.txt"
chmod 0644 "$TEST_DIR/mon/target.txt"

CURR_GID=$(id -g)
SEC_GID=$(id -G | tr ' ' '\n' | grep -v "^${CURR_GID}$" | head -n 1 || true)
if [ -z "$SEC_GID" ]; then
    echo "[*] Skip: User belongs to only one group, secondary GID not available"
    exit 0
fi

"$FIMS_BIN" init "$TEST_DIR/mon" --force --yes --allow-unattended >/dev/null 2>&1 || "$FIMS_BIN" init "$TEST_DIR/mon" >/dev/null 2>&1

# Apply BOTH chgrp (metadata) and chmod (permissions)
chgrp "$SEC_GID" "$TEST_DIR/mon/target.txt"
chmod 0755 "$TEST_DIR/mon/target.txt"

SCAN_OUTPUT="$("$FIMS_BIN" scan 2>&1 || true)"
HAS_META=$(echo "$SCAN_OUTPUT" | grep -i "METADATA_CHANGED" || true)

if [ -n "$HAS_META" ]; then
    echo "[+] Repro H PASS: METADATA_CHANGED reported even when permissions also changed"
    exit 0
else
    echo "[-] Repro H FAIL (Bug Present): METADATA_CHANGED was swallowed by PERMISSION_CHANGED"
    echo "$SCAN_OUTPUT"
    exit 1
fi
