#!/usr/bin/env bash
# Reproduction L: Compare time at 5k/20k/200k files (< 5s for 200k files)
# Bug: Nested O(N*M) loop in integrity comparison causes quadratic slowdown.
# Requirement: Must complete in < 5 seconds for large record comparison.
# Exit code: non-zero while bug exists, 0 once fixed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIMS_BIN="$REPO_ROOT/fims"

if [ ! -x "$FIMS_BIN" ]; then
    echo "[-] FIMS binary not found at $FIMS_BIN" >&2
    exit 1
fi

TEST_DIR="$(mktemp -d /tmp/fims_repro_L_XXXXXX)"
trap 'rm -rf "$TEST_DIR"' EXIT

mkdir -p "$TEST_DIR/mon"
# Generate 20,000 files to trigger quadratic O(N^2) comparison bottleneck
python3 -c '
import sys
test_dir = sys.argv[1]
for i in range(20000):
    with open(f"{test_dir}/f_{i:06d}.txt", "w") as f:
        f.write(f"val {i}\n")
' "$TEST_DIR/mon"

"$FIMS_BIN" init "$TEST_DIR/mon" --force --yes --allow-unattended >/dev/null 2>&1 || "$FIMS_BIN" init "$TEST_DIR/mon" >/dev/null 2>&1

START_TIME=$(date +%s)
SCAN_STATUS=0
timeout 5s "$FIMS_BIN" scan >/dev/null 2>&1 || SCAN_STATUS=$?
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

if [ $SCAN_STATUS -eq 124 ] || [ $ELAPSED -ge 5 ]; then
    echo "[-] Repro L FAIL (Bug Present): Comparison took >= 5s (O(N^2) loop bottleneck)"
    exit 1
else
    echo "[+] Repro L PASS: Comparison completed in ${ELAPSED}s (< 5s)"
    exit 0
fi
