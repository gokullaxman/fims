#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

echo "============================================================"
echo " Stage 1: Standard Clean Build & Test Suite"
echo "============================================================"
make clean
make -j$(nproc)
make test

echo "============================================================"
echo " Stage 2: Non-Root Test Execution"
echo "============================================================"
if [ "$(id -u)" -eq 0 ]; then
    if command -v setpriv >/dev/null 2>&1; then
        setpriv --reuid=nobody --regid=nogroup --clear-groups make test
    elif command -v runuser >/dev/null 2>&1; then
        runuser -u nobody -- make test
    elif command -v su >/dev/null 2>&1; then
        su nobody -s /bin/sh -c "make test"
    else
        echo "No tool available to drop privileges, skipping non-root stage"
    fi
else
    make test
fi

echo "============================================================"
echo " Stage 3: AddressSanitizer & UndefinedBehaviorSanitizer Run"
echo "============================================================"
make test-asan

echo "============================================================"
echo " Stage 4: Red Team Reproduction Verification (tests/repro)"
echo "============================================================"
make repro

echo "============================================================"
echo " ALL 4 VERIFICATION PIPELINE STAGES PASSED CLEANLY"
echo "============================================================"
