#!/usr/bin/env bash
set -e

DEMO_ROOT="/tmp/fims_demo_run"
DEMO_DIR="$DEMO_ROOT/test"
DATA_DIR="$DEMO_ROOT/data"
LOGS_DIR="$DEMO_ROOT/logs"

rm -rf "$DEMO_ROOT"
mkdir -p "$DEMO_DIR" "$DATA_DIR" "$LOGS_DIR"

export FIMS_BASELINE_PATH="$DATA_DIR/baseline.dat"
export FIMS_LOG_PATH="$LOGS_DIR/fims.log"
export FIMS_REPORT_PATH="$DATA_DIR/report.dat"
export FIMS_STATE_PATH="$DATA_DIR/status.dat"
export FIMS_CONFIG_PATH="$DATA_DIR/fims.conf"

echo "============================================================"
echo " FIMS End-to-End System Demonstration"
echo "============================================================"

echo ""
echo "=== Step 1: Creating sample monitored environment ==="
echo "Initial sample text content" > "$DEMO_DIR/sample.txt"
echo "Legacy data to be removed" > "$DEMO_DIR/old.txt"
echo "port=8080" > "$DEMO_DIR/config.txt"
chmod 0644 "$DEMO_DIR/sample.txt" "$DEMO_DIR/old.txt" "$DEMO_DIR/config.txt"

echo ""
echo "=== Step 2: Creating HMAC Authentication Key ==="
HMAC_KEY_FILE="$DATA_DIR/hmac.key"
openssl rand -hex 32 > "$HMAC_KEY_FILE"
chmod 0600 "$HMAC_KEY_FILE"
export FIMS_HMAC_KEY_FILE="$HMAC_KEY_FILE"
echo "[OK] Generated 256-bit HMAC key at $HMAC_KEY_FILE (mode 0600)"

echo ""
echo "=== Step 3: Initializing Trusted Baseline (HMAC-SHA256 authenticated) ==="
./fims init "$DEMO_DIR"
./fims baseline show

echo ""
echo "=== Step 4: Clean Scan (Expect exit code 0) ==="
./fims scan
echo "[OK] Clean scan exited 0"

echo ""
echo "=== Step 5: Introducing filesystem modifications ==="
echo "Unauthorized modification to sample.txt!" >> "$DEMO_DIR/sample.txt"
rm -f "$DEMO_DIR/old.txt"
echo "Newly dropped payload file" > "$DEMO_DIR/new.txt"
chmod 0777 "$DEMO_DIR/config.txt"

echo ""
echo "=== Step 6: Integrity Scan detecting violations (Expect exit code 3) ==="
set +e
./fims scan
SCAN_RC=$?
set -e
if [ "$SCAN_RC" -eq 3 ]; then
    echo "[OK] Changes detected: fims scan returned exit code 3 as expected"
else
    echo "[ERROR] Expected exit code 3, got $SCAN_RC" >&2
    exit 1
fi

echo ""
echo "=== Step 7: Displaying Integrity Report & System Status ==="
./fims report
./fims status

echo ""
echo "=== Step 8: Updating Trusted Baseline (Unattended mode) ==="
./fims baseline update --yes --allow-unattended
echo "[OK] Baseline updated cleanly"

echo ""
echo "=== Step 9: Demonstrating Baseline Tamper Detection (Expect exit code 2) ==="
echo "TAMPERED_APPENDED_LINE" >> "$FIMS_BASELINE_PATH"
set +e
./fims scan
TAMPER_RC=$?
set -e
if [ "$TAMPER_RC" -eq 2 ]; then
    echo "[OK] Tampered baseline rejected: fims scan returned exit code 2"
else
    echo "[ERROR] Expected exit code 2 on tampered baseline, got $TAMPER_RC" >&2
    exit 1
fi

# Restore baseline by re-initializing for monitor test
./fims init "$DEMO_DIR" --force --yes --allow-unattended

echo ""
echo "=== Step 10: Real-time inotify monitoring (3 seconds) ==="
./fims monitor --duration 3 &
MON_PID=$!
sleep 1
echo "Real-time modification captured by Linux inotify!" >> "$DEMO_DIR/sample.txt"
wait $MON_PID

echo ""
echo "=== Step 11: Audit Log ($FIMS_LOG_PATH) ==="
cat "$FIMS_LOG_PATH"

rm -rf "$DEMO_ROOT"
echo ""
echo "============================================================"
echo " FIMS DEMONSTRATION COMPLETED SUCCESSFULLY"
echo "============================================================"
