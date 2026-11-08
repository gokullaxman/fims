#!/usr/bin/env bash
set -e

DEMO_DIR="/tmp/fims_demo_run/test"
rm -rf /tmp/fims_demo_run data/*.dat data/*.conf logs/*.log

echo "=== Step 1 & 2: Creating test directory ($DEMO_DIR) and sample files ==="
mkdir -p "$DEMO_DIR"
echo "Initial sample text content" > "$DEMO_DIR/sample.txt"
echo "Legacy data to be removed" > "$DEMO_DIR/old.txt"
echo "port=8080" > "$DEMO_DIR/config.txt"
chmod 0644 "$DEMO_DIR/sample.txt" "$DEMO_DIR/old.txt" "$DEMO_DIR/config.txt"

echo ""
echo "=== Step 3: Initializing baseline ==="
./fims init "$DEMO_DIR"
./fims baseline show

echo ""
echo "=== Step 4-7: Modifying sample.txt, deleting old.txt, adding new.txt, chmod 0777 config.txt ==="
echo "Unauthorized modification to sample.txt!" >> "$DEMO_DIR/sample.txt"
rm -f "$DEMO_DIR/old.txt"
echo "Newly dropped payload file" > "$DEMO_DIR/new.txt"
chmod 0777 "$DEMO_DIR/config.txt"

echo ""
echo "=== Step 8: Running integrity scan ==="
./fims scan

echo ""
echo "=== Step 9: Displaying report and status ==="
./fims report
./fims status

echo ""
echo "=== Step 10: Real-time inotify monitoring (3 seconds) ==="
./fims monitor --duration 3 &
MON_PID=$!
sleep 1
echo "Real-time modification captured by Linux inotify!" >> "$DEMO_DIR/sample.txt"
wait $MON_PID

echo ""
echo "=== Audit Log (logs/fims.log) ==="
cat logs/fims.log
rm -rf /tmp/fims_demo_run
