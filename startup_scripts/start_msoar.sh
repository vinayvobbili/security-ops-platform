#!/bin/bash

cd /home/vinay/pub/IR || exit 1

# Kill existing msoar process if running
echo "Stopping existing MSOAR instances..."
source /home/vinay/pub/IR/deployment/kill_process.sh
kill_process_gracefully "webex_bots/msoar" "MSOAR" || exit 1
sleep 1

# Restart log viewer to ensure it shows latest logs
/home/vinay/pub/IR/deployment/restart_log_viewer.sh 8033 "MSOAR Bot" /home/vinay/pub/IR/logs/msoar.log

# Ensure logs directory exists
mkdir -p logs

# Note: Log file preserved for historical troubleshooting
# Use log rotation instead of wiping logs on restart

# Start new msoar instance in background
# Python logging handles all output - redirect nohup output to /dev/null
nohup env PYTHONPATH=/home/vinay/pub/IR .venv/bin/python webex_bots/msoar.py > /dev/null 2>&1 &

echo "Starting MSOAR bot..."
echo ""

# Wait for the log file to appear and contain data
sleep 2

# Tail the log file until we see device cleanup complete or timeout after 30 seconds
timeout 30 tail -f logs/msoar.log 2>/dev/null | while read -r line; do
    echo "$line"
    if echo "$line" | grep -q "Device cleanup complete"; then
        # Give it a few more seconds to finish initialization
        sleep 3
        pkill -P $$ tail  # Kill the tail process
        break
    fi
done

echo ""

# Check if the process is actually running
if pgrep -f "webex_bots/msoar" > /dev/null; then
    PID=$(pgrep -f 'webex_bots/msoar')
    echo "✅ MSOAR is running (PID: $PID)"
    echo ""
    echo "To view logs: tail -f /home/vinay/pub/IR/logs/msoar.log"
else
    echo "❌ Warning: MSOAR process not found"
    echo "Check logs: tail -20 /home/vinay/pub/IR/logs/msoar.log"
fi
