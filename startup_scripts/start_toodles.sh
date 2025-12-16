#!/bin/bash

cd /home/vinay/pub/IR || exit 1

# Kill existing toodles process if running
echo "Stopping existing Toodles instances..."
source /home/vinay/pub/IR/deployment/kill_process.sh
kill_process_gracefully "webex_bots/toodles" "Toodles" || exit 1
sleep 1

# Restart log viewer to ensure it shows latest logs
/home/vinay/pub/IR/deployment/restart_log_viewer.sh 8032 "Toodles Bot" /home/vinay/pub/IR/logs/toodles.log

# Ensure logs directory exists
mkdir -p logs

# Note: Log file preserved for historical troubleshooting
# Use log rotation instead of wiping logs on restart

# Start new toodles instance in background
# Python logging handles all output - redirect nohup output to /dev/null
nohup env PYTHONPATH=/home/vinay/pub/IR .venv/bin/python webex_bots/toodles.py > /dev/null 2>&1 &

echo "Starting Toodles bot..."
echo ""

# Wait for the log file to appear and contain data
sleep 2

# Tail the log file until we see device cleanup complete or timeout after 30 seconds
timeout 30 tail -f logs/toodles.log 2>/dev/null | while read -r line; do
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
if pgrep -f "webex_bots/toodles" > /dev/null; then
    PID=$(pgrep -f 'webex_bots/toodles')
    echo "✅ Toodles is running (PID: $PID)"
    echo ""
    echo "To view logs: tail -f /home/vinay/pub/IR/logs/toodles.log"
else
    echo "❌ Warning: Toodles process not found"
    echo "Check logs: tail -20 /home/vinay/pub/IR/logs/toodles.log"
fi
