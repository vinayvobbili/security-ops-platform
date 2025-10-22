#!/bin/bash

cd /Users/user/PycharmProjects/IR || exit 1

# Kill existing barnacles process if running
echo "Stopping existing Barnacles instances..."
pkill -f "webex_bots/barnacles.py"
sleep 1

# Clear the log file to ensure we see fresh output
: > barnacles.log

# Start new barnacles instance in background
nohup env PYTHONPATH=/Users/user/PycharmProjects/IR .venv/bin/python webex_bots/barnacles.py >> barnacles.log 2>&1 &

echo "Starting Barnacles bot..."
echo ""

# Wait for the log file to appear and contain data
sleep 2

# Tail the log file until we see device cleanup complete or timeout after 30 seconds
timeout 30 tail -f barnacles.log 2>/dev/null | while read -r line; do
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
if pgrep -f "webex_bots/barnacles.py" > /dev/null; then
    PID=$(pgrep -f 'webex_bots/barnacles.py')
    echo "✅ Barnacles is running (PID: $PID)"
    echo ""
    echo "To view logs: tail -f /Users/user/PycharmProjects/IR/barnacles.log"
else
    echo "❌ Warning: Barnacles process not found"
    echo "Check logs: tail -20 /Users/user/PycharmProjects/IR/barnacles.log"
fi
