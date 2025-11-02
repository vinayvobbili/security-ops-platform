#!/bin/bash

cd /Users/user/PycharmProjects/IR || exit 1

# Kill existing msoar process if running
echo "Stopping existing MSOAR instances..."
pkill -f "webex_bots/msoar.py"
sleep 1

# Ensure logs directory exists
mkdir -p logs

# Clear the log file to ensure we see fresh output
: > logs/msoar.log

# Start new msoar instance in background
# Python logging handles all output - no need to redirect here
nohup env PYTHONPATH=/Users/user/PycharmProjects/IR .venv/bin/python webex_bots/msoar.py >> logs/msoar.log 2>&1 &

echo "Starting MSOAR bot..."
echo ""

# Wait for the log file to appear and contain data
sleep 2

# Tail the log file until we see the listening message or timeout after 30 seconds
timeout 30 tail -f logs/msoar.log 2>/dev/null | while read -r line; do
    echo "$line"
    if echo "$line" | grep -q "Bot is now listening for messages"; then
        # Give it a few more seconds to finish initialization
        sleep 2
        pkill -P $$ tail  # Kill the tail process
        break
    fi
done

echo ""

# Check if the process is actually running
if pgrep -f "webex_bots/msoar.py" > /dev/null; then
    PID=$(pgrep -f 'webex_bots/msoar.py')
    echo "✅ MSOAR is running (PID: $PID)"
    echo ""
    echo "To view logs: tail -f /Users/user/PycharmProjects/IR/logs/msoar.log"
else
    echo "❌ Warning: MSOAR process not found"
    echo "Check logs: tail -20 /Users/user/PycharmProjects/IR/logs/msoar.log"
fi
