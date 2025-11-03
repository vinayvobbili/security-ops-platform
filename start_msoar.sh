#!/bin/bash

cd /home/vinay/pub/IR || exit 1

# Kill existing msoar process if running
echo "Stopping existing MSOAR instances..."
pkill -f "webex_bots/msoar"
sleep 2

# Force kill any remaining processes
if pgrep -f "webex_bots/msoar" > /dev/null; then
    echo "Force killing stubborn processes..."
    pkill -9 -f "webex_bots/msoar"
    sleep 1
fi

# Verify all processes are gone
if pgrep -f "webex_bots/msoar" > /dev/null; then
    echo "⚠️  Warning: Some MSOAR processes are still running:"
    pgrep -f "webex_bots/msoar"
    echo "Manual intervention required"
    exit 1
fi

# Ensure logs directory exists
mkdir -p logs

# Clear the log file to ensure we see fresh output
: > logs/msoar.log

# Start new msoar instance in background
# Python logging handles all output - no need to redirect here
nohup env PYTHONPATH=/home/vinay/pub/IR .venv/bin/python webex_bots/msoar.py &

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
    echo "To view logs: tail -f /home/vinay/pub/IR/logs/msoar.log"
else
    echo "❌ Warning: MSOAR process not found"
    echo "Check logs: tail -20 /home/vinay/pub/IR/logs/msoar.log"
fi
