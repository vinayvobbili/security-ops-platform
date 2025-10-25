#!/bin/bash

cd /home/vinay/pub/IR || exit 1

# Kill existing money_ball process if running
echo "Stopping existing Money Ball instances..."
pkill -f "webex_bots/money_ball.py"
sleep 1

# Ensure logs directory exists
mkdir -p logs

# Clear the log file to ensure we see fresh output
: > logs/money_ball.log

# Start new money_ball instance in background
# Python logging handles all output - no need to redirect here
nohup env PYTHONPATH=/home/vinay/pub/IR .venv/bin/python webex_bots/money_ball.py &

echo "Starting Money Ball bot..."
echo ""

# Wait for the log file to appear and contain data
sleep 2

# Tail the log file until we see device cleanup complete or timeout after 30 seconds
timeout 30 tail -f logs/money_ball.log 2>/dev/null | while read -r line; do
    echo "$line"
    if echo "$line" | grep -q "Device cleanup complete"; then
        # Give it a few more seconds to finish initialization
        sleep 3
        pkill -P $$ tail  # Kill the tail process.
        break
    fi
done

echo ""

# Check if the process is actually running
if pgrep -f "webex_bots/money_ball.py" > /dev/null; then
    PID=$(pgrep -f 'webex_bots/money_ball.py')
    echo "✅ Money Ball is running (PID: $PID)"
    echo ""
    echo "To view logs: tail -f /home/vinay/pub/IR/logs/money_ball.log"
else
    echo "❌ Warning: Money Ball process not found"
    echo "Check logs: tail -20 /home/vinay/pub/IR/logs/money_ball.log"
fi
