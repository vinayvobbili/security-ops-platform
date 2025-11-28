#!/bin/bash

cd /home/vinay/pub/IR || exit 1

# Rotate nohup.out to avoid confusion with old logs
if [ -f nohup.out ]; then
    TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
    mv nohup.out "nohup.out.$TIMESTAMP"
    echo "Rotated old nohup.out to nohup.out.$TIMESTAMP"

    # Keep only the last 5 rotated nohup files
    find . -maxdepth 1 -name "nohup.out.*" -type f -printf '%T@ %p\n' 2>/dev/null | \
        sort -rn | tail -n +6 | cut -d' ' -f2- | xargs rm -f 2>/dev/null || true
fi

# Kill existing barnacles process if running
echo "Stopping existing Barnacles instances..."
pkill -f "webex_bots/barnacles"
sleep 1

# Ensure logs directory exists
mkdir -p logs

# Note: Log file preserved for historical troubleshooting
# Use log rotation instead of wiping logs on restart

# Start new barnacles instance in background
# Python logging handles all output - no need to redirect here
nohup env PYTHONPATH=/home/vinay/pub/IR .venv/bin/python webex_bots/barnacles.py &

echo "Starting Barnacles bot..."
echo ""

# Wait for the log file to appear and contain data
sleep 2

# Tail the log file until we see device cleanup complete or timeout after 30 seconds
timeout 30 tail -f logs/barnacles.log 2>/dev/null | while read -r line; do
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
if pgrep -f "webex_bots/barnacles" > /dev/null; then
    PID=$(pgrep -f 'webex_bots/barnacles')
    echo "✅ Barnacles is running (PID: $PID)"
    echo ""
    echo "To view logs: tail -f /home/vinay/pub/IR/logs/barnacles.log"
else
    echo "❌ Warning: Barnacles process not found"
    echo "Check logs: tail -20 /home/vinay/pub/IR/logs/barnacles.log"
fi
