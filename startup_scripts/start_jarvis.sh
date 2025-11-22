#!/bin/bash

# Get the directory where this script is actually located (follow symlinks)
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT" || exit 1

# Kill existing jarvis process if running
echo "Stopping existing Jarvis instances..."
pkill -f "webex_bots/jarvis"
sleep 1

# Ensure logs directory exists
mkdir -p logs

# Note: Log file preserved for historical troubleshooting
# Use log rotation instead of wiping logs on restart

# Start new jarvis instance in background
# Python logging handles all output - no need to redirect here
nohup env PYTHONPATH="$PROJECT_ROOT" .venv/bin/python webex_bots/jarvis.py &

echo "Starting Jarvis bot..."
echo ""

# Wait for the log file to appear and contain data
sleep 2

# Tail the log file until we see device cleanup complete or timeout after 30 seconds
timeout 30 tail -f logs/jarvis.log 2>/dev/null | while read -r line; do
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
if pgrep -f "webex_bots/jarvis" > /dev/null; then
    PID=$(pgrep -f 'webex_bots/jarvis')
    echo "✅ Jarvis is running (PID: $PID)"
    echo ""
    echo "To view logs: tail -f $PROJECT_ROOT/logs/jarvis.log"
else
    echo "❌ Warning: Jarvis process not found"
    echo "Check logs: tail -20 $PROJECT_ROOT/logs/jarvis.log"
fi
