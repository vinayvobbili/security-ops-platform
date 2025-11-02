#!/bin/bash

# Get the directory where this script is actually located (follow symlinks)
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"

cd "$SCRIPT_DIR" || exit 1

# Kill existing jarvais process if running
echo "Stopping existing Jarvais instances..."
pkill -f "webex_bots/jarvais.py"
sleep 1

# Ensure logs directory exists
mkdir -p logs

# Clear the log file to ensure we see fresh output
: > logs/jarvais.log

# Start new jarvais instance in background
# Python logging handles all output - no need to redirect here
nohup env PYTHONPATH="$SCRIPT_DIR" .venv/bin/python webex_bots/jarvais.py &

echo "Starting Jarvais bot..."
echo ""

# Wait for the log file to appear and contain data
sleep 2

# Tail the log file until we see device cleanup complete or timeout after 30 seconds
timeout 30 tail -f logs/jarvais.log 2>/dev/null | while read -r line; do
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
if pgrep -f "webex_bots/jarvais.py" > /dev/null; then
    PID=$(pgrep -f 'webex_bots/jarvais.py')
    echo "✅ Jarvais is running (PID: $PID)"
    echo ""
    echo "To view logs: tail -f $SCRIPT_DIR/logs/jarvais.log"
else
    echo "❌ Warning: Jarvais process not found"
    echo "Check logs: tail -20 $SCRIPT_DIR/logs/jarvais.log"
fi
