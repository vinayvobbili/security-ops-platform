#!/bin/bash

# Get the project directory (parent of the directory containing this script)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR" || exit 1

# Kill existing pokedex process if running
echo "Stopping existing the security assistant bot instances..."
source "$SCRIPT_DIR/../deployment/kill_process.sh"
kill_process_gracefully "webex_bots/pokedex" "the security assistant bot" || exit 1
sleep 1

# Note: Log file preserved for historical troubleshooting
# Use log rotation instead of wiping logs on restart

# Start new pokedex instance in background
# Python logging handles all output - redirect nohup output to /dev/null
nohup env PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/.venv/bin/python" webex_bots/pokedex.py > /dev/null 2>&1 &

echo "Starting the security assistant bot bot..."
echo ""

# Wait for the log file to appear and contain data
sleep 2

# Tail the log file until we see device cleanup complete or timeout after 30 seconds
timeout 30 tail -f pokedex.log 2>/dev/null | while read -r line; do
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
if pgrep -f "webex_bots/pokedex" > /dev/null; then
    PID=$(pgrep -f 'webex_bots/pokedex')
    echo "✅ the security assistant bot is running (PID: $PID)"
    echo ""
    echo "To view logs: tail -f $PROJECT_DIR/pokedex.log"
else
    echo "❌ Warning: the security assistant bot process not found"
    echo "Check logs: tail -20 $PROJECT_DIR/pokedex.log"
fi
