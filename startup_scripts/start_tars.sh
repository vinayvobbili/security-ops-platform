#!/bin/bash

# Get the directory where this script is actually located (follow symlinks)
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"

# Go to parent directory (IR root)
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR" || exit 1

# Kill existing TARS process if running
echo "Stopping existing TARS instances..."
source "$PROJECT_DIR/deployment/kill_process.sh"
kill_process_gracefully "webex_bots/tars" "TARS" || exit 1
sleep 1

# Restart log viewer to ensure it shows latest logs
"$PROJECT_DIR/deployment/restart_log_viewer.sh" 8038 "TARS Bot" "$PROJECT_DIR/logs/tars.log"

# Ensure logs directory exists
mkdir -p logs

# Note: Log file preserved for historical troubleshooting
# Use log rotation instead of wiping logs on restart

# Start new TARS instance in background
# Python logging handles all output - redirect nohup output to /dev/null
nohup env PYTHONPATH="$PROJECT_DIR" .venv/bin/python webex_bots/tars.py > /dev/null 2>&1 &

echo "Starting TARS bot..."
echo ""

# Wait for the log file to appear and contain data
sleep 2

# Tail the log file until we see device cleanup complete or timeout after 30 seconds
timeout 30 tail -f logs/tars.log 2>/dev/null | while read -r line; do
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
if pgrep -f "webex_bots/tars" > /dev/null; then
    PID=$(pgrep -f 'webex_bots/tars')
    echo "✅ TARS is running (PID: $PID)"
    echo ""
    echo "To view logs: tail -f $PROJECT_DIR/logs/tars.log"
else
    echo "❌ Warning: TARS process not found"
    echo "Check logs: tail -20 $PROJECT_DIR/logs/tars.log"
fi
