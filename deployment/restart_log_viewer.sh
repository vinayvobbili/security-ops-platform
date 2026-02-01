#!/bin/bash
# Restart a specific log viewer by port number
# Usage: restart_log_viewer.sh <port> <title> <log_file>

PORT=$1
TITLE=$2
LOG_FILE=$3

if [ -z "$PORT" ] || [ -z "$TITLE" ] || [ -z "$LOG_FILE" ]; then
    echo "Usage: $0 <port> <title> <log_file>"
    exit 1
fi

PROJECT_DIR="/home/user/pub/IR"
cd "$PROJECT_DIR" || exit 1

# Load environment variables from .env
if [ -f .env ]; then
    set -a
    source .env
    set +a
fi

# Kill existing log viewer on this port
pkill -f "log_viewer.py.*--port $PORT" 2>/dev/null
sleep 0.5

# Start new log viewer
nohup .venv/bin/python deployment/log_viewer.py \
    --port "$PORT" \
    --title "$TITLE" \
    --file "$LOG_FILE" \
    > /dev/null 2>&1 &

# Verify it started
sleep 1
if pgrep -f "log_viewer.py.*--port $PORT" > /dev/null; then
    echo "✅ Log viewer for $TITLE restarted on port $PORT"
else
    echo "❌ Failed to start log viewer for $TITLE on port $PORT"
    exit 1
fi
