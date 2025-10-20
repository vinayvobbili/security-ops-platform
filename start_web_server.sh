#!/bin/bash

# Kill existing server process if running
echo "Checking for existing web_server.py processes..."
if pgrep -f "web_server.py" > /dev/null; then
    echo "Found existing process(es). Sending SIGTERM..."
    sudo pkill -f "web_server.py"

    # Wait up to 10 seconds for graceful shutdown
    for _ in {1..10}; do
        if ! pgrep -f "web_server.py" > /dev/null; then
            echo "Process stopped gracefully."
            break
        fi
        sleep 1
    done

    # Force kill if still running
    if pgrep -f "web_server.py" > /dev/null; then
        echo "Process still running. Sending SIGKILL..."
        sudo pkill -9 -f "web_server.py"
        sleep 1
    fi
fi

# Verify no processes are running
if pgrep -f "web_server.py" > /dev/null; then
    echo "ERROR: Failed to stop existing web_server.py processes"
    exit 1
fi

echo "Starting new server instance..."

# Start new server instance
# Port 8080 doesn't require sudo, but keeping it for consistency
# Using absolute paths that match sudoers configuration exactly
# Note: Redirect happens in user shell (not sudo) - this is intentional to keep log user-owned
# shellcheck disable=SC2024
sudo /usr/bin/nohup /usr/bin/env PYTHONPATH=/home/vinay/pub/IR /home/vinay/pub/IR/.venv/bin/python /home/vinay/pub/IR/web/web_server.py >> /home/vinay/pub/IR/web_server.log 2>&1 &

# Give the background process a moment to start
sleep 2

# Get the actual Python process PID (not the sudo PID)
PYTHON_PID=$(pgrep -f "python.*web_server.py" | tail -1)

if [ -n "$PYTHON_PID" ]; then
    echo "Server started with PID $PYTHON_PID"
else
    echo "Warning: Could not determine server PID - check web_server.log for errors"
fi

# Print final newline to ensure prompt appears on new line
echo ""
