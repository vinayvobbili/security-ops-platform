#!/bin/bash

# Kill existing server process if running
echo "Checking for existing web_server.py processes..."
if pgrep -f "web_server.py" > /dev/null; then
    echo "Found existing process(es). Sending SIGTERM..."
    pkill -f "web_server.py"

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
        pkill -9 -f "web_server.py"
        sleep 1
    fi
fi

# Verify no processes are running
if pgrep -f "web_server.py" > /dev/null; then
    echo "ERROR: Failed to stop existing web_server.py processes"
    exit 1
fi

echo "Starting new server instance..."
# Start new server instance with sudo to bind to port 80
# Note: Redirect happens in user shell (not sudo) - this is intentional to keep log user-owned
# shellcheck disable=SC2024
sudo nohup env PYTHONPATH=/home/vinay/pub/IR .venv/bin/python web/web_server.py >> web_server.log 2>&1 &

echo "Server started with PID $!"
