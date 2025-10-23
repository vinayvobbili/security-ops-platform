#!/bin/bash

# Disable job control messages to prevent "Killed" messages from interfering with output
set +m

cd /home/vinay/pub/IR || exit 1

# Kill existing server process if running
echo "Stopping existing web server instances..."
if pgrep -f "web_server.py" > /dev/null; then
    echo "Found existing process(es). Sending SIGTERM..."
    sudo pkill -f "web_server.py" >/dev/null 2>&1 || true

    # Wait up to 10 seconds for graceful shutdown
    for _ in {1..10}; do
        if ! pgrep -f "web_server.py" > /dev/null; then
            echo "Process stopped gracefully."
            break
        fi
        sleep 1
    done

    # Force kill if still running using per-PID kill to avoid bash 'Killed' status output
    if pgrep -f "web_server.py" > /dev/null; then
        echo "Process still running. Sending SIGKILL..."
        PIDS=$(pgrep -f "web_server.py")
        for PID in $PIDS; do
            # Double-check PID is numeric
            if [[ $PID =~ ^[0-9]+$ ]]; then
                sudo kill -9 "$PID" 2>/dev/null || true
            fi
        done
        sleep 2
        if pgrep -f "web_server.py" >/dev/null; then
            echo "⚠️  Warning: Some processes may still be present"
        else
            echo "Process terminated"
        fi
    fi
fi

# Verify no processes are running
if pgrep -f "web_server.py" > /dev/null; then
    echo ""
    echo "❌ ERROR: Failed to stop existing web_server.py processes"
    exit 1
fi

echo ""
echo "Checking for processes on proxy port 8080..."
PROXY_PORT_PIDS=$(lsof -ti:8080 2>/dev/null)
if [ -n "$PROXY_PORT_PIDS" ]; then
    echo "Found process(es) on port 8080: $PROXY_PORT_PIDS"
    echo "Killing stale proxy port processes..."
    echo "$PROXY_PORT_PIDS" | xargs kill -9 2>/dev/null
    sleep 1

    # Verify port is clear
    if lsof -ti:8080 > /dev/null 2>&1; then
        echo "⚠️  WARNING: Port 8080 may still be in use - continuing anyway"
    else
        echo "✅ Port 8080 cleared successfully"
    fi
else
    echo "✅ Port 8080 is clear"
fi

echo ""

# Clear the log file to ensure we see fresh output
: > web_server.log

echo "Starting Web Server..."
echo ""

# Start new server instance using sudo with NOPASSWD rule (required for port 80)
# This matches the sudoers whitelist exactly
# Redirect stderr/stdout to log file, suppressing nohup messages
# Note: Redirect happens as user (not root) which is intentional - log file is user-owned
# shellcheck disable=SC2024
sudo /usr/bin/nohup /usr/bin/env PYTHONPATH=/home/vinay/pub/IR /home/vinay/pub/IR/.venv/bin/python /home/vinay/pub/IR/web/web_server.py >> /home/vinay/pub/IR/web_server.log 2>&1 &

# Give the background process a moment to start
sleep 3

# Show initial startup log output (quick peek)
echo "Initial startup messages:"
echo "------------------------"
timeout 5 tail -10 web_server.log 2>/dev/null || echo "(no log output yet)"
echo "------------------------"
echo ""

# Get the actual Python process PID (not the sudo PID)
PYTHON_PID=$(pgrep -f "python.*web_server.py" | tail -1)

if [ -n "$PYTHON_PID" ]; then
    echo "✅ Web Server is running (PID: $PYTHON_PID)"
    echo ""
    echo "📋 To view logs: tail -f /home/vinay/pub/IR/web_server.log"
else
    echo "❌ Warning: Could not determine server PID"
    echo "📋 Check logs: tail -20 /home/vinay/pub/IR/web_server.log"
fi

echo ""
