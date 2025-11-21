#!/bin/bash

cd /home/vinay/pub/IR || exit 1

# Kill existing web server process if running
echo "Stopping existing Web Server instances..."
pkill -f "web/web_server.py"
sleep 1

# Ensure logs directory exists
mkdir -p logs

# Note: Log file preserved for historical troubleshooting
# Use log rotation instead of wiping logs on restart

# Start new web server instance in background
# Python logging handles all output - no need to redirect here
nohup env PYTHONPATH=/home/vinay/pub/IR .venv/bin/python web/web_server.py &

echo "Starting Web Server..."
echo ""

# Wait for the log file to appear and contain data
sleep 2

# Tail the log file until we see startup message or timeout after 30 seconds
timeout 30 tail -f logs/web_server.log 2>/dev/null | while read -r line; do
    echo "$line"
    # Look for Flask/Waitress startup message
    if echo "$line" | grep -qE "Serving on|Running on|Started"; then
        # Give it a few more seconds to finish initialization
        sleep 3
        pkill -P $$ tail  # Kill the tail process
        break
    fi
done

echo ""

# Check if the process is actually running
if pgrep -f "web/web_server.py" > /dev/null; then
    PID=$(pgrep -f 'web/web_server.py')
    echo "✅ Web Server is running (PID: $PID)"
    echo ""
    echo "To view logs: tail -f /home/vinay/pub/IR/logs/web_server.log"
else
    echo "❌ Warning: Web Server process not found"
    echo "Check logs: tail -20 /home/vinay/pub/IR/logs/web_server.log"
fi
