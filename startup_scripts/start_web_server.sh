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

# Kill ALL existing web server processes if running
echo "Stopping ALL existing Web Server instances..."

# Find all web_server.py processes
WEB_PIDS=$(pgrep -f "web_server.py")

if [ -n "$WEB_PIDS" ]; then
    echo "Found web_server.py processes: $WEB_PIDS"

    # Force kill ALL of them immediately (don't wait for graceful shutdown)
    echo "$WEB_PIDS" | xargs kill -9 2>/dev/null || true

    # Wait and verify they're all dead
    sleep 2

    # Double-check and kill any stragglers
    REMAINING=$(pgrep -f "web_server.py")
    if [ -n "$REMAINING" ]; then
        echo "Killing remaining processes: $REMAINING"
        echo "$REMAINING" | xargs kill -9 2>/dev/null || true
        sleep 1
    fi
else
    echo "No existing web_server.py processes found"
fi

# Force kill any process using ports 8080 and 8081
PROXY_PORT=8081
WEB_PORT=8080

echo "Force killing any processes on ports $WEB_PORT and $PROXY_PORT..."

# Kill anything on proxy port 8081 - multiple attempts to be sure
for attempt in 1 2 3; do
    PROXY_PID=$(lsof -ti:$PROXY_PORT 2>/dev/null)
    if [ -n "$PROXY_PID" ]; then
        echo "  Killing PID $PROXY_PID using port $PROXY_PORT (attempt $attempt)"
        kill -9 "$PROXY_PID" 2>/dev/null || true
        sleep 1
    else
        break
    fi
done

# Kill anything on web server port 8080
for attempt in 1 2 3; do
    WEB_PID=$(lsof -ti:$WEB_PORT 2>/dev/null)
    if [ -n "$WEB_PID" ]; then
        echo "  Killing PID $WEB_PID using port $WEB_PORT (attempt $attempt)"
        kill -9 "$WEB_PID" 2>/dev/null || true
        sleep 1
    else
        break
    fi
done

# Give processes time to fully die and sockets to be released
echo "Waiting for sockets to be fully released..."
sleep 3

# Final verification
if lsof -i:$PROXY_PORT > /dev/null 2>&1; then
    echo "WARNING: Port $PROXY_PORT still in use after cleanup!"
    lsof -i:$PROXY_PORT
fi
if lsof -i:$WEB_PORT > /dev/null 2>&1; then
    echo "WARNING: Port $WEB_PORT still in use after cleanup!"
    lsof -i:$WEB_PORT
fi

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
