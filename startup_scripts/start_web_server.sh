#!/bin/bash

cd /home/vinay/pub/IR || exit 1

SERVICE_NAME="ir-web-server.service"
APP_NAME="Web Server"
LOG_FILE="/home/vinay/pub/IR/logs/web_server.log"

echo "Managing $APP_NAME via systemd service: $SERVICE_NAME"
echo ""

# Stop the systemd service if it's running or in a stuck state
SERVICE_STATE=$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo "inactive")

if [[ "$SERVICE_STATE" != "inactive" ]]; then
    echo "Stopping $SERVICE_NAME (current state: $SERVICE_STATE)..."

    # Reset failed state first if needed
    if systemctl is-failed --quiet "$SERVICE_NAME" 2>/dev/null; then
        echo "  Resetting failed state..."
        sudo systemctl reset-failed "$SERVICE_NAME"
    fi

    sudo systemctl stop "$SERVICE_NAME"

    # Wait up to 30 seconds for graceful stop
    for i in {1..30}; do
        if ! systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
            break
        fi
        if [ $i -eq 15 ]; then
            echo "  ⏳ Service taking longer than expected to stop..."
        fi
        sleep 1
    done

    # If still running/stuck, force kill
    CURRENT_STATE=$(systemctl show -p ActiveState --value "$SERVICE_NAME" 2>/dev/null)
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null || \
       [[ "$CURRENT_STATE" == "deactivating" ]] || \
       [[ "$CURRENT_STATE" == "activating" ]]; then
        echo "  ⚠️  Graceful stop failed, force killing..."
        sudo systemctl kill --signal=SIGKILL "$SERVICE_NAME"
        sleep 2
        sudo systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true
    fi

    echo "✅ $SERVICE_NAME stopped"
else
    echo "ℹ️  $SERVICE_NAME is not currently running"
    # Still reset failed state just in case
    sudo systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true
fi

# Also kill any stray processes (in case they're not managed by systemd)
echo "Checking for stray web_server.py processes..."
WEB_PIDS=$(pgrep -f "web_server.py")
if [ -n "$WEB_PIDS" ]; then
    echo "Found stray processes: $WEB_PIDS - cleaning up..."
    echo "$WEB_PIDS" | xargs kill -9 2>/dev/null || true
    sleep 1
fi

# Force kill any process using ports 8080 and 8081
PROXY_PORT=8081
WEB_PORT=8080
echo "Checking ports $WEB_PORT and $PROXY_PORT..."

PROXY_PID=$(lsof -ti:$PROXY_PORT 2>/dev/null)
if [ -n "$PROXY_PID" ]; then
    echo "  Killing process using port $PROXY_PORT (PID: $PROXY_PID)"
    kill -9 "$PROXY_PID" 2>/dev/null || true
    sleep 1
fi

WEB_PID=$(lsof -ti:$WEB_PORT 2>/dev/null)
if [ -n "$WEB_PID" ]; then
    echo "  Killing process using port $WEB_PORT (PID: $WEB_PID)"
    kill -9 "$WEB_PID" 2>/dev/null || true
    sleep 1
fi

# Ensure logs directory exists
mkdir -p logs

# Start the systemd service
echo ""
echo "Starting $SERVICE_NAME..."
sudo systemctl start "$SERVICE_NAME"

# Wait for service to start
sleep 2

# Tail the log file until we see startup message or timeout after 30 seconds
echo "Waiting for $APP_NAME to initialize..."
timeout 30 tail -f "$LOG_FILE" 2>/dev/null | while read -r line; do
    echo "$line"
    # Look for Flask/Waitress startup message
    if echo "$line" | grep -qE "Serving on|Running on|Started"; then
        # Give it a moment to finish initialization
        sleep 2
        pkill -P $$ tail  # Kill the tail process
        break
    fi
done

echo ""

# Check if the service is running
if systemctl is-active --quiet "$SERVICE_NAME"; then
    PID=$(systemctl show -p MainPID --value "$SERVICE_NAME")
    echo "✅ $APP_NAME is running via systemd (PID: $PID)"
    echo ""
    echo "To view logs: tail -f $LOG_FILE"
    echo "   or: journalctl -u $SERVICE_NAME -f"
    echo ""
    echo "To manage: sudo systemctl {start|stop|restart|status} $SERVICE_NAME"
else
    echo "❌ Warning: $SERVICE_NAME failed to start"
    echo "Check status: systemctl status $SERVICE_NAME"
    echo "Check logs: journalctl -u $SERVICE_NAME -n 50"
    exit 1
fi
