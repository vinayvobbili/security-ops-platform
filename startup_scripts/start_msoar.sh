#!/bin/bash

cd /home/vinay/pub/IR || exit 1

SERVICE_NAME="ir-msoar.service"
BOT_NAME="MSOAR"
LOG_FILE="/home/vinay/pub/IR/logs/msoar.log"
LOG_VIEWER_PORT=8033

echo "Managing $BOT_NAME via systemd service: $SERVICE_NAME"
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

# Restart log viewer to ensure it shows latest logs
/home/vinay/pub/IR/deployment/restart_log_viewer.sh $LOG_VIEWER_PORT "$BOT_NAME Bot" "$LOG_FILE"

# Start the systemd service
echo ""
echo "Starting $SERVICE_NAME..."
sudo systemctl start "$SERVICE_NAME"

# Wait for service to start
sleep 2

# Tail the log file until we see device cleanup complete or timeout after 30 seconds
echo "Waiting for $BOT_NAME to initialize..."
timeout 30 tail -f "$LOG_FILE" 2>/dev/null | while read -r line; do
    echo "$line"
    if echo "$line" | grep -q "Device cleanup complete\|is up and running"; then
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
    echo "✅ $BOT_NAME is running via systemd (PID: $PID)"
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
