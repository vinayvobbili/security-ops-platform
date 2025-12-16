#!/bin/bash
# the security assistant bot ZScaler Monitor Management Script - the security assistant bot-specific only

# Get project directory (3 levels up from this script)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

PLIST_FILE="$HOME/Library/LaunchAgents/com.pokedex.zscaler.monitor.plist"
SERVICE_NAME="com.pokedex.zscaler.monitor"

show_status() {
    echo "🔍 the security assistant bot ZScaler Monitor Status:"
    if launchctl list | grep -q "$SERVICE_NAME"; then
        echo "✅ the security assistant bot ZScaler service is loaded"
        if pgrep -f "pokedex_zscaler_monitor.sh" > /dev/null; then
            echo "✅ the security assistant bot ZScaler monitor process is running"
        else
            echo "⚠️  the security assistant bot ZScaler service loaded but process not running"
        fi
    else
        echo "❌ the security assistant bot ZScaler service is not loaded"
    fi

    echo ""
    echo "🌙 MacBook Sleep Monitor Status:"
    if pgrep -f "macbook_sleep_monitor.py" > /dev/null; then
        echo "✅ MacBook Sleep Monitor is running"
        echo "PID: $(pgrep -f "macbook_sleep_monitor.py")"
    else
        echo "❌ MacBook Sleep Monitor is not running"
    fi

    echo ""
    echo "📊 Recent monitor activity:"
    echo "--- ZScaler Monitor ---"
    if [ -f "$PROJECT_DIR/logs/pokedex_zscaler_monitor.log" ]; then
        tail -n 3 "$PROJECT_DIR/logs/pokedex_zscaler_monitor.log"
    else
        echo "No ZScaler monitor log found"
    fi

    echo "--- Sleep Monitor ---"
    if [ -f "$PROJECT_DIR/logs/macbook_sleep_monitor.log" ]; then
        tail -n 3 "$PROJECT_DIR/logs/macbook_sleep_monitor.log"
    else
        echo "No sleep monitor log found"
    fi
}

start_sleep_monitor() {
    echo "🌙 Starting MacBook Sleep Monitor..."

    if pgrep -f "macbook_sleep_monitor.py" > /dev/null; then
        echo "⚠️  MacBook Sleep Monitor already running"
        return
    fi

    "$PROJECT_DIR/src/pokedex/start_sleep_monitor.sh"
    sleep 2
}

stop_sleep_monitor() {
    echo "🛑 Stopping MacBook Sleep Monitor..."

    pkill -f "macbook_sleep_monitor.py" 2>/dev/null
    rm -f "/tmp/pokedex_macbook_sleep_monitor.lock" 2>/dev/null

    sleep 1
}

start_monitor() {
    echo "🚀 Starting the security assistant bot ZScaler monitor..."

    # Load the service
    launchctl load "$PLIST_FILE" 2>/dev/null

    # Start the service
    launchctl start "$SERVICE_NAME"

    sleep 2

    # Also start sleep monitor for enhanced protection
    start_sleep_monitor

    show_status
}

stop_monitor() {
    echo "🛑 Stopping the security assistant bot ZScaler monitor..."

    # Stop the service
    launchctl stop "$SERVICE_NAME" 2>/dev/null

    # Unload the service
    launchctl unload "$PLIST_FILE" 2>/dev/null

    # Kill any remaining the security assistant bot monitor processes
    pkill -f "pokedex_zscaler_monitor.sh" 2>/dev/null

    # Also stop sleep monitor
    stop_sleep_monitor

    sleep 1
    show_status
}

restart_monitor() {
    echo "🔄 Restarting the security assistant bot ZScaler monitor..."
    stop_monitor
    sleep 2
    start_monitor
}

show_logs() {
    echo "📋 the security assistant bot ZScaler Monitor Logs:"
    echo "================================"
    if [ -f "$PROJECT_DIR/logs/pokedex_zscaler_monitor.log" ]; then
        tail -n 20 "$PROJECT_DIR/logs/pokedex_zscaler_monitor.log"
    else
        echo "No the security assistant bot ZScaler monitor log found"
    fi
}

case "$1" in
    start)
        start_monitor
        ;;
    stop)
        stop_monitor
        ;;
    restart)
        restart_monitor
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs
        ;;
    sleep-start)
        start_sleep_monitor
        ;;
    sleep-stop)
        stop_sleep_monitor
        ;;
    *)
        echo "the security assistant bot ZScaler Monitor Management"
        echo "=================================="
        echo "Usage: $0 {start|stop|restart|status|logs|sleep-start|sleep-stop}"
        echo ""
        echo "Commands:"
        echo "  start       - Start the the security assistant bot ZScaler monitor service + sleep monitor"
        echo "  stop        - Stop the the security assistant bot ZScaler monitor service + sleep monitor"
        echo "  restart     - Restart the the security assistant bot ZScaler monitor service + sleep monitor"
        echo "  status      - Show current monitor status"
        echo "  logs        - Show recent monitor logs"
        echo "  sleep-start - Start only the MacBook sleep monitor"
        echo "  sleep-stop  - Stop only the MacBook sleep monitor"
        echo ""
        show_status
        exit 1
        ;;
esac