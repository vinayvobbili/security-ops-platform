#!/bin/bash
# the security assistant bot ZScaler Monitor Management Script - the security assistant bot-specific only

PLIST_FILE="/Users/<redacted-email>/Library/LaunchAgents/com.pokedex.zscaler.monitor.plist"
SERVICE_NAME="com.pokedex.zscaler.monitor"
PROJECT_DIR="/Users/<redacted-email>/PycharmProjects/IR"

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
    echo "📊 Recent the security assistant bot monitor activity:"
    if [ -f "$PROJECT_DIR/logs/pokedex_zscaler_monitor.log" ]; then
        tail -n 5 "$PROJECT_DIR/logs/pokedex_zscaler_monitor.log"
    else
        echo "No the security assistant bot ZScaler monitor log found"
    fi
}

start_monitor() {
    echo "🚀 Starting the security assistant bot ZScaler monitor..."
    
    # Load the service
    launchctl load "$PLIST_FILE" 2>/dev/null
    
    # Start the service
    launchctl start "$SERVICE_NAME"
    
    sleep 2
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
    *)
        echo "the security assistant bot ZScaler Monitor Management"
        echo "=================================="
        echo "Usage: $0 {start|stop|restart|status|logs}"
        echo ""
        echo "Commands:"
        echo "  start   - Start the the security assistant bot ZScaler monitor service"
        echo "  stop    - Stop the the security assistant bot ZScaler monitor service"
        echo "  restart - Restart the the security assistant bot ZScaler monitor service"
        echo "  status  - Show current the security assistant bot ZScaler monitor status"
        echo "  logs    - Show recent the security assistant bot ZScaler monitor logs"
        echo ""
        show_status
        exit 1
        ;;
esac