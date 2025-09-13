#!/bin/bash
# Pokedex ZScaler Monitor Management Script - Pokedex-specific only

PLIST_FILE="/Users/user@company.com/Library/LaunchAgents/com.pokedex.zscaler.monitor.plist"
SERVICE_NAME="com.pokedex.zscaler.monitor"
PROJECT_DIR="/Users/user@company.com/PycharmProjects/IR"

show_status() {
    echo "🔍 Pokedex ZScaler Monitor Status:"
    if launchctl list | grep -q "$SERVICE_NAME"; then
        echo "✅ Pokedex ZScaler service is loaded"
        if pgrep -f "pokedex_zscaler_monitor.sh" > /dev/null; then
            echo "✅ Pokedex ZScaler monitor process is running"
        else
            echo "⚠️  Pokedex ZScaler service loaded but process not running"
        fi
    else
        echo "❌ Pokedex ZScaler service is not loaded"
    fi
    
    echo ""
    echo "📊 Recent Pokedex monitor activity:"
    if [ -f "$PROJECT_DIR/logs/pokedex_zscaler_monitor.log" ]; then
        tail -n 5 "$PROJECT_DIR/logs/pokedex_zscaler_monitor.log"
    else
        echo "No Pokedex ZScaler monitor log found"
    fi
}

start_monitor() {
    echo "🚀 Starting Pokedex ZScaler monitor..."
    
    # Load the service
    launchctl load "$PLIST_FILE" 2>/dev/null
    
    # Start the service
    launchctl start "$SERVICE_NAME"
    
    sleep 2
    show_status
}

stop_monitor() {
    echo "🛑 Stopping Pokedex ZScaler monitor..."
    
    # Stop the service
    launchctl stop "$SERVICE_NAME" 2>/dev/null
    
    # Unload the service
    launchctl unload "$PLIST_FILE" 2>/dev/null
    
    # Kill any remaining Pokedex monitor processes
    pkill -f "pokedex_zscaler_monitor.sh" 2>/dev/null
    
    sleep 1
    show_status
}

restart_monitor() {
    echo "🔄 Restarting Pokedex ZScaler monitor..."
    stop_monitor
    sleep 2
    start_monitor
}

show_logs() {
    echo "📋 Pokedex ZScaler Monitor Logs:"
    echo "================================"
    if [ -f "$PROJECT_DIR/logs/pokedex_zscaler_monitor.log" ]; then
        tail -n 20 "$PROJECT_DIR/logs/pokedex_zscaler_monitor.log"
    else
        echo "No Pokedex ZScaler monitor log found"
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
        echo "Pokedex ZScaler Monitor Management"
        echo "=================================="
        echo "Usage: $0 {start|stop|restart|status|logs}"
        echo ""
        echo "Commands:"
        echo "  start   - Start the Pokedex ZScaler monitor service"
        echo "  stop    - Stop the Pokedex ZScaler monitor service"
        echo "  restart - Restart the Pokedex ZScaler monitor service"
        echo "  status  - Show current Pokedex ZScaler monitor status"
        echo "  logs    - Show recent Pokedex ZScaler monitor logs"
        echo ""
        show_status
        exit 1
        ;;
esac