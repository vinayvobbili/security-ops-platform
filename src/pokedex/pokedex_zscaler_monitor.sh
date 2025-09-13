#!/bin/bash
# the security assistant bot ZScaler Monitor - MacBook sleep/wake resilience for the security assistant bot bot only
# Monitors for ZScaler connection kills and automatically restarts the security assistant bot

PROJECT_DIR="/Users/<redacted-email>/PycharmProjects/IR"
LOG_FILE="$PROJECT_DIR/logs/pokedex.log"
RESTART_SCRIPT="$PROJECT_DIR/src/pokedex/restart_pokedex.sh"
MONITOR_LOG="$PROJECT_DIR/logs/pokedex_zscaler_monitor.log"
LOCK_FILE="/tmp/pokedex_zscaler_monitor.lock"

# Configuration
CHECK_INTERVAL=30  # Check every 30 seconds
MAX_RESTARTS_PER_HOUR=6
RESTART_COOLDOWN=60  # Wait 60 seconds between restarts

# State tracking
LAST_RESTART_TIME=0
RESTART_COUNT_FILE="/tmp/pokedex_restart_count"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$MONITOR_LOG"
}

# Check if already running
if [ -f "$LOCK_FILE" ]; then
    log_message "the security assistant bot ZScaler monitor already running, exiting"
    exit 0
fi

# Create lock file and setup cleanup
touch "$LOCK_FILE"
trap 'rm -f "$LOCK_FILE"; exit' EXIT INT TERM

log_message "🛡️ Starting the security assistant bot ZScaler monitor..."

# Initialize restart counter
if [ ! -f "$RESTART_COUNT_FILE" ]; then
    echo "0:$(date +%s)" > "$RESTART_COUNT_FILE"
fi

is_pokedex_running() {
    pgrep -f "pokedex.py" > /dev/null
}

should_restart() {
    local current_time=$(date +%s)
    local count_data=$(cat "$RESTART_COUNT_FILE" 2>/dev/null || echo "0:$current_time")
    local restart_count=$(echo "$count_data" | cut -d: -f1)
    local first_restart_time=$(echo "$count_data" | cut -d: -f2)
    
    # Reset counter if more than an hour has passed
    if [ $((current_time - first_restart_time)) -gt 3600 ]; then
        echo "0:$current_time" > "$RESTART_COUNT_FILE"
        restart_count=0
    fi
    
    # Check rate limit
    if [ "$restart_count" -ge "$MAX_RESTARTS_PER_HOUR" ]; then
        log_message "⚠️ the security assistant bot restart rate limit exceeded ($restart_count/$MAX_RESTARTS_PER_HOUR per hour)"
        return 1
    fi
    
    # Check cooldown period
    if [ $((current_time - LAST_RESTART_TIME)) -lt "$RESTART_COOLDOWN" ]; then
        log_message "⏳ the security assistant bot restart cooldown active ($(($RESTART_COOLDOWN - (current_time - LAST_RESTART_TIME)))s remaining)"
        return 1
    fi
    
    return 0
}

restart_pokedex() {
    if ! should_restart; then
        return 1
    fi
    
    log_message "🔄 Restarting the security assistant bot due to ZScaler connection issue..."
    
    # Update restart tracking
    local current_time=$(date +%s)
    local count_data=$(cat "$RESTART_COUNT_FILE" 2>/dev/null || echo "0:$current_time")
    local restart_count=$(echo "$count_data" | cut -d: -f1)
    local first_restart_time=$(echo "$count_data" | cut -d: -f2)
    
    # If this is the first restart in the current hour window
    if [ "$restart_count" -eq 0 ]; then
        first_restart_time=$current_time
    fi
    
    restart_count=$((restart_count + 1))
    echo "$restart_count:$first_restart_time" > "$RESTART_COUNT_FILE"
    LAST_RESTART_TIME=$current_time
    
    # Execute restart
    if [ -x "$RESTART_SCRIPT" ]; then
        "$RESTART_SCRIPT" 2>&1 | while IFS= read -r line; do
            log_message "RESTART: $line"
        done
    else
        log_message "❌ the security assistant bot restart script not found or not executable: $RESTART_SCRIPT"
        return 1
    fi
    
    # Verify restart succeeded
    sleep 10
    if is_pokedex_running; then
        log_message "✅ the security assistant bot successfully restarted (restart #$restart_count this hour)"
        return 0
    else
        log_message "❌ the security assistant bot restart failed"
        return 1
    fi
}

check_pokedex_zscaler_issues() {
    # Check if the security assistant bot is running
    if ! is_pokedex_running; then
        log_message "📴 the security assistant bot not running, attempting to start..."
        restart_pokedex
        return
    fi
    
    # Check for ZScaler connection issues in recent the security assistant bot logs
    if [ -f "$LOG_FILE" ]; then
        # Look for connection issues in the last 2 minutes
        local recent_time=$(date -v-2M '+%Y-%m-%d %H:%M' 2>/dev/null || date -d '2 minutes ago' '+%Y-%m-%d %H:%M')
        
        # ZScaler-specific connection errors affecting the security assistant bot
        local zscaler_errors=$(tail -n 200 "$LOG_FILE" | grep -E "(Connection reset by peer|ConnectionClosedError|Connection aborted|no close frame received|WebSocket.*failed)" | grep -c "$recent_time\|$(date '+%Y-%m-%d %H:%M')")
        
        if [ "$zscaler_errors" -gt 0 ]; then
            log_message "🚨 Detected $zscaler_errors ZScaler connection issues in recent the security assistant bot logs"
            restart_pokedex
            return
        fi
        
        # Check for WebSocket disconnections without immediate reconnection
        local websocket_disconnects=$(tail -n 100 "$LOG_FILE" | grep -c "WebSocket.*closed\|connection.*lost\|Backing off.*websocket" | head -1)
        local websocket_reconnects=$(tail -n 50 "$LOG_FILE" | grep -c "WebSocket Opened\|connection.*established" | head -1)
        
        if [ "$websocket_disconnects" -gt 0 ] && [ "$websocket_reconnects" -eq 0 ]; then
            log_message "🔗 the security assistant bot WebSocket disconnected without reconnection detected"
            restart_pokedex
            return
        fi
    fi
    
    log_message "✅ the security assistant bot appears healthy (WebSocket connected)"
}

# Main monitoring loop
log_message "🔍 the security assistant bot ZScaler monitor started - checking every ${CHECK_INTERVAL}s for ZScaler issues"

while true; do
    check_pokedex_zscaler_issues
    sleep "$CHECK_INTERVAL"
done