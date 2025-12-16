#!/bin/bash
# Universal ZScaler Bot Monitor - Configurable for any bot
# Currently configured for Pokedex, easily extendible to other bots

# Bot Configuration - MODIFY THESE FOR OTHER BOTS
BOT_NAME="pokedex"                    # Bot identifier (pokedex, hal9000, etc.)
BOT_PROCESS_NAME="pokedex.py"         # Process name to monitor
BOT_LOG_FILE="pokedex.log"            # Log file name
BOT_RESTART_SCRIPT="restart_pokedex.sh"  # Restart script name
BOT_DISPLAY_NAME="Pokedex"            # Display name for logs

# Derived paths - these auto-adjust based on bot name
# Get project directory (3 levels up from this script)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOG_FILE="$PROJECT_DIR/logs/$BOT_LOG_FILE"
RESTART_SCRIPT="$PROJECT_DIR/src/$BOT_NAME/$BOT_RESTART_SCRIPT"
MONITOR_LOG="$PROJECT_DIR/logs/${BOT_NAME}_zscaler_monitor.log"
LOCK_FILE="/tmp/${BOT_NAME}_zscaler_monitor.lock"
RESTART_COUNT_FILE="/tmp/${BOT_NAME}_restart_count"

# Configuration
CHECK_INTERVAL=30  # Check every 30 seconds
MAX_RESTARTS_PER_HOUR=6
RESTART_COOLDOWN=60  # Wait 60 seconds between restarts

# State tracking
LAST_RESTART_TIME=0

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [$BOT_DISPLAY_NAME] $1" | tee -a "$MONITOR_LOG"
}

# Check if already running
if [ -f "$LOCK_FILE" ]; then
    log_message "ZScaler monitor already running, exiting"
    exit 0
fi

# Create lock file and setup cleanup
touch "$LOCK_FILE"
trap 'rm -f "$LOCK_FILE"; exit' EXIT INT TERM

log_message "🛡️ Starting $BOT_DISPLAY_NAME ZScaler monitor..."
log_message "📍 Monitoring: $BOT_PROCESS_NAME | Log: $BOT_LOG_FILE | Restart: $BOT_RESTART_SCRIPT"

# Initialize restart counter
if [ ! -f "$RESTART_COUNT_FILE" ]; then
    echo "0:$(date +%s)" > "$RESTART_COUNT_FILE"
fi

is_bot_running() {
    pgrep -f "$BOT_PROCESS_NAME" > /dev/null
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
        log_message "⚠️ Restart rate limit exceeded ($restart_count/$MAX_RESTARTS_PER_HOUR per hour)"
        return 1
    fi
    
    # Check cooldown period
    if [ $((current_time - LAST_RESTART_TIME)) -lt "$RESTART_COOLDOWN" ]; then
        log_message "⏳ Restart cooldown active ($(($RESTART_COOLDOWN - (current_time - LAST_RESTART_TIME)))s remaining)"
        return 1
    fi
    
    return 0
}

restart_bot() {
    if ! should_restart; then
        return 1
    fi
    
    log_message "🔄 Restarting $BOT_DISPLAY_NAME due to ZScaler connection issue..."
    
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
        log_message "❌ Restart script not found or not executable: $RESTART_SCRIPT"
        return 1
    fi
    
    # Verify restart succeeded
    sleep 10
    if is_bot_running; then
        log_message "✅ $BOT_DISPLAY_NAME successfully restarted (restart #$restart_count this hour)"
        return 0
    else
        log_message "❌ $BOT_DISPLAY_NAME restart failed"
        return 1
    fi
}

check_zscaler_issues() {
    # Check if bot is running
    if ! is_bot_running; then
        log_message "📴 $BOT_DISPLAY_NAME not running, attempting to start..."
        restart_bot
        return
    fi
    
    # Check for ZScaler connection issues in recent logs
    if [ -f "$LOG_FILE" ]; then
        # Look for connection issues in the last 2 minutes
        local recent_time=$(date -v-2M '+%Y-%m-%d %H:%M' 2>/dev/null || date -d '2 minutes ago' '+%Y-%m-%d %H:%M')
        
        # ZScaler-specific connection errors
        local zscaler_errors=$(tail -n 200 "$LOG_FILE" | grep -E "(Connection reset by peer|ConnectionClosedError|Connection aborted|no close frame received|WebSocket.*failed)" | grep -c "$recent_time\|$(date '+%Y-%m-%d %H:%M')")
        
        if [ "$zscaler_errors" -gt 0 ]; then
            log_message "🚨 Detected $zscaler_errors ZScaler connection issues in recent logs"
            restart_bot
            return
        fi
        
        # Check for WebSocket disconnections without immediate reconnection
        local websocket_disconnects=$(tail -n 100 "$LOG_FILE" | grep -c "WebSocket.*closed\|connection.*lost\|Backing off.*websocket" | head -1)
        local websocket_reconnects=$(tail -n 50 "$LOG_FILE" | grep -c "WebSocket Opened\|connection.*established" | head -1)
        
        if [ "$websocket_disconnects" -gt 0 ] && [ "$websocket_reconnects" -eq 0 ]; then
            log_message "🔗 WebSocket disconnected without reconnection detected"
            restart_bot
            return
        fi
    fi
    
    log_message "✅ $BOT_DISPLAY_NAME appears healthy (WebSocket connected)"
}

# Main monitoring loop
log_message "🔍 Monitor started - checking every ${CHECK_INTERVAL}s for ZScaler issues"

while true; do
    check_zscaler_issues
    sleep "$CHECK_INTERVAL"
done