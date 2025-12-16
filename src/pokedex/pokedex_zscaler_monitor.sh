#!/bin/bash
# Pokedex ZScaler Monitor - MacBook sleep/wake resilience for Pokedex bot only
# Monitors for ZScaler connection kills and automatically restarts Pokedex

# Get project directory (3 levels up from this script)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOG_FILE="$PROJECT_DIR/logs/pokedex.log"
RESTART_SCRIPT="$PROJECT_DIR/src/pokedex/restart_pokedex.sh"
MONITOR_LOG="$PROJECT_DIR/logs/pokedex_zscaler_monitor.log"
LOCK_FILE="/tmp/pokedex_zscaler_monitor.lock"

# Configuration
CHECK_INTERVAL=15  # Check every 15 seconds for faster sleep/wake detection
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
    log_message "Pokedex ZScaler monitor already running, exiting"
    exit 0
fi

# Create lock file and setup cleanup
touch "$LOCK_FILE"
trap 'rm -f "$LOCK_FILE"; exit' EXIT INT TERM

log_message "🛡️ Starting Pokedex ZScaler monitor..."

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
        log_message "⚠️ Pokedex restart rate limit exceeded ($restart_count/$MAX_RESTARTS_PER_HOUR per hour)"
        return 1
    fi
    
    # Check cooldown period
    if [ $((current_time - LAST_RESTART_TIME)) -lt "$RESTART_COOLDOWN" ]; then
        log_message "⏳ Pokedex restart cooldown active ($(($RESTART_COOLDOWN - (current_time - LAST_RESTART_TIME)))s remaining)"
        return 1
    fi
    
    return 0
}

restart_pokedex() {
    if ! should_restart; then
        return 1
    fi
    
    log_message "🔄 Restarting Pokedex due to ZScaler connection issue..."
    
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
        log_message "❌ Pokedex restart script not found or not executable: $RESTART_SCRIPT"
        return 1
    fi
    
    # Verify restart succeeded
    sleep 10
    if is_pokedex_running; then
        log_message "✅ Pokedex successfully restarted (restart #$restart_count this hour)"
        return 0
    else
        log_message "❌ Pokedex restart failed"
        return 1
    fi
}

detect_system_sleep_wake() {
    # Check if system recently woke from sleep by monitoring system uptime
    local current_uptime=$(sysctl -n kern.boottime 2>/dev/null | grep -o 'sec = [0-9]*' | cut -d' ' -f3)
    local current_time=$(date +%s)

    if [ -n "$current_uptime" ]; then
        local uptime_seconds=$((current_time - current_uptime))

        # Store previous uptime check
        local uptime_file="/tmp/pokedx_uptime_check"

        if [ -f "$uptime_file" ]; then
            local prev_uptime=$(cat "$uptime_file")

            # If uptime decreased significantly, system likely went to sleep
            if [ "$uptime_seconds" -lt "$((prev_uptime - 60))" ]; then
                log_message "🌙 System sleep/wake detected - uptime decreased from ${prev_uptime}s to ${uptime_seconds}s"
                return 0  # Sleep detected
            fi
        fi

        # Update uptime file
        echo "$uptime_seconds" > "$uptime_file"
    fi

    return 1  # No sleep detected
}

check_pokedx_zscaler_issues() {
    # Check for system sleep/wake first (highest priority for ZScaler)
    if detect_system_sleep_wake; then
        log_message "🚨 System sleep/wake detected - ZScaler likely killed connections"
        restart_pokedx
        return
    fi
    # Check if Pokedex is running
    if ! is_pokedex_running; then
        log_message "📴 Pokedex not running, attempting to start..."
        restart_pokedex
        return
    fi
    
    # Check for ZScaler connection issues in recent Pokedex logs
    if [ -f "$LOG_FILE" ]; then
        # Look for connection issues in the last 2 minutes
        local recent_time=$(date -v-2M '+%Y-%m-%d %H:%M' 2>/dev/null || date -d '2 minutes ago' '+%Y-%m-%d %H:%M')
        
        # ZScaler-specific connection errors affecting Pokedex
        local zscaler_errors=$(tail -n 200 "$LOG_FILE" | grep -E "(Connection reset by peer|ConnectionClosedError|Connection aborted|no close frame received|WebSocket.*failed)" | grep -c "$recent_time\|$(date '+%Y-%m-%d %H:%M')")
        
        if [ "$zscaler_errors" -gt 0 ]; then
            log_message "🚨 Detected $zscaler_errors ZScaler connection issues in recent Pokedex logs"
            restart_pokedex
            return
        fi
        
        # Check for WebSocket disconnections without immediate reconnection
        local websocket_disconnects=$(tail -n 100 "$LOG_FILE" | grep -c "WebSocket.*closed\|connection.*lost\|Backing off.*websocket" | head -1)
        local websocket_reconnects=$(tail -n 50 "$LOG_FILE" | grep -c "WebSocket Opened\|connection.*established" | head -1)
        
        if [ "$websocket_disconnects" -gt 0 ] && [ "$websocket_reconnects" -eq 0 ]; then
            log_message "🔗 Pokedex WebSocket disconnected without reconnection detected"
            restart_pokedex
            return
        fi
    fi
    
    log_message "✅ Pokedex appears healthy (WebSocket connected)"
}

# Main monitoring loop
log_message "🔍 Pokedex ZScaler monitor started - checking every ${CHECK_INTERVAL}s for ZScaler issues"

while true; do
    check_pokedex_zscaler_issues
    sleep "$CHECK_INTERVAL"
done