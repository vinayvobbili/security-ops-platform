#!/bin/bash
# Monitor bot timeout rates and connection pool health
# Usage: ./monitor_bot_timeouts.sh [duration_in_hours]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$PROJECT_DIR/logs"

DURATION_HOURS="${1:-24}"
DURATION_SECONDS=$((DURATION_HOURS * 3600))

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Bot Timeout Monitor${NC}"
echo -e "${GREEN}========================================${NC}"
echo "Monitoring for: $DURATION_HOURS hours"
echo "Start time: $(date)"
echo ""

# Function to count timeouts in last N minutes
count_recent_timeouts() {
    local minutes=$1
    local since=$(date -d "$minutes minutes ago" +"%Y-%m-%d %H:%M" 2>/dev/null || date -v-${minutes}M +"%Y-%m-%d %H:%M")

    # Count timeout errors in logs from the last N minutes
    local count=$(tail -10000 "$LOG_DIR"/*.log 2>/dev/null | \
                  grep -E "Read timed out.*read timeout|ReadTimeout|Timeout.*60" | \
                  grep -E "[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}" | \
                  awk -v since="$since" '$1 " " $2 >= since' | \
                  wc -l)

    echo "$count"
}

# Function to show bot status
show_bot_status() {
    echo -e "\n${YELLOW}[$(date '+%H:%M:%S')] Bot Status:${NC}"
    ps aux | grep -E "python.*webex_bots/(jarvis|tars|barnacles|money_ball|toodles|msoar).py" | \
        grep -v grep | \
        awk '{printf "  %-15s PID: %-7s CPU: %5s%% MEM: %5s%% Time: %10s\n", $11, $2, $3, $4, $10}'

    if [ $? -ne 0 ]; then
        echo -e "  ${RED}No bots running!${NC}"
    fi
}

# Function to show connection stats
show_connection_stats() {
    echo -e "\n${YELLOW}[$(date '+%H:%M:%S')] Connection Stats:${NC}"

    # Count established HTTPS connections to Webex
    local webex_conns=$(ss -tn state established '( dport = :443 )' 2>/dev/null | grep '170.72.245' | wc -l)
    echo "  Webex HTTPS connections: $webex_conns"

    # Show timeout rate
    local timeouts_1min=$(count_recent_timeouts 1)
    local timeouts_5min=$(count_recent_timeouts 5)
    local timeouts_60min=$(count_recent_timeouts 60)

    echo "  Timeouts (last 1 min):  $timeouts_1min"
    echo "  Timeouts (last 5 min):  $timeouts_5min"
    echo "  Timeouts (last 60 min): $timeouts_60min"

    # Alert if high timeout rate
    if [ "$timeouts_1min" -gt 5 ]; then
        echo -e "  ${RED}⚠️  HIGH TIMEOUT RATE! ($timeouts_1min in last minute)${NC}"
    elif [ "$timeouts_5min" -gt 10 ]; then
        echo -e "  ${YELLOW}⚠️  Elevated timeout rate ($timeouts_5min in last 5 minutes)${NC}"
    else
        echo -e "  ${GREEN}✓ Timeout rate normal${NC}"
    fi
}

# Initial status
show_bot_status
show_connection_stats

# Monitor loop
echo -e "\n${GREEN}Starting monitoring loop (checks every 5 minutes)...${NC}"
echo "Press Ctrl+C to stop"
echo ""

START_TIME=$(date +%s)
CHECK_INTERVAL=300  # 5 minutes

while true; do
    sleep $CHECK_INTERVAL

    # Check if duration exceeded
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))

    if [ $ELAPSED -ge $DURATION_SECONDS ]; then
        echo -e "\n${GREEN}Monitoring duration completed ($DURATION_HOURS hours)${NC}"
        break
    fi

    # Show status
    show_bot_status
    show_connection_stats
done

# Final summary
echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}Monitoring Complete${NC}"
echo -e "${GREEN}========================================${NC}"
echo "End time: $(date)"

# Show total timeout count
echo -e "\n${YELLOW}Timeout Summary:${NC}"
for bot in jarvis tars barnacles money_ball toodles msoar; do
    if [ -f "$LOG_DIR/${bot}.log" ]; then
        count=$(grep -c "Read timed out" "$LOG_DIR/${bot}.log" 2>/dev/null || echo 0)
        echo "  $bot: $count total timeouts"
    fi
done
