#!/bin/bash
# Restart all bots with connection pool fix
# Usage: ./restart_bots_with_pool_fix.sh [bot_name]
# If no bot_name specified, restarts all bots

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

BOT_NAME="${1:-all}"

# Function to stop a bot
stop_bot() {
    local bot=$1
    echo -e "${YELLOW}Stopping $bot...${NC}"

    # Find and kill the bot process
    pids=$(pgrep -f "python.*webex_bots/$bot.py" || true)

    if [ -n "$pids" ]; then
        echo "  Found PIDs: $pids"
        kill $pids || true
        sleep 2

        # Force kill if still running
        pids=$(pgrep -f "python.*webex_bots/$bot.py" || true)
        if [ -n "$pids" ]; then
            echo "  Force killing: $pids"
            kill -9 $pids || true
        fi
        echo -e "  ${GREEN}✓ Stopped $bot${NC}"
    else
        echo -e "  ${YELLOW}$bot was not running${NC}"
    fi
}

# Function to start a bot
start_bot() {
    local bot=$1
    echo -e "${YELLOW}Starting $bot...${NC}"

    # Check if bot file exists
    if [ ! -f "webex_bots/$bot.py" ]; then
        echo -e "  ${RED}✗ Bot file not found: webex_bots/$bot.py${NC}"
        return 1
    fi

    # Start bot in background
    nohup .venv/bin/python "webex_bots/$bot.py" > /dev/null 2>&1 &
    local pid=$!

    # Wait a bit and check if it's still running
    sleep 3
    if ps -p $pid > /dev/null; then
        echo -e "  ${GREEN}✓ Started $bot (PID: $pid)${NC}"
    else
        echo -e "  ${RED}✗ Failed to start $bot${NC}"
        return 1
    fi
}

# Function to restart a bot
restart_bot() {
    local bot=$1
    echo -e "\n${GREEN}======================================${NC}"
    echo -e "${GREEN}Restarting: $bot${NC}"
    echo -e "${GREEN}======================================${NC}"
    stop_bot "$bot"
    sleep 2
    start_bot "$bot"
}

# List of bots with connection pool fixes
BOTS_WITH_FIX=(
    "jarvis"
    "tars"
    "barnacles"
    "money_ball"
)

# Main logic
if [ "$BOT_NAME" = "all" ]; then
    echo -e "${GREEN}Restarting all bots with connection pool fix...${NC}\n"

    for bot in "${BOTS_WITH_FIX[@]}"; do
        restart_bot "$bot"
    done

    echo -e "\n${GREEN}======================================${NC}"
    echo -e "${GREEN}All bots restarted!${NC}"
    echo -e "${GREEN}======================================${NC}"

elif [[ " ${BOTS_WITH_FIX[@]} " =~ " ${BOT_NAME} " ]]; then
    restart_bot "$BOT_NAME"
else
    echo -e "${RED}Error: Unknown bot name '$BOT_NAME'${NC}"
    echo -e "Available bots: ${BOTS_WITH_FIX[*]}"
    exit 1
fi

# Show current bot status
echo -e "\n${YELLOW}Current bot status:${NC}"
ps aux | grep -E "python.*webex_bots/(jarvis|tars|barnacles|money_ball|toodles|msoar).py" | grep -v grep || echo "No bots running"

echo -e "\n${GREEN}✓ Done!${NC}"
echo -e "\n${YELLOW}Monitor logs for timeouts:${NC}"
echo "  tail -f logs/*.log | grep -i timeout"
