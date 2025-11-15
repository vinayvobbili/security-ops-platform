#!/bin/bash
# Safely restart all Webex bots with the reconnection fix

BOTS=("toodles" "barnacles" "money_ball" "msoar")
BOT_DIR="$HOME/pub/IR"

echo "🔄 Restarting all Webex bots with reconnection fix"
echo "=================================================="
echo ""

# Pull latest code from git
echo "📥 Pulling latest code from git..."
cd "$BOT_DIR" || exit 1

# Discard any local changes to ensure clean pull
git restore . 2>/dev/null

if git pull; then
    echo "   ✅ Code updated successfully"
else
    echo "   ⚠️  Git pull failed, continuing with current code"
fi
echo ""

# Function to restart a single bot
restart_bot() {
    local bot_name=$1
    echo "🔄 Restarting $bot_name..."

    # Kill old process
    pkill -f "python.*webex_bots/${bot_name}.py" 2>/dev/null
    sleep 2

    # Start new process
    cd "$BOT_DIR" || exit 1
    nohup .venv/bin/python "webex_bots/${bot_name}.py" >> "logs/${bot_name}.log" 2>&1 &
    sleep 3

    # Verify it started
    if pgrep -f "python.*webex_bots/${bot_name}.py" > /dev/null; then
        local pid
        pid=$(pgrep -f "python.*webex_bots/${bot_name}.py")
        echo "   ✅ $bot_name started (PID: $pid)"
    else
        echo "   ❌ $bot_name failed to start"
        return 1
    fi
}

# Restart each bot
for bot in "${BOTS[@]}"; do
    restart_bot "$bot"
    echo ""
done

echo "=================================================="
echo "📊 Final Status:"
echo ""

# Show all running bots
pgrep -f 'python.*webex_bots' | while read -r pid; do
    # Get the full command line for this PID
    cmd=$(ps -p "$pid" -o command= 2>/dev/null)
    # Skip if it's the log_viewer
    if [[ "$cmd" == *"log_viewer"* ]]; then
        continue
    fi
    # Extract bot name
    bot=$(echo "$cmd" | grep -oP 'webex_bots/\K[^.]+')
    uptime=$(ps -p "$pid" -o etime= 2>/dev/null | tr -d ' ')
    echo "✅ $bot (PID: $pid, Uptime: $uptime)"
done

echo ""
echo "🔍 Monitor individual bots:"
for bot in "${BOTS[@]}"; do
    echo "   tail -f ~/pub/IR/logs/${bot}.log"
done

echo ""
echo "🔍 Monitor all reconnections:"
echo "   ./monitor_bot_reconnections.sh"
