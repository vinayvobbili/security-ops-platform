#!/bin/bash
# Safely restart all Webex bots with the reconnection fix

BOTS=("toodles" "barnacles" "money_ball" "msoar")
BOT_DIR="$HOME/IR"

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

    # Kill ALL old processes (gracefully first, then forcefully)
    if pgrep -f "python.*webex_bots/${bot_name}.py" > /dev/null; then
        echo "   🛑 Stopping existing instances..."
        # Try graceful shutdown first (SIGTERM)
        pkill -f "python.*webex_bots/${bot_name}.py" 2>/dev/null
        sleep 3

        # Force kill any remaining processes (SIGKILL)
        if pgrep -f "python.*webex_bots/${bot_name}.py" > /dev/null; then
            echo "   ⚠️  Force killing stuck processes..."
            pkill -9 -f "python.*webex_bots/${bot_name}.py" 2>/dev/null
            sleep 2
        fi

        # Final verification - ensure ALL processes are dead
        local retry=0
        while pgrep -f "python.*webex_bots/${bot_name}.py" > /dev/null && [ $retry -lt 5 ]; do
            echo "   ⏳ Waiting for processes to terminate..."
            sleep 1
            retry=$((retry + 1))
        done

        if pgrep -f "python.*webex_bots/${bot_name}.py" > /dev/null; then
            echo "   ❌ Failed to kill all old instances"
            return 1
        fi
        echo "   ✅ All old instances stopped"
    fi

    # Start new process
    cd "$BOT_DIR" || exit 1
    nohup .venv/bin/python "webex_bots/${bot_name}.py" >> "logs/${bot_name}.log" 2>&1 &
    sleep 3

    # Verify exactly ONE instance started
    local process_count
    process_count=$(pgrep -f "python.*webex_bots/${bot_name}.py" | wc -l)
    if [ "$process_count" -eq 1 ]; then
        local pid
        pid=$(pgrep -f "python.*webex_bots/${bot_name}.py")
        echo "   ✅ $bot_name started (PID: $pid)"
    elif [ "$process_count" -gt 1 ]; then
        echo "   ⚠️  Multiple instances detected ($process_count) - something is wrong!"
        return 1
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
    echo "   tail -f ~/security-ops-platform/logs/${bot}.log"
done

echo ""
echo "🔍 Monitor all reconnections:"
echo "   ./monitor_bot_reconnections.sh"
