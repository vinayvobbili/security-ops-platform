#!/bin/bash
# Restart all Webex bots - use after deploying code updates
# This script safely restarts bots using systemd services

set -e

BOTS=("toodles" "barnacles" "money_ball" "msoar" "jarvais")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "🔄 Restarting All Webex Bots"
echo "===================================="
echo "Project: $PROJECT_DIR"
echo ""

# Check if we're running on the VM with systemd
if command -v systemctl &> /dev/null && systemctl is-system-running &> /dev/null; then
    echo "📦 Using systemd to manage bots"
    USE_SYSTEMD=true
else
    echo "🔧 Using manual process management"
    USE_SYSTEMD=false
fi

echo ""

# Function to restart bot via systemd
restart_bot_systemd() {
    local bot_name=$1
    local service_name="ir-${bot_name}"

    echo "🔄 Restarting $bot_name (systemd)..."

    # Check if service exists
    if ! systemctl list-unit-files | grep -q "$service_name.service"; then
        echo "   ⚠️  Service $service_name not found"
        return 1
    fi

    # Restart service
    sudo systemctl restart "$service_name"
    sleep 2

    # Check status
    if systemctl is-active --quiet "$service_name"; then
        local pid=$(systemctl show --property=MainPID --value "$service_name")
        echo "   ✅ $bot_name started (PID: $pid)"
    else
        echo "   ❌ $bot_name failed to start"
        echo "   📋 Check logs: sudo journalctl -u $service_name -n 20"
        return 1
    fi
}

# Function to restart bot manually
restart_bot_manual() {
    local bot_name=$1
    echo "🔄 Restarting $bot_name (manual)..."

    cd "$PROJECT_DIR" || exit 1

    # Kill old process
    pkill -f "python.*webex_bots/${bot_name}.py" 2>/dev/null || true
    sleep 2

    # Start new process with PYTHONPATH
    PYTHONPATH="$PROJECT_DIR" nohup "$PROJECT_DIR/.venv/bin/python" \
        "webex_bots/${bot_name}.py" >> "logs/${bot_name}.log" 2>&1 &
    sleep 3

    # Verify it started
    if pgrep -f "python.*webex_bots/${bot_name}.py" > /dev/null; then
        local pid=$(pgrep -f "python.*webex_bots/${bot_name}.py")
        echo "   ✅ $bot_name started (PID: $pid)"
    else
        echo "   ❌ $bot_name failed to start"
        echo "   📋 Check logs: tail -20 logs/${bot_name}.log"
        return 1
    fi
}

# Restart each bot
FAILED_BOTS=()
for bot in "${BOTS[@]}"; do
    if [ "$USE_SYSTEMD" = true ]; then
        if ! restart_bot_systemd "$bot"; then
            FAILED_BOTS+=("$bot")
        fi
    else
        if ! restart_bot_manual "$bot"; then
            FAILED_BOTS+=("$bot")
        fi
    fi
    echo ""
done

# Summary
echo "===================================="
echo "📊 Final Status:"
echo ""

if [ "$USE_SYSTEMD" = true ]; then
    for bot in "${BOTS[@]}"; do
        service_name="ir-${bot}"
        if systemctl is-active --quiet "$service_name"; then
            pid=$(systemctl show --property=MainPID --value "$service_name")
            uptime=$(ps -p "$pid" -o etime= 2>/dev/null | tr -d ' ' || echo "N/A")
            echo "✅ $bot (PID: $pid, Uptime: $uptime)"
        else
            echo "❌ $bot (not running)"
        fi
    done
else
    ps aux | grep '[p]ython.*webex_bots' | grep -v log_viewer | while read -r line; do
        pid=$(echo "$line" | awk '{print $2}')
        bot=$(echo "$line" | grep -oP 'webex_bots/\K[^.]+')
        uptime=$(ps -p "$pid" -o etime= 2>/dev/null | tr -d ' ')
        echo "✅ $bot (PID: $pid, Uptime: $uptime)"
    done
fi

echo ""

# Report failures
if [ ${#FAILED_BOTS[@]} -gt 0 ]; then
    echo "⚠️  Failed to restart: ${FAILED_BOTS[*]}"
    echo ""
fi

# Monitoring instructions
echo "🔍 Monitoring:"
if [ "$USE_SYSTEMD" = true ]; then
    echo "   systemctl status ir-<bot-name>"
    echo "   sudo journalctl -u ir-<bot-name> -f"
else
    echo "   tail -f $PROJECT_DIR/logs/<bot-name>.log"
fi

echo ""
echo "📊 Check reconnection fix is working:"
echo "   $PROJECT_DIR/deployment/monitor_bot_reconnections.sh"
echo ""

# Exit with error if any bots failed
if [ ${#FAILED_BOTS[@]} -gt 0 ]; then
    exit 1
fi
