#!/bin/bash
# Pokedex SOC Bot - runs as background process
# Starts automatically via Launch Agent on Mac restart
#
# To apply changes: just run this script again (it will restart the process)
# To stop: ./scripts/start_pokedex.sh stop

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PID_FILE="$HOME/.pokedex.pid"
LOG_FILE="$PROJECT_DIR/logs/pokedex.log"

# =============================================================================
# CONFIGURATION - Edit these settings as needed
# =============================================================================

# (Add any config toggles here if needed in the future)

# =============================================================================

stop_process() {
    if [ -f "$PID_FILE" ]; then
        OLD_PID=$(cat "$PID_FILE")
        if kill -0 "$OLD_PID" 2>/dev/null; then
            echo "Stopping pokedex (PID: $OLD_PID)..."
            kill "$OLD_PID"
            sleep 1
        fi
        rm -f "$PID_FILE"
    fi
}

# Handle stop command
if [ "$1" = "stop" ]; then
    stop_process
    echo "Stopped."
    exit 0
fi

# Handle foreground mode (for launchd with KeepAlive)
if [ "$1" = "--foreground" ]; then
    stop_process
    mkdir -p "$PROJECT_DIR/logs"
    cd "$PROJECT_DIR"
    source .venv/bin/activate
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting Pokedex SOC Bot (foreground mode)..."
    exec python webex_bots/pokedex.py >> "$LOG_FILE" 2>&1
fi

# Stop existing process before starting new one
stop_process

# Ensure logs directory exists
mkdir -p "$PROJECT_DIR/logs"

# Activate virtual environment
cd "$PROJECT_DIR"
source .venv/bin/activate

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting Pokedex SOC Bot..."
echo "  Log file: $LOG_FILE"

# Run in background
nohup python webex_bots/pokedex.py >> "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"

echo "Started with PID: $(cat "$PID_FILE")"
