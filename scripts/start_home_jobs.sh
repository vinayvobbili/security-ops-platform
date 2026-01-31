#!/bin/bash
# Home jobs scheduler - runs as background process
# Starts automatically via Launch Agent on Mac restart
#
# To apply changes: just run this script again (it will restart the process)
# To stop: ./scripts/start_home_jobs.sh stop

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PID_FILE="$HOME/.home_jobs.pid"
LOG_FILE="$PROJECT_DIR/logs/home_jobs.log"

# =============================================================================
# CONFIGURATION - Edit these settings as needed
# =============================================================================

# Uncomment to enable hourly tipper analysis (Mon-Fri 9AM-6PM ET)
export ENABLE_HOURLY_TIPPER_ANALYSIS="true"

# =============================================================================

stop_process() {
    if [ -f "$PID_FILE" ]; then
        OLD_PID=$(cat "$PID_FILE")
        if kill -0 "$OLD_PID" 2>/dev/null; then
            echo "Stopping home_jobs (PID: $OLD_PID)..."
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
    export ENABLE_HOURLY_TIPPER_ANALYSIS="${ENABLE_HOURLY_TIPPER_ANALYSIS:-false}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting home_jobs scheduler (foreground mode)..."
    echo "  Hourly tipper analysis: $ENABLE_HOURLY_TIPPER_ANALYSIS"
    exec python src/home_jobs.py >> "$LOG_FILE" 2>&1
fi

# Stop existing process before starting new one
stop_process

# Ensure logs directory exists
mkdir -p "$PROJECT_DIR/logs"

# Activate virtual environment
cd "$PROJECT_DIR"
source .venv/bin/activate

# Set defaults for env vars not explicitly set
export ENABLE_HOURLY_TIPPER_ANALYSIS="${ENABLE_HOURLY_TIPPER_ANALYSIS:-false}"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting home_jobs scheduler..."
echo "  Hourly tipper analysis: $ENABLE_HOURLY_TIPPER_ANALYSIS"
echo "  Log file: $LOG_FILE"

# Run in background
nohup python src/home_jobs.py >> "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"

echo "Started with PID: $(cat "$PID_FILE")"
