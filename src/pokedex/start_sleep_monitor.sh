#!/bin/bash
# Start MacBook Sleep Monitor for Pokedex Bot

PROJECT_DIR="/Users/user@company.com/PycharmProjects/IR"
SCRIPT_PATH="$PROJECT_DIR/src/pokedex/macbook_sleep_monitor.py"
LOCK_FILE="/tmp/pokedex_macbook_sleep_monitor.lock"
LOG_FILE="$PROJECT_DIR/logs/macbook_sleep_monitor.log"

# Check if already running
if [ -f "$LOCK_FILE" ]; then
    echo "⚠️  MacBook Sleep Monitor already running (PID: $(cat $LOCK_FILE))"
    exit 1
fi

echo "Stopping any existing Sleep Monitor instances..."
pkill -f "macbook_sleep_monitor.py" 2>/dev/null || true
sleep 1

echo "Starting MacBook Sleep Monitor for Pokedex..."
echo ""

# Change to project directory
cd "$PROJECT_DIR" || exit 1

# Activate virtual environment if it exists
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

# Set Python path
export PYTHONPATH="$PROJECT_DIR:$PYTHONPATH"

# Clear the log file to ensure we see fresh output
> "$LOG_FILE"

# Start the monitor
python3 "$SCRIPT_PATH" &
MONITOR_PID=$!

echo "Waiting for initialization..."
sleep 2

# Show initial log output if available
if [ -f "$LOG_FILE" ]; then
    echo "Initial startup messages:"
    timeout 3 tail -10 "$LOG_FILE" 2>/dev/null || true
    echo ""
fi

# Check if the process is actually running
if pgrep -f "macbook_sleep_monitor.py" > /dev/null; then
    PID=$(pgrep -f 'macbook_sleep_monitor.py')
    echo "✅ MacBook Sleep Monitor is running (PID: $PID)"
    echo ""
    echo "To view logs: tail -f $LOG_FILE"
else
    echo "❌ Warning: MacBook Sleep Monitor process not found"
    echo "Check logs: tail -20 $LOG_FILE"
fi