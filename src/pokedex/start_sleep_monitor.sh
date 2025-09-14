#!/bin/bash
# Start MacBook Sleep Monitor for Pokedex Bot

PROJECT_DIR="/Users/user@company.com/PycharmProjects/IR"
SCRIPT_PATH="$PROJECT_DIR/src/pokedex/macbook_sleep_monitor.py"
LOCK_FILE="/tmp/pokedex_macbook_sleep_monitor.lock"

# Check if already running
if [ -f "$LOCK_FILE" ]; then
    echo "MacBook Sleep Monitor already running (PID: $(cat $LOCK_FILE))"
    exit 1
fi

echo "🚀 Starting MacBook Sleep Monitor for Pokedx..."

# Change to project directory
cd "$PROJECT_DIR" || exit 1

# Activate virtual environment if it exists
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

# Set Python path
export PYTHONPATH="$PROJECT_DIR:$PYTHONPATH"

# Start the monitor
python3 "$SCRIPT_PATH" &

echo "✅ MacBook Sleep Monitor started with PID: $!"
echo "Logs: $PROJECT_DIR/logs/macbook_sleep_monitor.log"