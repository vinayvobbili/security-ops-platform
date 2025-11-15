#!/bin/bash
# Start the health checker that uses one bot to ping others

BOT_DIR="$HOME/pub/IR"
LOG_FILE="$BOT_DIR/logs/health_checker.log"

cd "$BOT_DIR" || exit 1

# Kill existing health checker if running
pkill -f "python.*health_checker.py" 2>/dev/null

# Start health checker in background
nohup .venv/bin/python health_checker.py >> "$LOG_FILE" 2>&1 &

sleep 2

# Verify it started
if pgrep -f "python.*health_checker.py" > /dev/null; then
    PID=$(pgrep -f "python.*health_checker.py")
    echo "✅ Health checker started (PID: $PID)"
    echo "📊 Monitor with: tail -f $LOG_FILE"
else
    echo "❌ Health checker failed to start"
    echo "📊 Check logs: cat $LOG_FILE"
    exit 1
fi
