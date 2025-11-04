#!/bin/bash

cd /Users/user/PycharmProjects/IR || exit 1

# Kill existing pokedex process if running
echo "Stopping existing the security assistant bot instances..."
pkill -f "webex_bots/pokedex"
sleep 1

# Clear the log file to ensure we see fresh output
: > pokedex.log

# Start new pokedex instance in background
# Python logging handles all output - no need to redirect here
nohup env PYTHONPATH=/Users/user/PycharmProjects/IR .venv/bin/python webex_bots/pokedex.py &

echo "Starting the security assistant bot bot..."
echo ""

# Wait for the log file to appear and contain data
sleep 2

# Tail the log file until we see device cleanup complete or timeout after 30 seconds
timeout 30 tail -f pokedex.log 2>/dev/null | while read -r line; do
    echo "$line"
    if echo "$line" | grep -q "Device cleanup complete"; then
        # Give it a few more seconds to finish initialization
        sleep 3
        pkill -P $$ tail  # Kill the tail process
        break
    fi
done

echo ""

# Check if the process is actually running
if pgrep -f "webex_bots/pokedex" > /dev/null; then
    PID=$(pgrep -f 'webex_bots/pokedex')
    echo "✅ the security assistant bot is running (PID: $PID)"
    echo ""
    echo "To view logs: tail -f /Users/user/PycharmProjects/IR/pokedex.log"
else
    echo "❌ Warning: the security assistant bot process not found"
    echo "Check logs: tail -20 /Users/user/PycharmProjects/IR/pokedex.log"
fi
