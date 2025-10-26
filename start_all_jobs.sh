#!/bin/bash

cd /home/vinay/pub/IR || exit 1

# Kill existing all_jobs process if running
echo "Stopping existing All Jobs instances..."
pkill -f "src/all_jobs.py"
sleep 1

# Clear the log file to ensure we see fresh output
: > logs/all_jobs.log

# Start new all_jobs instance in background
nohup env PYTHONPATH=/home/vinay/pub/IR .venv/bin/python src/all_jobs.py >> logs/all_jobs.log 2>&1 &

echo "Starting All Jobs..."
echo ""

# Wait for the log file to appear and contain data
sleep 2

# Show initial log output
echo "Initial startup messages:"
timeout 5 tail -f logs/all_jobs.log 2>/dev/null | head -20 || true
echo ""

# Check if the process is actually running
if pgrep -f "src/all_jobs.py" > /dev/null; then
    PID=$(pgrep -f 'src/all_jobs.py')
    echo "✅ All Jobs is running (PID: $PID)"
    echo ""
    echo "To view logs: tail -f /home/vinay/pub/IR/logs/all_jobs.log"
else
    echo "❌ Warning: All Jobs process not found"
    echo "Check logs: tail -20 /home/vinay/pub/IR/logs/all_jobs.log"
fi
