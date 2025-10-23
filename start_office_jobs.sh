#!/bin/bash

cd /home/vinay/pub/IR || exit 1

# Kill existing office_jobs process if running
echo "Stopping existing Office Jobs instances..."
pkill -f "src/office_jobs.py"
sleep 1

# Clear the log file to ensure we see fresh output
: > office_jobs.log

# Start new office_jobs instance in background
nohup env PYTHONPATH=/home/vinay/pub/IR .venv/bin/python src/office_jobs.py >> office_jobs.log 2>&1 &

echo "Starting Office Jobs..."
echo ""

# Wait for the log file to appear and contain data
sleep 2

# Show initial log output
echo "Initial startup messages:"
timeout 5 tail -f office_jobs.log 2>/dev/null | head -20 || true
echo ""

# Check if the process is actually running
if pgrep -f "src/office_jobs.py" > /dev/null; then
    PID=$(pgrep -f 'src/office_jobs.py')
    echo "✅ Office Jobs is running (PID: $PID)"
    echo ""
    echo "To view logs: tail -f /home/vinay/pub/IR/office_jobs.log"
else
    echo "❌ Warning: Office Jobs process not found"
    echo "Check logs: tail -20 /home/vinay/pub/IR/office_jobs.log"
fi
