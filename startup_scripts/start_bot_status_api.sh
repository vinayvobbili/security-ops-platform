#!/bin/bash

cd /opt/incident-response || exit 1

# Kill existing bot status API if running
echo "Stopping existing bot status API..."
pkill -f "deployment/bot_status_api.py" 2>/dev/null
sleep 1

# Ensure logs directory exists
mkdir -p logs

# Load environment variables
source .env

# Start new bot status API instance in background
nohup .venv/bin/python deployment/bot_status_api.py > logs/bot_status_api.log 2>&1 &

echo "Starting Bot Status API..."
sleep 2

# Check if the process is actually running
if pgrep -f "deployment/bot_status_api.py" > /dev/null; then
    PID=$(pgrep -f 'deployment/bot_status_api.py')
    echo "✅ Bot Status API is running (PID: $PID)"
    echo "   Listening on: http://0.0.0.0:8040"
    echo "   Health check: curl http://localhost:8040/api/health"
    echo ""
    echo "To view logs: tail -f /opt/incident-response/logs/bot_status_api.log"
else
    echo "❌ Warning: Bot Status API process not found"
    echo "Check logs: tail -20 /opt/incident-response/logs/bot_status_api.log"
fi
