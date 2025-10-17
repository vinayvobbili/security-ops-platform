#!/bin/bash

# Kill existing server process if running
pkill -f "web_server.py"
sleep 1

# Start new server instance
nohup env PYTHONPATH=/home/vinay/pub/IR .venv/bin/python web/web_server.py >> web_server.log 2>&1 &
