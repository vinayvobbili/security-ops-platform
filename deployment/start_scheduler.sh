#!/bin/bash
# Startup script for scheduler
# This ensures proper logging and process management

cd /home/user/IR || exit

# Kill any existing process
pkill -f "scheduler"
sleep 2

# Start with unbuffered Python output
nohup /home/user/IR/.venv/bin/python -u src/ir_scheduler.py >> logs/ir_scheduler.log 2>&1 &

echo "ir_scheduler started with PID: $!"
echo "Monitor logs with: tail -f /home/user/IR/logs/ir_scheduler.log"
