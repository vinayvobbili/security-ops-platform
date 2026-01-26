#!/bin/bash
# Startup script for all_jobs scheduler
# This ensures proper logging and process management

cd /home/vinay/pub/IR || exit

# Kill any existing process
pkill -f "all_jobs"
sleep 2

# Start with unbuffered Python output
nohup /home/vinay/pub/IR/.venv/bin/python -u src/all_jobs.py >> logs/all_jobs.log 2>&1 &

echo "all_jobs scheduler started with PID: $!"
echo "Monitor logs with: tail -f /home/vinay/pub/IR/logs/all_jobs.log"
