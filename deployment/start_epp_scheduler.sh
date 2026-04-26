#!/bin/bash
# Startup script for EPP scheduler (CrowdStrike + Tanium ring tagging)

cd /home/user/IR || exit

# Kill any existing process
pkill -f "epp_scheduler"
sleep 2

# Start with unbuffered Python output
nohup /home/user/IR/.venv/bin/python -u src/epp_scheduler.py >> logs/epp_scheduler.log 2>&1 &

echo "epp_scheduler started with PID: $!"
echo "Monitor logs with: tail -f /home/user/IR/logs/epp_scheduler.log"
