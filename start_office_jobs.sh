#!/bin/bash

# Kill existing office_jobs process if running
pkill -f "src/office_jobs.py"
sleep 1

# Start new office_jobs instance
nohup env PYTHONPATH=/home/vinay/pub/IR .venv/bin/python src/office_jobs.py >> office_jobs.log 2>&1 &
