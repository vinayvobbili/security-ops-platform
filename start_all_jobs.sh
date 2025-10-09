#!/bin/bash

# Kill existing all_jobs process if running
pkill -f "src/all_jobs.py"
sleep 1

# Start new all_jobs instance
nohup env PYTHONPATH=/Users/user/PycharmProjects/IR .venv/bin/python src/all_jobs.py >> all_jobs.log 2>&1 &
