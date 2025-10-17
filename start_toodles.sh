#!/bin/bash

# Kill existing toodles process if running
pkill -f "webex_bots/toodles.py"
sleep 1

# Start new toodles instance
nohup env PYTHONPATH=/home/vinay/pub/IR .venv/bin/python webex_bots/toodles.py >> toodles.log 2>&1 &
