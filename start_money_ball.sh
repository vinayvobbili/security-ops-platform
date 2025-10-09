#!/bin/bash

# Kill existing money_ball process if running
pkill -f "webex_bots/money_ball.py"
sleep 1

# Start new money_ball instance
nohup env PYTHONPATH=/home/vinay/pub/IR .venv/bin/python webex_bots/money_ball.py >> money_ball.log 2>&1 &
