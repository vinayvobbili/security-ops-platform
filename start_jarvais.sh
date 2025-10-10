#!/bin/bash

# Kill existing barnacles process if running
pkill -f "webex_bots/jarvais.py"
sleep 1

# Start new barnacles instance
nohup env PYTHONPATH=/Users/user/PycharmProjects/IR .venv/bin/python webex_bots/jarvais.py >> jarvais.log 2>&1 &
