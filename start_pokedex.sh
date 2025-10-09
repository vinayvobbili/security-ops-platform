#!/bin/bash

# Kill existing pokedex process if running
pkill -f "webex_bots/pokedex.py"
sleep 1

# Start new pokedex instance
nohup env PYTHONPATH=/Users/user/PycharmProjects/IR .venv/bin/python webex_bots/pokedex.py >> pokedex.log 2>&1 &
