#!/bin/bash
# Jarvais SOC Bot Runner Script

# Save current directory
ORIGINAL_DIR=$(pwd)

# Change to project directory
cd /Users/user/PycharmProjects/IR || exit 1

# Activate virtual environment and run bot
source .venv/bin/activate
export PYTHONPATH="/Users/user/PycharmProjects/IR:$PYTHONPATH"
python webex_bots/jarvais.py

# Return to original directory
cd "$ORIGINAL_DIR" || exit 1