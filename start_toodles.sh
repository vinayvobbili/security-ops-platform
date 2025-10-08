#!/bin/bash
nohup env PYTHONPATH=/home/vinay/pub/IR .venv/bin/python webex_bots/toodles.py >> toodles.log 2>&1 &
