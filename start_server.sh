#!/bin/bash
nohup env PYTHONPATH=/home/vinay/pub/IR .venv/bin/python web/web_server.py >> web_server.log 2>&1 &
