#!/bin/bash
nohup env PYTHONPATH=/home/vinay/pub/IR .venv/bin/python src/office_jobs.py >> office_jobs.log 2>&1 &
