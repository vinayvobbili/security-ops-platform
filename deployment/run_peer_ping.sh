#!/bin/bash
# Wrapper script to run peer ping from cron
# Add to cron: */5 * * * * /home/vinay/pub/IR/deployment/run_peer_ping.sh

cd /home/vinay/pub/IR
PYTHONPATH=/home/vinay/pub/IR /home/vinay/pub/IR/.venv/bin/python /home/vinay/pub/IR/src/peer_ping_keepalive.py >> /home/vinay/pub/IR/logs/peer_ping.log 2>&1
