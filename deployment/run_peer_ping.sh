#!/bin/bash
# Wrapper script to run peer ping from cron
# Add to cron: */5 * * * * /home/user/pub/IR/deployment/run_peer_ping.sh

cd /home/user/pub/IR
PYTHONPATH=/home/user/pub/IR /home/user/pub/IR/.venv/bin/python /home/user/pub/IR/src/peer_ping_keepalive.py >> /home/user/pub/IR/logs/peer_ping.log 2>&1
