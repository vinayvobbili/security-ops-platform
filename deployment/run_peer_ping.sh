#!/bin/bash
# Wrapper script to run peer ping from cron
# Add to cron: */5 * * * * /home/user/IR/deployment/run_peer_ping.sh

cd /home/user/IR
PYTHONPATH=/home/user/IR /home/user/IR/.venv/bin/python /home/user/IR/src/peer_ping_keepalive.py >> /home/user/IR/logs/peer_ping.log 2>&1
