#!/bin/bash
# Wrapper script to run peer ping from cron
# Add to cron: */5 * * * * /opt/incident-response/deployment/run_peer_ping.sh

cd /opt/incident-response
PYTHONPATH=/opt/incident-response /opt/incident-response/.venv/bin/python /opt/incident-response/src/peer_ping_keepalive.py >> /opt/incident-response/logs/peer_ping.log 2>&1
