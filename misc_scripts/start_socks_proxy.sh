#!/usr/bin/env bash
# Start a SOCKS5 proxy on localhost:1080 routed through the Mac on the LAN.
#
# Requires the Mac tunnel to be running (misc_scripts/start_tunnel_to_vm.py)
# which reverse-forwards port 2222 -> Mac SSH.
#
# The Salesforce scanner reads SALESFORCE_SCAN_PROXY from .env to use this.

set -euo pipefail

SOCKS_PORT=1080
REVERSE_SSH_PORT=2222
SSH_USER="${REVERSE_SSH_USER:-labuser}"

# Check if the reverse SSH tunnel is up
if ! nc -z localhost "$REVERSE_SSH_PORT" 2>/dev/null; then
    echo "ERROR: Reverse SSH tunnel not available on port $REVERSE_SSH_PORT"
    echo "Make sure start_tunnel_to_vm.py is running on the Mac."
    exit 1
fi

# Kill any existing SOCKS proxy on this port
pkill -f "ssh.*-D $SOCKS_PORT.*-p $REVERSE_SSH_PORT" 2>/dev/null || true
sleep 1

echo "Starting SOCKS5 proxy on localhost:$SOCKS_PORT via Mac (port $REVERSE_SSH_PORT)..."
ssh -D "$SOCKS_PORT" \
    -p "$REVERSE_SSH_PORT" \
    -N -f \
    -o StrictHostKeyChecking=no \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=3 \
    "$SSH_USER@localhost"

echo "SOCKS5 proxy running on localhost:$SOCKS_PORT"
echo "Set SALESFORCE_SCAN_PROXY=socks5h://localhost:$SOCKS_PORT in .env"
