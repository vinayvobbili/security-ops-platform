#!/bin/bash

# This script creates an SSH tunnel and launches Chrome through it
#
# The SSH tunnel (SOCKS5 proxy) is created on local port 8888
# and forwards traffic through metcirt-lab VM

# Kill any existing SSH tunnel on port 8888
pkill -f "ssh.*-D 8888.*metcirt-lab" 2>/dev/null

# Create SSH SOCKS tunnel in background
ssh -D 8888 -N -f metcirt-lab

# Wait a moment for tunnel to establish
sleep 1

# Launch Chrome with SOCKS proxy
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --user-data-dir="$HOME/chrome-proxy-profile" \
  --proxy-server="socks5://localhost:8888" \
  &

echo "Chrome launched with SOCKS5 proxy through metcirt-lab VM"
echo "To close the tunnel: pkill -f 'ssh.*-D 8888.*metcirt-lab'"
