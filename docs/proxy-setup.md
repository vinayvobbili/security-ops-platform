# Proxy Setup Guide

## Overview

This guide explains how to route network traffic from your Mac through the metcirt-lab VM using an SSH SOCKS5 tunnel.

## Current Status

- ✅ SSH SOCKS5 tunnel working on port 8888
- ✅ Auto-starts on Mac boot via launchd
- ✅ Auto-restarts if connection drops
- ✅ Chrome routing through VM successfully
- ✅ Claude CLI configured to use proxy
- ⚠️ HTTP proxy on port 8081 has bugs (receives requests but doesn't respond from external IPs)

## Troubleshooting

**If the proxy stops working, run the diagnostic script:**

```bash
~/debug-proxy.sh
```

This will check all components and tell you exactly what's wrong and how to fix it.

**For detailed troubleshooting steps, see:** `~/PROXY-TROUBLESHOOTING.md`

---

## SSH SOCKS5 Tunnel (Recommended)

### Quick Start

The easiest way to use the proxy is through the SSH SOCKS5 tunnel on port 8888.

### Chrome with Proxy

**Start Chrome with proxy:**

```bash
~/chrome-with-proxy.sh
```

This script automatically:

- Kills any existing SSH tunnel on port 8888
- Creates a new SSH SOCKS5 tunnel to metcirt-lab
- Launches Chrome with a separate profile using the proxy

**Verify it's working:**

- Visit `http://httpbin.org/ip` in the proxy Chrome window
- You should see the VM's public IP (162.192.161.81) instead of your Mac's IP

**Stop the tunnel:**

```bash
pkill -f 'ssh.*-D 8888.*metcirt-lab'
```

### Automatic Startup (launchd)

The SSH tunnel is managed by a launchd service that:
- Auto-starts when you log into your Mac
- Auto-restarts if the connection drops
- Keeps the connection alive with heartbeats

**Service location:** `~/Library/LaunchAgents/com.user.socks-tunnel.plist`

**Manage the service:**

```bash
# Check status
launchctl list | grep socks-tunnel
ps aux | grep "ssh.*-D 8888" | grep -v grep

# Stop the service
launchctl unload ~/Library/LaunchAgents/com.user.socks-tunnel.plist

# Start the service
launchctl load ~/Library/LaunchAgents/com.user.socks-tunnel.plist

# Restart the service
launchctl unload ~/Library/LaunchAgents/com.user.socks-tunnel.plist
launchctl load ~/Library/LaunchAgents/com.user.socks-tunnel.plist

# View logs
tail -f /tmp/socks-tunnel.log
tail -f /tmp/socks-tunnel.err
```

### Claude CLI with Proxy

**Configuration:** Environment variables are set in `~/.zshrc` (lines 39-40)

The proxy is configured automatically for all new terminal sessions.

#### Option 1: Temporary (Single Session)

```bash
export ALL_PROXY="socks5://localhost:8888"
export all_proxy="socks5://localhost:8888"
claude
```

#### Option 2: Permanent Configuration

Add to `~/.zshrc`:

```bash
# Proxy for Claude CLI via SSH tunnel to metcirt-lab
export ALL_PROXY="socks5://localhost:8888"
export all_proxy="socks5://localhost:8888"
```

Then reload your shell:

```bash
source ~/.zshrc
```

#### Test the configuration:

```bash
# Verify proxy is set
echo $ALL_PROXY

# Test Claude CLI
claude --version
```

### Manual Tunnel Management

**Start tunnel manually:**

```bash
ssh -D 8888 -N -f metcirt-lab
```

**Check if tunnel is running:**

```bash
ps aux | grep "ssh.*-D 8888" | grep -v grep
```

**Stop tunnel:**

```bash
pkill -f 'ssh.*-D 8888.*metcirt-lab'
```

**Restart tunnel:**

```bash
pkill -f 'ssh.*-D 8888.*metcirt-lab' && ssh -D 8888 -N -f metcirt-lab
```

### Test Proxy Connection

```bash
# Test with curl
curl -x socks5://localhost:8888 https://httpbin.org/ip
```

Expected output should show the VM's IP address.

---

## HTTP Proxy on Port 8081 (Not Working - Future Fix)

### Known Issues

The HTTP proxy running on the VM at port 8081 has bugs:

- Works from VM localhost
- Times out when accessed from external IPs (like your Mac)
- `do_CONNECT` method may not be getting called for external requests

### Changes Made

Modified `/web/web_server.py`:

- Changed `OptimizedProxy` base class from `SimpleHTTPRequestHandler` to `BaseHTTPRequestHandler`
- Committed as: `e96b78c5`

### Future Investigation Steps

If we need to fix the HTTP proxy:

1. **Add detailed logging:**
    - Log all incoming connections
    - Log request methods being called
    - Track request routing

2. **Network debugging:**
    - Use `tcpdump` to capture traffic on port 8081
    - Verify what packets are being received
    - Check response packets being sent

3. **Configuration checks:**
    - Verify firewall/iptables rules
    - Check `ThreadingTCPServer` configuration
    - Test binding to different interfaces

4. **Client testing:**
    - Test with various clients (curl, wget, Python requests)
    - Compare localhost vs external IP behavior
    - Test different HTTP methods (GET, POST, CONNECT)

---

## Troubleshooting

### Tunnel not connecting

```bash
# Check SSH connectivity
ssh lab-vm "echo 'Connection OK'"

# Verify port 8888 is not in use
lsof -i :8888
```

### Chrome won't start

```bash
# Kill any existing proxy Chrome instances
pkill -f "chrome-proxy-profile"

# Restart the tunnel and Chrome
~/chrome-with-proxy.sh
```

### Claude CLI not using proxy

```bash
# Verify environment variables
echo $ALL_PROXY
echo $all_proxy

# Check tunnel is running
ps aux | grep "ssh.*-D 8888" | grep -v grep

# Test proxy manually
curl -x socks5://localhost:8888 https://httpbin.org/ip
```

---

## Files

### Chrome Proxy Script

Location: `~/chrome-with-proxy.sh`

```bash
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
```

### Web Server Proxy Code

Location: `/Users/user/PycharmProjects/IR/web/web_server.py`

Relevant class: `OptimizedProxy` (line 639)

VM location: `/home/vinay/pub/IR/web/web_server.py`

---

## Notes

- The SOCKS5 tunnel is more reliable and secure than the HTTP proxy
- Chrome uses a separate profile (`~/chrome-proxy-profile`) to avoid affecting your normal browsing
- The tunnel requires an active SSH connection to metcirt-lab
- If the VM restarts, you'll need to restart the tunnel
