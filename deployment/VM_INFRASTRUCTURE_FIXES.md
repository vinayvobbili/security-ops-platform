# VM Infrastructure Fixes for metcirt-lab

This document describes infrastructure improvements made to the metcirt-lab VM to address reliability and performance issues.

## Problems Identified

1. **File Descriptor Limits Too Low (1024)**
   - Websocket bots need many concurrent connections
   - Default limit was too low, causing connection failures

2. **TCP Keepalive Too Long (2 hours)**
   - Connections went stale after idle periods
   - TCP took 2 hours to detect dead connections
   - Caused DNS resolution failures after idle periods

3. **No Process Management**
   - Manual startup with shell scripts
   - No auto-restart on crash
   - No automatic startup on boot
   - No centralized logging

4. **DNS Configuration Issues**
   - systemd-resolved stub (127.0.0.53) timing out
   - Using DHCP-provided DNS servers (unreliable)
   - Causing "Temporary failure in name resolution" errors

5. **Security Issues**
   - Netplan configuration files had overly permissive permissions

## Fixes Applied

### 1. Infrastructure Configuration

Run the infrastructure fixes script:

```bash
cd /home/vinay/pub/IR/deployment
sudo bash vm_infrastructure_fixes.sh
```

This script applies:
- **File descriptor limits** increased to 65536
- **TCP keepalive** reduced to 60 seconds
- **Netplan permissions** secured (600)
- **IPv6 disabled** to reduce DNS overhead
- **DNS servers** set to Google (8.8.8.8, 8.8.4.4) and Cloudflare (1.1.1.1)

### 2. Systemd Service Installation

Install systemd services for automatic management:

```bash
cd /home/vinay/pub/IR/deployment
sudo bash install_systemd_services.sh
```

This installs 6 systemd services:
- `ir-all-jobs` - Job scheduler
- `ir-msoar` - MSOAR bot
- `ir-money-ball` - MoneyBall bot
- `ir-toodles` - Toodles bot
- `ir-barnacles` - Barnacles bot
- `ir-jarvais` - Jarvais bot

## Managing Services

### Starting Services

Start all services:
```bash
sudo systemctl start ir-all-jobs ir-msoar ir-money-ball ir-toodles ir-barnacles ir-jarvais
```

Start individual service:
```bash
sudo systemctl start ir-msoar
```

### Stopping Services

Stop all services:
```bash
sudo systemctl stop ir-all-jobs ir-msoar ir-money-ball ir-toodles ir-barnacles ir-jarvais
```

### Checking Status

Check all IR services:
```bash
sudo systemctl status ir-*
```

Check individual service:
```bash
sudo systemctl status ir-msoar
```

### Viewing Logs

View logs in real-time:
```bash
journalctl -u ir-msoar -f
```

View recent logs:
```bash
journalctl -u ir-msoar -n 100
```

View logs from all IR services:
```bash
journalctl -u ir-* -f
```

### Restarting After Code Changes

After pulling new code from git:
```bash
sudo systemctl restart ir-all-jobs ir-msoar ir-money-ball ir-toodles ir-barnacles ir-jarvais
```

## Benefits

### Before
- Manual startup required after every reboot
- No automatic recovery from crashes
- File descriptor limits causing connection issues
- Stale TCP connections after 2+ hours of idle time
- DNS failures requiring manual intervention
- Logs scattered across multiple files

### After
- ✅ Automatic startup on boot
- ✅ Automatic restart on crash (30-second delay)
- ✅ File descriptor limits properly set (65536)
- ✅ TCP connections stay fresh (60-second keepalive)
- ✅ Reliable DNS with explicit servers
- ✅ Centralized logging via journald
- ✅ Easy service management with systemctl

## Verification

After applying fixes, verify the configuration:

### Check File Descriptor Limits
```bash
# Start a new login session, then:
ulimit -n
# Should show: 65536
```

### Check TCP Keepalive
```bash
sysctl net.ipv4.tcp_keepalive_time
sysctl net.ipv4.tcp_keepalive_intvl
sysctl net.ipv4.tcp_keepalive_probes
# Should show: 60, 10, 6
```

### Check DNS Configuration
```bash
resolvectl status
# Should show: 8.8.8.8, 8.8.4.4, 1.1.1.1
```

### Check Services
```bash
sudo systemctl status ir-*
# All should show: active (running)
```

## Rollback (If Needed)

If issues occur, you can revert to manual startup:

```bash
# Stop and disable systemd services
sudo systemctl stop ir-*
sudo systemctl disable ir-*

# Remove service files
sudo rm /etc/systemd/system/ir-*.service
sudo systemctl daemon-reload

# Revert to old DNS (DHCP)
sudo rm /etc/netplan/01-netcfg.yaml
sudo netplan apply

# Revert TCP keepalive
sudo rm /etc/sysctl.d/99-ir-keepalive.conf
sudo sysctl -p

# Use old startup scripts
cd /home/vinay/pub/IR
~/bin/start_all_jobs
~/bin/start_msoar
# etc...
```

## Monitoring

Monitor bot health with:
```bash
# Quick status check
systemctl is-active ir-*

# Detailed status
sudo systemctl status ir-* --no-pager

# Check for recent crashes/restarts
journalctl -u ir-* --since "1 hour ago" | grep -i "started\|stopped\|failed"
```

## Troubleshooting

### Service won't start
```bash
# Check logs for errors
journalctl -u ir-msoar -n 50

# Check if virtual environment exists
ls -la /home/vinay/pub/IR/.venv/bin/python

# Check file permissions
ls -la /home/vinay/pub/IR/webex_bots/msoar.py
```

### DNS issues persist
```bash
# Test DNS resolution
nslookup webexapis.com
dig webexapis.com

# Check actual DNS servers being used
resolvectl status

# Test connectivity to DNS servers
ping -c 3 8.8.8.8
```

### File descriptor errors
```bash
# Check current limit (in running process)
cat /proc/$(pgrep -f msoar.py)/limits | grep "open files"

# Should show: 65536

# If not, restart the service or reboot
```

## Additional Notes

- File descriptor limit requires a new login session or reboot to take effect
- TCP keepalive changes are effective immediately
- Systemd services run with LimitNOFILE=65536 even before reboot
- All services restart automatically on failure after 30 seconds
- Services are enabled to start on boot automatically
