# Audit Logging Quick Reference

This directory contains scripts to monitor access to your age encryption key.

## Quick Start

### 1. Setup (one-time)
```bash
bash misc_scripts/setup_key_audit.sh
```

This installs `auditd` and configures it to track all access to `~/.config/age/key.txt`.

### 2. Check for suspicious activity
```bash
# View all access
python misc_scripts/check_key_access.py

# View only suspicious
python misc_scripts/check_key_access.py --suspicious

# View summary
python misc_scripts/check_key_access.py --summary
```

### 3. Setup automated alerts (optional)
```bash
# Test first
python misc_scripts/monitor_key_access.py --alert-webex --dry-run

# Add to crontab for hourly checks
crontab -e

# Add this line:
0 * * * * cd /home/vinay/pub/IR && .venv/bin/python misc_scripts/monitor_key_access.py --alert-webex
```

## Scripts Overview

### `setup_key_audit.sh`
- Installs auditd
- Configures audit rules for the key file
- Makes rules persistent across reboots

**Usage:**
```bash
bash misc_scripts/setup_key_audit.sh
```

### `check_key_access.py`
- Views audit logs in a readable format
- Flags suspicious access patterns
- Shows summaries and statistics

**Usage:**
```bash
# All events
python misc_scripts/check_key_access.py

# Only today
python misc_scripts/check_key_access.py --today

# Last 24 hours
python misc_scripts/check_key_access.py --last 24h

# Only suspicious
python misc_scripts/check_key_access.py --suspicious

# Summary only
python misc_scripts/check_key_access.py --summary
```

### `monitor_key_access.py`
- Checks for new suspicious activity
- Sends alerts to Webex/email
- Designed to run via cron

**Usage:**
```bash
# Manual check with Webex alert
python misc_scripts/monitor_key_access.py --alert-webex

# Dry run (no alerts sent)
python misc_scripts/monitor_key_access.py --alert-webex --dry-run

# Custom threshold (alert on 3+ suspicious events)
python misc_scripts/monitor_key_access.py --alert-webex --threshold 3
```

## What's Considered Suspicious?

The scripts flag these patterns:
- ✋ **Root access** - sudo/root user accessing the key
- ✋ **Direct viewing** - `cat`, `less`, `more` on the key
- ✋ **Copy attempts** - `cp`, `scp`, `rsync` on the key
- ✋ **Network tools** - `curl`, `wget`, `nc` accessing the key
- ✋ **Unexpected commands** - anything unusual

**Legitimate access** from your Python application is NOT flagged.

## Example Output

### Normal activity:
```
✓ Event #1
  Time:     2025-01-10 14:32:15
  User:     vinay
  Command:  python
  Exe:      /home/vinay/pub/IR/.venv/bin/python
```

### Suspicious activity:
```
🚨 SUSPICIOUS Event #2
  Time:     2025-01-10 15:45:22
  User:     root
  Command:  cat
  Exe:      /usr/bin/cat
  Flags:    root_access, direct_cat_of_key
```

## Cron Setup Examples

### Check every hour
```bash
0 * * * * cd /home/vinay/pub/IR && .venv/bin/python misc_scripts/monitor_key_access.py --alert-webex
```

### Check every 30 minutes
```bash
*/30 * * * * cd /home/vinay/pub/IR && .venv/bin/python misc_scripts/monitor_key_access.py --alert-webex
```

### Check daily at 9 AM
```bash
0 9 * * * cd /home/vinay/pub/IR && .venv/bin/python misc_scripts/monitor_key_access.py --alert-webex
```

### Check and send email summary daily
```bash
0 8 * * * cd /home/vinay/pub/IR && .venv/bin/python misc_scripts/check_key_access.py --summary --today > /tmp/audit_report.txt && mail -s "Daily Key Access Report" you@example.com < /tmp/audit_report.txt
```

## Troubleshooting

### Audit logs empty?
```bash
# Check if auditd is running
sudo systemctl status auditd

# Check if rule exists
sudo auditctl -l | grep age_key_access

# Test by accessing the key
cat ~/.config/age/key.txt

# Check logs
python misc_scripts/check_key_access.py --last 5m
```

### auditd not installed?
```bash
sudo apt install auditd audispd-plugins
sudo systemctl enable auditd
sudo systemctl start auditd
```

### Permission denied?
All audit commands require `sudo`. The Python scripts handle this automatically.

## Important Notes

### This is Detective, Not Preventive
- ✅ You'll **know** if someone accessed the key
- ✅ You can **investigate** and respond
- ❌ It doesn't **prevent** the access

### Legitimate Access Shows Up Too
Your application legitimately accesses the key every time it starts. Don't be alarmed by:
- Python process accessing the key
- Age command accessing the key
- Your own user account accessing during maintenance

### Performance Impact
Audit logging has minimal performance impact, but:
- Logs can grow over time
- Consider rotating audit logs regularly
- Monitor disk space in `/var/log/audit/`

## Advanced: Manual Audit Queries

Raw auditd commands:

```bash
# View all events
sudo ausearch -k age_key_access -i

# Events since yesterday
sudo ausearch -k age_key_access -ts yesterday -i

# Events from specific user
sudo ausearch -k age_key_access -ui root -i

# Count events
sudo ausearch -k age_key_access | grep -c "type=SYSCALL"
```

## See Also

- [Main Documentation](ENV_ENCRYPTION.md)
- [auditd documentation](https://linux.die.net/man/8/auditd)
- [ausearch documentation](https://linux.die.net/man/8/ausearch)
