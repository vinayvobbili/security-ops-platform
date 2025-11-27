# all_jobs Scheduler Troubleshooting Summary

## Problem
The all_jobs.py scheduler was failing to send scheduled shift announcements at 12:30 PM ET and 2:00 PM ET. No error logs were being generated.

## Root Cause Analysis

### Primary Issue
**The process was dying silently** without logging any errors. Evidence:
- Process started at 11:33 UTC (7:33 AM ET)
- No activity logged between 7:33 AM and when I investigated at 2:27 PM ET
- Process had completely stopped before 12:30 PM ET scheduled time
- No ERROR level logs captured the failure

### Contributing Factors
1. **Logging level too high** - Set to ERROR, missing WARNING and INFO level diagnostics
2. **No stdout capture** - Print statements weren't being logged
3. **No process monitoring** - No automatic restart when process died
4. **No heartbeat** - Impossible to tell if process was alive without checking `ps`
5. **Python output buffering** - Startup messages weren't immediately written to logs

### Note about 2:00 PM ET
There is **NO 2:00 PM ET scheduled job** in the code. The configured times are:
- 04:30 ET - Morning shift
- 12:30 ET - Afternoon shift
- 20:30 ET - Night shift (8:30 PM)

## Solutions Implemented

### 1. Systemd Service (deployment/all_jobs.service)
- Automatic restart on failure
- 10-second restart delay
- Resource limits: 2GB memory, 200% CPU
- Stdout/stderr capture to logs

### 2. Enhanced Logging (src/all_jobs.py)
- Changed level from ERROR to WARNING
- Added explicit StreamHandler for stdout
- Captures more diagnostic information

### 3. Heartbeat Monitoring (src/all_jobs.py)
- Logs every 5 minutes showing:
  - Current timestamp in ET
  - Number of scheduled jobs
  - Next scheduled run time
- Proves process is alive and functioning

### 4. Startup Script (deployment/start_all_jobs.sh)
- Ensures clean process restart
- Uses Python `-u` flag for unbuffered output
- Proper log file redirection
- Can be run manually or via cron

## Deployment Steps

### Quick Start (Manual)
```bash
ssh lab-vm
cd /home/vinay/pub/IR
./deployment/start_all_jobs.sh
```

### Monitor Logs
```bash
tail -f /home/vinay/pub/IR/logs/all_jobs.log
```

### Install Systemd Service (Requires sudo)
```bash
sudo cp /home/vinay/pub/IR/deployment/all_jobs.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable all_jobs
sudo systemctl start all_jobs
sudo systemctl status all_jobs
```

## Verification

### Check Process Status
```bash
ps aux | grep all_jobs | grep -v grep
```

### Expected Log Output
```
Starting crash-proof job scheduler...
2025-10-31 14:35:49,472 - __main__ - INFO - Initializing security operations scheduler
2025-10-31 14:40:49,123 - __main__ - INFO - Heartbeat - Scheduler alive at 2025-10-31 14:40:49 EDT | Jobs scheduled: 15 | Next run: 2025-10-31 16:30:00
```

### Verify Scheduled Times
The scheduler will next trigger shift announcements at:
- **12:30 PM ET** (16:30 UTC) - Afternoon shift
- **08:30 PM ET** (00:30 UTC) - Night shift
- **04:30 AM ET** (08:30 UTC) - Morning shift

## Future Recommendations

1. **Set up systemd service** - Provides automatic recovery from crashes
2. **Monitor heartbeat logs** - Alert if no heartbeat for >10 minutes
3. **Investigate OOM issues** - Check `dmesg` and `journalctl` for memory-related kills
4. **Add alerting** - Send notification if process dies unexpectedly
5. **Review resource usage** - The process was using 1.2% memory (205MB) which seems normal

## Files Modified/Created

- `src/all_jobs.py` - Enhanced logging and heartbeat
- `deployment/all_jobs.service` - Systemd service definition
- `deployment/start_all_jobs.sh` - Manual startup script
- `deployment/DEPLOYMENT.md` - Detailed deployment instructions
- `deployment/TROUBLESHOOTING_SUMMARY.md` - This file

## Testing Timeline

- **18:35 UTC (2:35 PM ET)** - Process restarted with new code
- **18:40 UTC (2:40 PM ET)** - First heartbeat expected
- **Next shift announcement** - 00:30 UTC Nov 1 (8:30 PM ET Oct 31)
- **Following shift announcement** - 08:30 UTC Nov 1 (4:30 AM ET Nov 1)
- **Critical test** - 16:30 UTC Nov 1 (12:30 PM ET Nov 1)

The scheduler is now running and should remain stable with proper logging for future debugging.
