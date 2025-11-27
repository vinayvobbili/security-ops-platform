# Deployment Instructions for all_jobs Scheduler

## Manual Deployment Steps

1. **Pull latest code on VM:**
   ```bash
   ssh lab-vm
   cd /home/vinay/pub/IR
   git pull
   ```

2. **Stop current process:**
   ```bash
   pkill -f all_jobs.py
   ```

3. **Test the updated script:**
   ```bash
   cd /home/vinay/pub/IR
   .venv/bin/python src/all_jobs.py
   ```
   You should see:
   - "Starting crash-proof job scheduler..."
   - "Initializing security operations scheduler" log entry
   - Heartbeat logs every 5 minutes

4. **Install systemd service (requires sudo):**
   ```bash
   sudo cp /home/vinay/pub/IR/deployment/all_jobs.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable all_jobs
   sudo systemctl start all_jobs
   ```

5. **Verify service is running:**
   ```bash
   sudo systemctl status all_jobs
   ```

6. **Monitor logs:**
   ```bash
   tail -f /home/vinay/pub/IR/logs/all_jobs.log
   ```

## What's Changed

### Logging Improvements
- Changed level from ERROR to WARNING for better visibility
- Added stdout handler to capture print statements
- Heartbeat logs every 5 minutes showing:
  - Current timestamp in ET
  - Number of scheduled jobs
  - Next scheduled run time

### Process Monitoring
- systemd service with automatic restart on failure
- Restart delay: 10 seconds
- Resource limits: 2GB memory, 200% CPU
- Logs automatically appended to logs/all_jobs.log

### Expected Log Output
```
2025-10-31 14:30:00,123 - __main__ - INFO - Initializing security operations scheduler
2025-10-31 14:35:00,456 - __main__ - INFO - Heartbeat - Scheduler alive at 2025-10-31 14:35:00 EDT | Jobs scheduled: 15 | Next run: 2025-10-31 16:30:00
2025-10-31 14:40:00,789 - __main__ - INFO - Heartbeat - Scheduler alive at 2025-10-31 14:40:00 EDT | Jobs scheduled: 15 | Next run: 2025-10-31 16:30:00
```

## Troubleshooting

### If service won't start:
```bash
sudo journalctl -u all_jobs -n 50
```

### If you see OOM kills:
```bash
sudo dmesg | grep -i oom
```

### To manually run without systemd:
```bash
cd /home/vinay/pub/IR
nohup .venv/bin/python src/all_jobs.py >> logs/all_jobs.log 2>&1 &
```

## Scheduled Times (All in ET)

- **00:01 ET** - Daily chart generation
- **04:30 ET** - Morning shift announcement
- **07:00 ET** - Daily thithi check
- **08:00 ET (Mon)** - On-call change announcement
- **08:00 ET (Fri)** - Weekly efficacy reports
- **12:30 ET** - Afternoon shift announcement
- **14:00 ET (Fri)** - On-call change alert
- **17:00 ET** - Remove expired security test entries
- **20:30 ET** - Night shift announcement
- **Every 1 min** - Response SLA risk monitoring
- **Every 3 min** - Containment SLA risk monitoring
- **Every 5 min** - Host verification checks
- **Every hour** - Incident declaration SLA risk monitoring
