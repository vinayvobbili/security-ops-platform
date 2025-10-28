# Connection Health Improvements for MoneyBall Bot

**Date:** 2025-10-28
**Bot:** MoneyBall
**Issue:** ReadTimeout and Connection Aborted errors

## Changes Made

### 1. Increased API Timeout (webex_bots/money_ball.py)

**Before:**
```python
webex_api = WebexTeamsAPI(access_token=config.webex_bot_access_token_moneyball)
```

**After:**
```python
webex_api = WebexTeamsAPI(
    access_token=config.webex_bot_access_token_moneyball,
    single_request_timeout=120,  # Increased from default 60s to 120s
    wait_on_rate_limit=True
)
```

**Impact:**
- Reduces timeout errors for slow network conditions or large file uploads
- Better handles proxy (ZScaler) latency
- Prevents premature timeouts during chart uploads

### 2. Added Connection Health Monitoring

**New Module:** `src/utils/connection_health.py`

Features:
- Tracks success/failure rates for all API requests
- Records response times (min/avg/max)
- Monitors timeout frequency
- Counts reconnection events
- Provides periodic health summaries (every 5 minutes)
- Thread-safe metrics collection

**Usage:**
```python
from src.utils.connection_health import ConnectionHealthMonitor

monitor = ConnectionHealthMonitor(bot_name="MoneyBall")
monitor.record_request_success(duration=1.2)
monitor.record_request_timeout(duration=60.0)
monitor.log_summary()
```

### 3. Integrated Health Monitoring into Bot Framework

**Modified:** `src/utils/bot_resilience.py`

- Health monitor automatically created on bot startup
- Tracks all reconnection events with reasons
- Monitors keepalive ping health
- Records connection errors by type
- Logs periodic summaries during operation

### 4. Enhanced Webex Messaging with Metrics

**Modified:** `src/utils/webex_messaging.py`

- All message sends tracked for success/failure
- Response times recorded
- Timeout vs connection errors differentiated
- Automatic periodic health summaries

## Expected Benefits

### Reduced Errors
- 120s timeout accommodates network latency and proxy delays
- Should see fewer timeout errors in logs

### Better Visibility
- Periodic health summaries logged every 5 minutes
- Example log output:
  ```
  📊 [MoneyBall] Connection Health Summary:
    Uptime: 1:23:45
    Total Requests: 247
    Success Rate: 94.3% (overall) | 98.0% (recent 100)
    Successful: 233 | Failed: 14
    Timeouts: 8 | Connection Errors: 6
    Reconnections: 3
    Response Time: avg=2.34s | min=0.45s | max=15.67s
    Last Success: 12.3s ago
    Error Types: {'ReadTimeout': 8, 'ConnectionAbortedError': 4, 'RemoteDisconnected': 2}
  ```

### Proactive Monitoring
- Health metrics help identify patterns
- Can detect degrading performance before failures
- Easier troubleshooting with detailed error breakdown

## Testing

All components tested successfully:
- ✅ Connection health monitor working
- ✅ Health metrics tracked correctly
- ✅ Integration with webex_messaging verified
- ✅ MoneyBall configuration updated
- ✅ Imports and dependencies validated

## Next Steps

1. **Deploy the changes** - Restart MoneyBall bot to apply new timeout settings
2. **Monitor logs** - Watch for health summaries every 5 minutes
3. **Verify improvement** - Check if timeout frequency decreases
4. **Review metrics** - Use health data to identify remaining issues

## Monitoring Commands

Check recent logs:
```bash
tail -100 /Users/user/PycharmProjects/IR/logs/money_ball.log | grep "Connection Health Summary"
```

Check for timeout errors:
```bash
tail -500 /Users/user/PycharmProjects/IR/logs/money_ball.log | grep -i timeout
```

Check reconnection events:
```bash
tail -500 /Users/user/PycharmProjects/IR/logs/money_ball.log | grep "Reconnection #"
```

## Files Modified

1. `webex_bots/money_ball.py` - Increased API timeout
2. `src/utils/connection_health.py` - **NEW** - Health monitoring module
3. `src/utils/bot_resilience.py` - Integrated health tracking
4. `src/utils/webex_messaging.py` - Added metrics collection

## Rollback Instructions

If needed, revert to previous timeout:
```python
webex_api = WebexTeamsAPI(access_token=config.webex_bot_access_token_moneyball)
```

The health monitoring is non-invasive and can be left in place even if reverting timeout changes.
