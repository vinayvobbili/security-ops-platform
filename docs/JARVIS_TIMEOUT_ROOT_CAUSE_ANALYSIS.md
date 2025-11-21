# Jarvis Bot Timeout Issue - Root Cause Analysis

**Date**: 2025-11-21
**Investigated By**: Claude Code
**Issue**: Jarvis bot experiencing frequent 60-second timeout errors on VM

## Executive Summary

The Jarvis bot (and other bots on the VM) were experiencing **1,338+ timeout errors** due to **connection pool exhaustion**. The default 10-connection pool was insufficient for 6 concurrent bots processing WebSocket messages with thread pools.

**Fix**: Increased connection pool from 10 → 50 and added automatic retry logic.

---

## Root Cause Analysis

### Symptoms
- 60-second timeout errors when processing WebSocket messages
- Error: `ReadTimeout: HTTPSConnectionPool(host='webexapis.com', port=443): Read timed out. (read timeout=60)`
- Occurring in `enhanced_websocket_client.py` when calling `messages.get()`
- 686 timeout errors in jarvis.log alone
- 1,338 total timeout errors across all bot logs

### Environment
- **VM**: inr106 (metcirt-lab)
- **OS**: Ubuntu Linux 6.8.0-87-generic
- **Running Bots**: 6 simultaneous bots
  1. jarvis.py (PID 291824) - 474MB RAM
  2. tars.py (PID 294276)
  3. toodles.py (PID 291706)
  4. barnacles.py (PID 291737)
  5. money_ball.py (PID 291770)
  6. msoar.py (PID 291797)

### Network Performance
Basic network connectivity to Webex is **FAST**:
```
- DNS lookup: 0.001s
- TCP connect: 0.109s
- SSL handshake: 0.375s
- Total time: 0.484s
```

API calls in isolation work fine (0.06-0.68s). The issue is **NOT** network latency.

### The Real Problem: Connection Pool Exhaustion

#### Default Configuration
```python
webex_api = WebexTeamsAPI(access_token=token)
# Uses default requests.adapters.HTTPAdapter:
#   pool_connections: 10
#   pool_maxsize: 10
#   max_retries: 0
```

#### Why It Failed
1. **Multiple API instances per bot**:
   - Main bot code creates one WebexTeamsAPI instance
   - WebSocket client creates ANOTHER instance internally
   - Each has its own 10-connection pool

2. **Concurrent message processing**:
   - WebSocket messages are processed in thread pool executor
   - Each thread calls `messages.get()` to fetch message details
   - Multiple threads compete for same 10-connection pool

3. **Connection stalls**:
   - Connections can become stale/stuck
   - requests library doesn't have aggressive connection recycling
   - New requests wait for available connection
   - After 60 seconds → timeout

4. **6 bots amplify the problem**:
   - 6 bots × 2 API instances × 10 connections = 120 potential connections
   - All competing for limited resources
   - Measured: 32 established HTTPS connections to Webex

### Timeline
- **2025-11-16 19:06**: First timeout logged
- **2025-11-21 15:25**: ReadTimeout during message processing
- **2025-11-21 15:34**: Connection aborted with RemoteDisconnected
- **Total**: 5+ days of intermittent failures

---

## Solution Implemented

### 1. Created Connection Pool Configuration Utility

**File**: `src/utils/webex_pool_config.py`

```python
def configure_webex_api_session(api_instance,
                                pool_connections=50,
                                pool_maxsize=50,
                                max_retries=3):
    """Configure larger connection pool and retry logic"""
    session = api_instance._session._req_session

    retry_strategy = Retry(
        total=max_retries,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "PUT", "DELETE"]
    )

    adapter = HTTPAdapter(
        pool_connections=pool_connections,  # 10 → 50
        pool_maxsize=pool_maxsize,          # 10 → 50
        max_retries=retry_strategy,         # 0 → 3
        pool_block=False
    )

    session.mount("https://", adapter)
    return api_instance
```

### 2. Updated Jarvis Bot Configuration

**File**: `webex_bots/jarvis.py` (lines 57-72)

```python
from src.utils.webex_pool_config import configure_webex_api_session

webex_api = configure_webex_api_session(
    WebexTeamsAPI(
        access_token=CONFIG.webex_bot_access_token_jarvis,
        single_request_timeout=120,  # Increased from 60s
    ),
    pool_connections=50,  # Increased from 10
    pool_maxsize=50,      # Increased from 10
    max_retries=3         # Enable automatic retry
)
```

### 3. Verified Configuration

**Before**:
```
Pool connections: 10
Pool maxsize: 10
Max retries: Retry(total=0, ...)
```

**After**:
```
Pool connections: 50
Pool maxsize: 50
Max retries: Retry(total=3, ...)
API call successful in 1.61s
```

---

## Deployment Steps

### 1. Applied to Jarvis (COMPLETED)
```bash
scp src/utils/webex_pool_config.py vinay@metcirt-lab:/home/vinay/pub/IR/src/utils/
scp webex_bots/jarvis.py vinay@metcirt-lab:/home/vinay/pub/IR/webex_bots/
```

### 2. Restart Jarvis Bot
```bash
ssh vinay@metcirt-lab
cd /home/vinay/pub/IR
pkill -f "python.*jarvis.py"  # Stop old version
nohup .venv/bin/python webex_bots/jarvis.py > /dev/null 2>&1 &  # Start with new config
```

### 3. Apply to Other Bots (RECOMMENDED)
The following bots should also be updated:
- tars.py
- toodles.py
- barnacles.py
- money_ball.py
- msoar.py

**Update pattern for each bot**:
```python
# Add import
from src.utils.webex_pool_config import configure_webex_api_session

# Wrap existing WebexTeamsAPI creation
webex_api = configure_webex_api_session(
    WebexTeamsAPI(access_token=CONFIG.webex_bot_access_token_XXX, single_request_timeout=120),
    pool_connections=50,
    pool_maxsize=50,
    max_retries=3
)
```

---

## Monitoring & Validation

### Check for Timeout Errors
```bash
ssh vinay@metcirt-lab
cd /home/vinay/pub/IR/logs
grep -c "Read timed out" jarvis.log  # Should stop increasing after fix
tail -f jarvis.log | grep -i timeout  # Watch for new timeouts
```

### Monitor Connection Pool Health
```bash
# Count established connections
ss -tn state established '( dport = :443 )' | grep '170.72.245' | wc -l

# Check bot process stats
ps aux | grep 'python.*webex_bots'
```

### Expected Results
- **Timeout errors**: Should drop to near-zero
- **Connection count**: May increase slightly (50 vs 10 max) but won't exhaust
- **Bot stability**: More resilient to transient network issues (3 retries)

---

## Additional Recommendations

### 1. Consider Single Shared API Instance
Instead of each bot creating its own API instance, consider a shared instance:
```python
# Global shared instance with large pool
_shared_webex_api = None

def get_webex_api():
    global _shared_webex_api
    if _shared_webex_api is None:
        _shared_webex_api = configure_webex_api_session(
            WebexTeamsAPI(access_token=token),
            pool_connections=100,
            pool_maxsize=100
        )
    return _shared_webex_api
```

### 2. Monitor VM Resource Limits
- Current: 32 HTTPS connections across 6 bots
- After fix: Could reach 50 per bot × 6 = 300 connections
- Verify VM has sufficient file descriptors: `ulimit -n`

### 3. Enable Connection Pool Logging (Debug)
```python
import logging
logging.getLogger("urllib3.connectionpool").setLevel(logging.DEBUG)
```

---

## Conclusion

The 60-second timeout errors were caused by **connection pool exhaustion**, not network latency. By increasing the pool size from 10 → 50 and adding retry logic, the bots should now handle concurrent WebSocket message processing without timeouts.

**Next Steps**:
1. ✅ Deploy fix to jarvis.py
2. ⏳ Restart jarvis bot with new configuration
3. ⏳ Monitor logs for 24-48 hours
4. ⏳ If successful, apply to remaining 5 bots
5. ⏳ Consider shared API instance for further optimization
