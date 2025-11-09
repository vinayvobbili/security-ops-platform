# WebSockets 14.2 Canary Deployment - Critical Test Tomorrow

**Date Started**: 2025-11-08 17:29 EST
**Status**: 🧪 CANARY TESTING IN PROGRESS
**Critical Test**: Tomorrow morning (2025-11-09) after 8+ hours idle

---

## 🎯 Quick Start (If Session Lost)

**Tell Claude/Gemini in the morning:**

> "Check the websockets 14.2 canary test status. I'm about to send the first message to Barnacles after overnight idle. Help me monitor and decide next steps based on docs/WEBSOCKETS_14.2_CANARY_TEST.md"

---

## 📋 What We Did Today (2025-11-08)

### Problem Being Solved

**Bots fail to respond to the FIRST message after long idle periods** (8+ hours). Second message always works. This suggests stale WebSocket connections.

### Root Cause Investigation

1. **Discovered**: Bots had keepalive pings, but only tested REST API (not WebSocket message channel)
2. **Found**: websockets 11.0.3 (May 2023) has known bugs causing stale connections
3. **Identified**: websockets 14.2 (Jan 2025) has critical fixes for our exact symptoms

### Solutions Implemented

#### Layer 1: More Aggressive WebSocket Pings ✅

- **Changed**: `ping_interval` from 30s → **10s** (3x more frequent)
- **Changed**: `ping_timeout` from 15s → **5s** (fail faster)
- **File**: `src/utils/enhanced_websocket_client.py`
- **Commit**: `c4121c18`

#### Layer 2: Proactive Reconnection ✅

- **Added**: `max_connection_age_hours` parameter (default: 12 hours)
- **Behavior**: Bot auto-reconnects every 12h even if healthy
- **File**: `src/utils/bot_resilience.py`
- **Commit**: `c4121c18`

#### Layer 3: Package Upgrades ✅

- **webex_bot**: Upgraded from 1.0.5 → **1.0.8** (local & VM synced)
- **websockets**: Canary test 11.0.3 → **14.2** (Barnacles only)
- **Commits**: `b4443b07`, `d53c2e15`, `b5b94a9d`

#### Layer 4: API Compatibility Fix ✅

- **Problem**: websockets 12.0+ changed API (`extra_headers` → `additional_headers`)
- **Solution**: Auto-detect version and use correct parameter name
- **File**: `src/utils/enhanced_websocket_client.py` (lines 133-143)
- **Commit**: `d53c2e15`

---

## 🔬 WebSockets 14.2 Critical Bug Fixes

These bugs in 11.0.3 could be causing the "first message lost" symptom:

### Version 14.2 (January 2025)

```
✅ Prevents close() from blocking when network becomes unavailable
   or when receive buffers are saturated

✅ Fixes recv() with timeout=0 - If message already received, return it
   (Previously raised TimeoutError incorrectly)
```

### Version 14.1 (November 2024)

```
✅ Once connection is closed, messages previously received and buffered
   can be read (just like legacy implementation)
```

### Version 13.1 (September 2024)

```
✅ Fixed bug in threading implementation that could prevent program
   from exiting when connection wasn't closed properly

✅ Redirecting from ws:// URI to wss:// URI now works
```

**These are EXACTLY the symptoms we're experiencing!**

---

## 📦 Current Deployment Status

### On VM (metcirt-lab)

| Bot           | webex_bot | websockets | Status     | Purpose         |
|---------------|-----------|------------|------------|-----------------|
| **Barnacles** | 1.0.8     | **14.2**   | 🧪 Running | **CANARY TEST** |
| Toodles       | 1.0.8     | 11.0.3     | ⏸️ Running | Baseline        |
| MoneyBall     | 1.0.8     | 11.0.3     | ⏸️ Running | Baseline        |
| Jarvis        | 1.0.8     | 11.0.3     | ⏸️ Running | Baseline        |
| MSOAR         | 1.0.8     | 11.0.3     | ⏸️ Running | Baseline        |

### Git Commits (Pushed to GitHub)

```
b5b94a9d - Allow websockets 11.0.3 to 14.x upgrade in requirements.txt
d53c2e15 - Add websockets 12.0+ API compatibility to enhanced_websocket_client
b4443b07 - Update webex_bot to 1.0.8 and pin websockets version
c4121c18 - Enhance bot resilience to prevent stale connection issues
```

All on branch: `main`

---

## 🧪 CRITICAL TEST - Tomorrow Morning (2025-11-09)

### The Test

**After 8+ hours of idle time:**

1. **Send FIRST message to Barnacles** via Webex
    - Simple message: "hi" or "status"

2. **Observe behavior:**
    - ✅ **SUCCESS**: Bot responds to first message immediately
    - ❌ **FAILURE**: First message ignored, second message works (same as before)

### Why This Test Matters

This is when stale connections manifest. The connection appears "alive" (TCP connected, pings working) but the backend has stopped routing messages. Our hypothesis:

- **Old behavior (11.0.3)**: WebSocket appears connected but is functionally dead → first message lost
- **New behavior (14.2)**: Bug fixes prevent stale connections → first message works

### Monitoring Commands

```bash
# 1. Check Barnacles is still running
ssh metcirt-lab 'ps aux | grep barnacles.py | grep -v grep'

# 2. Verify websockets version
ssh metcirt-lab 'cd ~/pub/IR && .venv/bin/pip show websockets | grep Version'
# Expected: Version: 14.2

# 3. Check for errors BEFORE sending test message
ssh metcirt-lab 'tail -50 ~/pub/IR/logs/barnacles.log | grep -E "ERROR|WARNING|Connection"'

# 4. Watch logs while sending test message
ssh metcirt-lab 'tail -f ~/pub/IR/logs/barnacles.log'

# 5. After test - check message handling
ssh metcirt-lab 'tail -100 ~/pub/IR/logs/barnacles.log | grep -E "Message|ERROR|WARNING"'
```

### Expected Log Evidence

**If test PASSES**, you should see:

```
2025-11-09 [TIME] - INFO - [Received message from user]
2025-11-09 [TIME] - INFO - [Bot processing command]
2025-11-09 [TIME] - INFO - [Bot sent response]
```

**If test FAILS**, you might see:

```
2025-11-09 [TIME] - ERROR - Connection error / timeout
2025-11-09 [TIME] - INFO - Triggering reconnection
2025-11-09 [TIME] - INFO - WebSocket Opened with keepalive enabled
```

---

## 🔄 Next Steps Based on Results

### ✅ If Test PASSES (First message works!)

**Action**: Rollout websockets 14.2 to all bots

```bash
# 1. Upgrade websockets on VM
ssh metcirt-lab 'cd ~/pub/IR && .venv/bin/pip install "websockets>=14.2,<15.0" -q'

# 2. Restart each bot (one at a time with 2-minute gaps)
ssh metcirt-lab 'ps aux | grep "toodles.py" | grep python | grep -v grep | awk "{print \$2}" | xargs kill'
ssh metcirt-lab 'cd ~/pub/IR && PYTHONPATH=. nohup .venv/bin/python webex_bots/toodles.py > logs/toodles.log 2>&1 &'

# Wait 2 minutes, verify Toodles works, then continue with next bot...

# 3. Verify all bots running
ssh metcirt-lab 'for bot in barnacles toodles money_ball jarvis msoar; do \
  echo "=== $bot ==="; \
  .venv/bin/pip show websockets | grep Version; \
  ps aux | grep "${bot}.py" | grep -v grep; \
done'

# 4. Update local environment
.venv/bin/pip install "websockets>=14.2,<15.0"

# 5. Commit if needed
git add -u
git commit -m "Complete websockets 14.2 rollout after successful canary test"
git push origin main
```

**Then**: Monitor for a week to ensure stability.

### ❌ If Test FAILS (Still needs second message)

**Action**: Rollback Barnacles to 11.0.3, investigate further

```bash
# 1. Rollback websockets
ssh metcirt-lab 'cd ~/pub/IR && .venv/bin/pip install websockets==11.0.3 -q'

# 2. Restart Barnacles
ssh metcirt-lab 'ps aux | grep "barnacles.py" | grep python | grep -v grep | awk "{print \$2}" | xargs kill'
ssh metcirt-lab 'cd ~/pub/IR && PYTHONPATH=. nohup .venv/bin/python webex_bots/barnacles.py > logs/barnacles.log 2>&1 &'

# 3. Verify rollback
ssh metcirt-lab 'cd ~/pub/IR && .venv/bin/pip show websockets | grep Version'
# Expected: Version: 11.0.3
```

**Then**: We still have Layers 1 & 2 (10s pings, 12h reconnect) which should help. May need deeper investigation.

---

## 🐛 Troubleshooting

### Barnacles Not Responding at All

```bash
# Check if bot is running
ssh metcirt-lab 'ps aux | grep barnacles.py | grep -v grep'

# Check recent logs
ssh metcirt-lab 'tail -50 ~/pub/IR/logs/barnacles.log'

# Look for crash/error
ssh metcirt-lab 'tail -200 ~/pub/IR/logs/barnacles.log | grep -i "error\|exception\|traceback" | tail -20'

# If crashed, restart with 11.0.3
ssh metcirt-lab 'cd ~/pub/IR && .venv/bin/pip install websockets==11.0.3 -q'
ssh metcirt-lab 'cd ~/pub/IR && PYTHONPATH=. nohup .venv/bin/python webex_bots/barnacles.py > logs/barnacles.log 2>&1 &'
```

### Check Connection Health

```bash
# Check WebSocket connection established
ssh metcirt-lab 'tail -100 ~/pub/IR/logs/barnacles.log | grep -i "websocket opened\|connection\|keepalive"'

# Check for reconnections (should see pattern of disconnects/reconnects if unstable)
ssh metcirt-lab 'grep -i "reconnection\|websocket opened" ~/pub/IR/logs/barnacles.log | tail -20'
```

### Verify All Enhancements Active

```bash
# Should see "10s ping interval" in logs
ssh metcirt-lab 'grep "10s ping interval" ~/pub/IR/logs/barnacles.log | tail -1'

# Should see "Keepalive monitoring active"
ssh metcirt-lab 'grep "Keepalive monitoring active" ~/pub/IR/logs/barnacles.log | tail -1'
```

---

## 📊 Session Context for AI Assistants

### Files Modified

```
src/utils/bot_resilience.py           - Resilience enhancements
src/utils/enhanced_websocket_client.py - WebSocket compatibility & pings
requirements.txt                        - Package version updates
```

### Key Code Locations

**10s ping configuration:**

- `src/utils/enhanced_websocket_client.py:128` - `ping_interval: 10`
- `src/utils/bot_resilience.py:123` - `kwargs.setdefault('ping_interval', 10)`

**12h proactive reconnection:**

- `src/utils/bot_resilience.py:230-236` - Connection age check

**Version compatibility:**

- `src/utils/enhanced_websocket_client.py:133-143` - Auto-detect extra_headers vs additional_headers

### Why We Chose Canary Approach

1. **Risk mitigation**: Test on 1 bot before impacting all 5
2. **Quick rollback**: Can revert single bot in <2 minutes if issues
3. **Clear comparison**: 4 bots on 11.0.3 provide baseline behavior
4. **Real-world test**: Overnight idle is the exact failure scenario

---

## 📞 Quick Reference

### Bot Locations

- **Repository**: github.com:vinayvobbili/IR.git
- **VM**: metcirt-lab (inr106)
- **Path**: ~/pub/IR
- **Logs**: ~/pub/IR/logs/

### Important Processes

```bash
# View all running bots
ssh metcirt-lab 'ps aux | grep "webex_bots/" | grep python | grep -v grep'

# Check specific bot uptime
ssh metcirt-lab 'ps -o etime,cmd -p $(pgrep -f barnacles.py)'
```

### Log Viewer URLs (if configured)

```
http://[VM_IP]:8036  # Barnacles log viewer
http://[VM_IP]:8035  # Jarvis log viewer
http://[VM_IP]:8034  # MoneyBall log viewer
http://[VM_IP]:8033  # MSOAR log viewer
http://[VM_IP]:8032  # Toodles log viewer
```

---

## 🎯 Success Metrics

**Short-term (Tomorrow)**:

- ✅ Barnacles responds to first message after 8+ hour idle
- ✅ No WebSocket connection errors in logs
- ✅ No emergency reconnections triggered

**Medium-term (1 week)**:

- ✅ All bots respond to first message consistently
- ✅ No increase in reconnection frequency
- ✅ Proactive 12h reconnections happening smoothly

**Long-term**:

- ✅ Zero "first message lost" incidents
- ✅ Stable connections lasting full 12h between proactive reconnects
- ✅ WebSocket pings preventing any stale connections

---

## 💡 Background Reading

### Related Docs

- `docs/connection-health-improvements.md` - Previous connection work
- `docs/ROOT_CAUSE_ANALYSIS.md` - Historical debugging
- `docs/retry_mechanism.md` - Retry patterns

### External References

- [websockets changelog](https://websockets.readthedocs.io/en/stable/project/changelog.html)
- [webex_bot GitHub](https://github.com/fbradyirl/webex_bot)

---

**Last Updated**: 2025-11-08 22:40 EST
**Next Milestone**: First message test after overnight idle (2025-11-09 morning)
**Owner**: Vinay
**Status**: ⏰ WAITING FOR CRITICAL TEST
