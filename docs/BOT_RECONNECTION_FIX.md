# Toodles Bot Reconnection Fix

## Problem Summary

The Toodles bot was configured with resilience features (proactive reconnection, auto-reconnect on errors), but **it wasn't staying up 24x7**. When a reconnection was triggered, the bot would hang indefinitely and never actually restart.

### Symptoms (from logs)
```
2025-11-04 08:59:57 - 🔄 Triggering Toodles reconnection: Proactive reconnection
2025-11-04 09:00:07 - Bot instance cleared for Toodles
[NOTHING FOR 3+ HOURS - BOT STUCK]
2025-11-04 12:12:05 - [Bot eventually responds to messages, but no proper restart logged]
```

Pattern repeated multiple times throughout Nov 4-5.

## Root Cause

In `src/utils/bot_resilience.py`, the `_run_bot_with_monitoring()` method was calling `bot.run()` and expecting it to return when the WebSocket was closed for reconnection. However:

1. When reconnection was triggered, the WebSocket was closed
2. But `bot.run()` **never returned** - it hung indefinitely
3. The main reconnection loop was **stuck waiting** for `bot.run()` to exit
4. No restart could occur because the main thread was blocked

## Solution

Modified `_run_bot_with_monitoring()` to:

1. **Run bot in a separate thread** - allows main thread to monitor it
2. **Create asyncio event loop** for bot thread (Python 3.12+ requirement)
3. **Main thread actively monitors** `_reconnection_needed` flag every second
4. **When reconnection is requested**, main thread detects it immediately and:
   - Waits up to 10 seconds for bot thread to exit gracefully
   - Logs warning if thread doesn't exit cleanly
   - Returns control to reconnection loop
5. **Reconnection loop restarts the bot** with fresh connection

### Key Code Changes

**Before** (src/utils/bot_resilience.py:381-391):
```python
def _run_bot_with_monitoring(self):
    try:
        # Just run the bot directly
        self.bot_instance.run()  # <-- BLOCKS FOREVER IF WEBSOCKET DOESN'T EXIT CLEANLY
    except Exception as e:
        logger.error(f"Error running {self.bot_name}: {e}")
        raise
```

**After** (src/utils/bot_resilience.py:381-432):
```python
def _run_bot_with_monitoring(self):
    # Run bot in separate thread
    def run_bot():
        # Create event loop for thread (Python 3.12+)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self.bot_instance.run()

    bot_thread = threading.Thread(target=run_bot, daemon=False)
    bot_thread.start()

    # Monitor bot thread AND reconnection flag
    while bot_running.is_set() and not self._reconnection_needed and not self.shutdown_requested:
        time.sleep(1)  # Check every second

    # If reconnection requested, wait for thread to exit
    if self._reconnection_needed:
        bot_thread.join(timeout=10)
        # Control returns to main loop for restart
```

## Expected Behavior After Fix

When a reconnection is triggered (either proactively every 10 minutes, or due to connection errors):

```
[Trigger] 🔄 Triggering Toodles reconnection: [reason]
[Wait]    Forcing shutdown of Toodles for reconnection...
[Wait]    Waiting 10s for complete connection cleanup...
[Clear]   Bot instance cleared for Toodles
[Restart] 🚀 Starting Toodles (attempt N/5)
[Ready]   🚀 Toodles is up and running (startup in X.Xs)...
```

**Total time: ~15-30 seconds** (not hours!)

## Monitoring the Fix

Use the monitoring script:
```bash
./monitor_bot_reconnections.sh
```

Or manually check logs:
```bash
ssh lab-vm "grep -E '(Triggering.*reconnection|Bot instance cleared|up and running)' ~/pub/IR/logs/toodles.log | tail -20"
```

### What to Look For

✅ **Good** (fix working):
- Reconnection triggered
- Bot instance cleared
- "up and running" within 30 seconds
- No long gaps between these events

❌ **Bad** (fix not working):
- Reconnection triggered
- Bot instance cleared
- Long silence (minutes/hours)
- No "up and running" message

## Current Status

- **Fix deployed:** 2025-11-05 08:47:44
- **Bot PID:** 59079 (on lab-vm)
- **Current uptime:** See monitoring script
- **Next proactive reconnection:** Every 600 seconds (10 minutes)

The bot will proactively reconnect every 10 minutes to prevent proxy timeouts. Each reconnection should complete in ~15-30 seconds.

## Testing Plan

1. **Passive monitoring** (recommended):
   - Run `./monitor_bot_reconnections.sh` every few hours
   - Verify bot stays up 24x7
   - Check reconnections complete quickly

2. **Active testing** (if needed):
   - Wait for next proactive reconnection (every 10 min)
   - Watch logs during reconnection
   - Verify "up and running" appears within 30s

3. **Stress testing** (optional):
   - Simulate connection errors by temporarily blocking network
   - Verify bot reconnects automatically
   - Check logs show clean restart cycle

## Rollback Plan

If the fix causes issues:

```bash
ssh lab-vm "cd ~/pub/IR && git checkout cc772c6e src/utils/bot_resilience.py"
ssh lab-vm "cd ~/pub/IR && pkill -f 'python.*toodles' && nohup .venv/bin/python webex_bots/toodles.py >> logs/toodles.log 2>&1 &"
```

(This reverts to the previous version before the threading fix)

## Additional Notes

- **Python version compatibility:** Fix tested on Python 3.12.3 (VM) and 3.13 (local)
- **Asyncio event loop:** Required for Python 3.10+ threading behavior
- **No functional changes:** Bot commands and features unchanged
- **Performance:** Negligible overhead from threading (bot runs in separate thread anyway)

## Commit Info

- **Commit:** 68c12edf
- **Message:** "Fix bot reconnection hanging issue"
- **Files changed:** src/utils/bot_resilience.py (65 additions, 6 deletions)
