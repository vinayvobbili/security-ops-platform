# Integration Guide: Persistent Sessions & Enhanced Error Recovery

This guide shows how to integrate the new persistent session storage and enhanced error recovery systems into the Pokedx bot.

## Files Created

### 1. Persistent Session Storage
- **File**: `/pokedex_bot/core/session_manager.py` 
- **Purpose**: SQLite-based conversation persistence
- **Features**:
  - 30 messages per session storage
  - 4K character context window 
  - Automatic cleanup (24 hours)
  - Export/import capabilities
  - Health monitoring

### 2. Enhanced Error Recovery
- **File**: `/pokedex_bot/core/error_recovery.py`
- **Purpose**: Graceful tool failure handling
- **Features**:
  - Intelligent retry logic with backoff
  - Context-aware fallback responses
  - Tool availability tracking
  - Graceful degradation

## Integration Steps

### Step 1: Update Imports in my_model.py

Replace the current session management imports:

```python
# OLD - Remove these lines:
from collections import defaultdict, deque
from datetime import datetime, timedelta

# OLD session storage variables - Remove:
conversation_sessions = defaultdict(lambda: deque(maxlen=30))
session_cleanup_interval = timedelta(hours=24)

# OLD session functions - Remove:
def cleanup_old_sessions():
def add_to_session(session_key: str, role: str, content: str):
def get_conversation_context(session_key: str, max_messages: int = 20) -> str:
def get_session_info(session_key: str = None) -> dict:

# NEW - Add these imports:
from my_bot.core.session_manager import get_session_manager
from my_bot.core.error_recovery import get_recovery_manager, enhanced_agent_wrapper
```

### Step 2: Update Session Functions in ask()

Replace the session management calls:

```python
# OLD - Replace these lines:
cleanup_old_sessions()
conversation_context = get_conversation_context(session_key)

# With:
session_manager = get_session_manager()
session_manager.cleanup_old_sessions()
conversation_context = session_manager.get_conversation_context(session_key)
```

### Step 3: Replace Agent Call with Error Recovery

Replace the agent invocation:

```python
# OLD - Replace this section:
agent_result = agent_executor.invoke({"input": agent_input})
if agent_result and 'output' in agent_result:
    final_response = agent_result['output']
    add_to_session(session_key, "user", query)
    add_to_session(session_key, "assistant", final_response)

# With:
recovery_manager = get_recovery_manager()
try:
    final_response = enhanced_agent_wrapper(agent_executor, agent_input, recovery_manager)
    session_manager.add_message(session_key, "user", query)
    session_manager.add_message(session_key, "assistant", final_response)
except Exception as e:
    logger.error(f"Enhanced agent wrapper failed: {e}")
    final_response = recovery_manager.get_fallback_response('general', query)
```

### Step 4: Update Fast Path Session Storage

Replace session storage in fast responses:

```python
# OLD:
add_to_session(session_key, "user", query)
add_to_session(session_key, "assistant", final_response)

# NEW:
session_manager = get_session_manager()
session_manager.add_message(session_key, "user", query)
session_manager.add_message(session_key, "assistant", final_response)
```

## Testing the Integration

### Test Persistent Sessions

1. **Start the bot**
2. **Send a message**: "Hello"
3. **Send follow-up**: "What did I just say?"
4. **Restart the bot**
5. **Send another follow-up**: "Do you remember our conversation?"

**Expected**: Bot should remember conversation context even after restart.

### Test Error Recovery

1. **Simulate CrowdStrike failure** (disconnect network/API)
2. **Ask**: "What's the status of device ABC123?"
3. **Expected**: Helpful fallback message instead of error

### Verify Database Creation

Check that SQLite database is created:
```bash
ls -la /Users/user/PycharmProjects/IR/data/transient/sessions/
# Should see: conversations.db
```

### Check Session Health

Add this debug endpoint to test:

```python
from my_bot.core.session_manager import get_session_manager
session_manager = get_session_manager()
print(session_manager.get_session_info())
```

## Benefits After Integration

### Operational Benefits
- ✅ **Sessions survive restarts** - No lost conversation context
- ✅ **Better error handling** - Helpful messages instead of technical errors  
- ✅ **Automatic recovery** - Tools retry automatically with backoff
- ✅ **Graceful degradation** - Bot stays functional when services are down

### User Experience Benefits
- ✅ **Seamless conversations** - Context maintained across restarts
- ✅ **Professional responses** - No more "Error occurred" messages
- ✅ **Helpful guidance** - Fallback responses guide users to alternatives
- ✅ **Improved reliability** - Bot works even during service outages

### Monitoring Benefits
- ✅ **Tool health visibility** - Track which services are having issues
- ✅ **Session analytics** - Understand conversation patterns
- ✅ **Error tracking** - Monitor failure rates and recovery effectiveness
- ✅ **Performance metrics** - Database queries are indexed and optimized

## Configuration Options

### Session Manager Configuration
```python
# In session_manager.py, you can adjust:
self.max_messages_per_session = 30      # Messages to store
self.session_timeout_hours = 24         # Auto-cleanup interval  
self.max_context_chars = 4000           # Context window size
self.max_context_messages = 20          # Max messages in context
```

### Error Recovery Configuration  
```python
# In error_recovery.py, you can adjust:
self.retry_config = {
    'crowdstrike': {'max_retries': 2, 'delay': 1.0, 'backoff': 2.0},
    'weather': {'max_retries': 3, 'delay': 0.5, 'backoff': 1.5},
    'document_search': {'max_retries': 1, 'delay': 0.5, 'backoff': 1.0}
}
```

## Rollback Plan

If issues arise, you can quickly rollback by:

1. **Comment out new imports**
2. **Restore old session functions** from git history
3. **Remove enhanced_agent_wrapper calls**
4. **Restart bot**

The old in-memory system will continue working as before.

## Next Steps

After successful integration:

1. **Monitor performance** - Check database query performance
2. **Tune configurations** - Adjust retry/timeout settings based on usage
3. **Add monitoring dashboards** - Track tool health and session usage
4. **Consider additional tools** - Add error recovery for other integrations
5. **Implement session export** - For conversation analytics or backup

## Support

- **Session issues**: Check SQLite database permissions and disk space
- **Import errors**: Verify file paths match your directory structure  
- **Recovery issues**: Check tool configurations and network connectivity
- **Performance**: Monitor database size and consider periodic cleanup