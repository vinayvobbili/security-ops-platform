# Retry Utilities

Automatic retry mechanism for handling transient failures in API calls.

## Quick Reference

### Simple Decorator Usage

```python
from src.utils.retry_utils import with_webex_retry

@with_webex_retry(max_attempts=3)
def my_webex_function():
    webex_api.messages.create(roomId=room_id, text="Hello")
```

### Using Messaging Helpers (Recommended)

```python
from src.utils.webex_messaging import send_message, send_message_with_files

# Simple message
send_message(webex_api, room_id, markdown="**Hello**")

# Message with files
send_message_with_files(webex_api, room_id, files=["chart.png"], markdown="Chart!")
```

## Files

- **retry_utils.py** - Core retry decorators and logic
- **webex_messaging.py** - Webex-specific messaging helpers with retry
- **../../tests/test_retry_utils.py** - Unit tests
- **../../docs/retry_mechanism.md** - Full documentation

## Features

- ✅ Automatic retry on transient failures
- ✅ Exponential backoff with jitter
- ✅ Smart exception detection
- ✅ Configurable retry behavior
- ✅ Comprehensive logging
- ✅ 17 unit tests (all passing)

## Configuration

Default settings for Webex retry:
- Max attempts: 3
- Initial delay: 2 seconds
- Max delay: 30 seconds
- Backoff multiplier: 2x
- Jitter: Enabled

## Retries On

- Connection errors (ConnectionError, ConnectionResetError, etc.)
- Timeouts (TimeoutError)
- SSL/TLS errors
- Rate limits (429, 503, 504)
- Proxy-related errors

## Does NOT Retry

- Logic errors (ValueError, TypeError, KeyError)
- Invalid parameters
- Programming errors

## Testing

```bash
python -m pytest tests/test_retry_utils.py -v
```

## Full Documentation

See [docs/retry_mechanism.md](../../docs/retry_mechanism.md) for complete documentation.
