# Retry Mechanism Documentation

## Overview

The retry mechanism provides automatic retry logic for transient failures in Webex API calls and other network operations. It uses exponential backoff with jitter to avoid thundering herd problems.

## Features

- **Automatic Retries**: Automatically retries failed operations on transient errors
- **Exponential Backoff**: Delays between retries increase exponentially to give services time to recover
- **Jitter**: Random jitter prevents multiple clients from retrying simultaneously
- **Smart Exception Detection**: Distinguishes between retryable and non-retryable errors
- **Configurable**: Fully configurable retry behavior (attempts, delays, backoff multiplier)
- **Callbacks**: Optional callbacks for retry and failure events
- **Logging**: Comprehensive logging of retry attempts and failures

## Quick Start

### Basic Usage with Decorator

```python
from src.utils.retry_utils import with_retry

@with_retry(max_attempts=3, initial_delay=1.0)
def my_api_call():
    # Your API call here
    response = api.do_something()
    return response
```

### Webex-Specific Retry

For Webex API calls, use the specialized `with_webex_retry` decorator:

```python
from src.utils.retry_utils import with_webex_retry

@with_webex_retry(max_attempts=3)
def send_notification(room_id, message):
    webex_api.messages.create(roomId=room_id, text=message)
```

### Using Webex Messaging Helpers

The easiest way is to use the pre-built messaging helpers:

```python
from src.utils.webex_messaging import send_message, send_message_with_files

# Simple message (includes automatic retry)
send_message(webex_api, room_id, markdown="**Hello World**")

# Message with file attachment (includes automatic retry)
send_message_with_files(
    webex_api,
    room_id,
    files=["chart.png"],
    markdown="Here's your chart!"
)

# Safe send (doesn't throw exceptions)
from src.utils.webex_messaging import safe_send_message

success = safe_send_message(
    webex_api,
    room_id,
    markdown="**Error occurred**",
    fallback_text="Error occurred"
)
if not success:
    logger.warning("Failed to notify user")
```

## Configuration Options

### Retry Decorator Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `max_attempts` | int | 3 | Maximum number of attempts (including initial) |
| `initial_delay` | float | 1.0 | Initial delay in seconds before first retry |
| `max_delay` | float | 60.0 | Maximum delay in seconds between retries |
| `backoff_multiplier` | float | 2.0 | Multiplier for exponential backoff |
| `jitter` | bool | True | Add random jitter to delays |
| `retryable_exceptions` | tuple | ConnectionError, etc. | Exceptions that trigger retry |
| `non_retryable_exceptions` | tuple | ValueError, etc. | Exceptions that never retry |
| `on_retry` | callable | None | Callback called before each retry |
| `on_failure` | callable | None | Callback called on final failure |

### Webex Retry Defaults

The `with_webex_retry` decorator uses optimized defaults for Webex API:

- `max_attempts`: 3
- `initial_delay`: 2.0 seconds (longer for API rate limiting)
- `max_delay`: 30.0 seconds
- `backoff_multiplier`: 2.0
- `jitter`: True

## Retryable vs Non-Retryable Exceptions

### Retryable Exceptions (Will Retry)

- `ConnectionError`
- `ConnectionResetError`
- `ConnectionAbortedError`
- `TimeoutError`
- `OSError`
- `RequestException` (from requests library)
- `ProtocolError` (from urllib3)
- Any exception with messages containing:
  - "connection reset", "connection aborted"
  - "timeout", "timed out"
  - "rate limit", "too many requests"
  - "503", "504", "service unavailable"
  - "ssl", "certificate", "proxy"

### Non-Retryable Exceptions (Will Not Retry)

- `ValueError` - Invalid input
- `TypeError` - Type errors
- `KeyError` - Missing keys
- `AttributeError` - Missing attributes

These fail immediately without retry since they indicate programming errors.

## Advanced Usage

### Custom Retry Logic

```python
from src.utils.retry_utils import with_retry

@with_retry(
    max_attempts=5,
    initial_delay=2.0,
    max_delay=120.0,
    backoff_multiplier=3.0,
    jitter=True
)
def my_custom_api_call():
    # Your logic here
    pass
```

### With Callbacks

```python
def on_retry_callback(attempt, exception, delay):
    print(f"Retry attempt {attempt} after {delay}s due to: {exception}")

def on_failure_callback(exception, total_attempts):
    print(f"Failed after {total_attempts} attempts: {exception}")

@with_retry(
    max_attempts=3,
    on_retry=on_retry_callback,
    on_failure=on_failure_callback
)
def my_function():
    # Your logic
    pass
```

### Context Manager Approach

For more control, use the `RetryContext` context manager:

```python
from src.utils.retry_utils import RetryContext, RetryConfig

config = RetryConfig(max_attempts=3, initial_delay=1.0)

with RetryContext(config) as retry:
    while retry.should_retry():
        try:
            result = api_call()
            retry.success()
            break
        except Exception as e:
            retry.failed(e)
```

## Webex Messaging Helper Functions

### send_message()

Send a simple Webex message with automatic retry:

```python
from src.utils.webex_messaging import send_message

send_message(
    webex_api,
    room_id,
    text="Plain text message",
    markdown="**Markdown** message"
)
```

### send_message_with_files()

Send a message with file attachments:

```python
from src.utils.webex_messaging import send_message_with_files

send_message_with_files(
    webex_api,
    room_id,
    files=["chart.png", "report.pdf"],
    markdown="See attached files"
)
```

### send_card()

Send an Adaptive Card:

```python
from src.utils.webex_messaging import send_card

card_attachment = {
    "contentType": "application/vnd.microsoft.card.adaptive",
    "content": adaptive_card.to_dict()
}

send_card(
    webex_api,
    room_id,
    attachments=[card_attachment],
    text="Card fallback text"
)
```

### safe_send_message()

Send a message without throwing exceptions (returns boolean):

```python
from src.utils.webex_messaging import safe_send_message

success = safe_send_message(
    webex_api,
    room_id,
    markdown="**Alert**",
    fallback_text="Alert"
)

if not success:
    logger.warning("Failed to send message")
```

## Integration with Existing Bots

### Example: Money Ball Bot

The `send_chart` function in money_ball.py uses the retry mechanism:

```python
from src.utils.webex_messaging import send_message_with_files, safe_send_message

def send_chart(room_id, display_name, chart_name, chart_filename):
    try:
        # ... validate chart path ...

        # Send message with chart (includes automatic retry)
        send_message_with_files(
            webex_api,
            room_id,
            files=[chart_path],
            markdown=f"📊 **{display_name}, here's your {chart_name} chart!**"
        )

    except Exception as e:
        # Safe error notification (won't throw)
        safe_send_message(
            webex_api,
            room_id,
            markdown=f"❌ Failed to send {chart_name} chart",
            fallback_text=f"Failed to send {chart_name} chart"
        )
```

### Example: Aging Tickets Report

The aging tickets module uses retry for report sending:

```python
from src.utils.webex_messaging import send_message

def send_report(room_id):
    # ... generate report ...

    send_message(
        webex_api,
        room_id,
        text="Aging Tickets Summary",
        markdown=f"Summary: {report_data}"
    )
```

## Monitoring and Logging

The retry mechanism provides comprehensive logging:

### Success After Retry
```
⚠️ send_chart attempt 1/3 failed: ConnectionError: Connection reset. Retrying in 2.00s...
✅ send_chart succeeded on attempt 2/3
```

### Final Failure
```
⚠️ send_chart attempt 1/3 failed: ConnectionError: Connection reset. Retrying in 2.00s...
⚠️ send_chart attempt 2/3 failed: ConnectionError: Connection reset. Retrying in 4.00s...
⚠️ send_chart attempt 3/3 failed: ConnectionError: Connection reset. Retrying in 8.00s...
❌ send_chart failed after 3 attempts. Last error: ConnectionError: Connection reset
```

### Non-Retryable Error
```
❌ send_chart failed with non-retryable exception: ValueError: Invalid room_id
```

## Best Practices

1. **Use Webex-specific decorators**: Use `with_webex_retry` or the messaging helpers for Webex API calls
2. **Use safe_send for error notifications**: When sending error messages, use `safe_send_message` to avoid cascading failures
3. **Set appropriate max_attempts**: 3 attempts is usually sufficient for transient failures
4. **Use longer delays for APIs**: API rate limits benefit from longer initial delays (2-5 seconds)
5. **Log failures**: Always log retry attempts and final failures for debugging
6. **Test retry logic**: Include tests for both successful retries and final failures

## Testing

Run the retry mechanism tests:

```bash
python -m pytest tests/test_retry_utils.py -v
```

Example test:

```python
def test_retry_on_connection_error():
    mock_api = Mock()
    mock_api.messages.create.side_effect = [
        ConnectionError("fail"),
        Mock(return_value="success")
    ]

    result = send_message(mock_api, "room_id", text="test")
    assert mock_api.messages.create.call_count == 2
```

## Troubleshooting

### Problem: Function not retrying
**Solution**: Ensure the exception is in the retryable_exceptions list or matches transient error patterns

### Problem: Too many retries causing delays
**Solution**: Reduce max_attempts or adjust initial_delay and max_delay

### Problem: Retrying on logic errors
**Solution**: These shouldn't retry. Check if the exception is correctly categorized

### Problem: Rate limit errors
**Solution**: Increase initial_delay to 5+ seconds for rate-limited APIs

## Migration Guide

### Old Code (Direct API Call)
```python
webex_api.messages.create(roomId=room_id, text="Hello")
```

### New Code (With Retry)
```python
from src.utils.webex_messaging import send_message

send_message(webex_api, room_id, text="Hello")
```

### Old Code (With Error Handling)
```python
try:
    webex_api.messages.create(roomId=room_id, text="Hello")
except Exception as e:
    logger.error(f"Failed to send: {e}")
```

### New Code (With Safe Send)
```python
from src.utils.webex_messaging import safe_send_message

if not safe_send_message(webex_api, room_id, text="Hello"):
    logger.error("Failed to send message")
```

## Related Documentation

- [Bot Resilience Framework](bot_resilience.md) - Connection-level resilience
- [Webex Bot Development](webex_bots.md) - General bot development guide
- [Error Handling](error_handling.md) - Overall error handling strategy

## Support

For issues or questions:
1. Check logs for retry attempt messages
2. Verify exception types are retryable
3. Review retry configuration parameters
4. Run unit tests to verify behavior
