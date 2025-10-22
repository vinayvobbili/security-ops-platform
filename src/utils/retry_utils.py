"""
Retry Utilities for API Calls

Provides retry decorators and helpers for handling transient failures
in API calls, particularly for Webex API operations.

Usage:
    from src.utils.retry_utils import with_retry, RetryConfig

    @with_retry(max_attempts=3, initial_delay=1.0)
    def my_api_call():
        # Your API call here
        pass
"""

import time
import logging
from functools import wraps
from typing import Callable, Any, Optional, Tuple, Type
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class RetryConfig:
    """Configuration for retry behavior"""
    max_attempts: int = 3
    initial_delay: float = 1.0
    max_delay: float = 60.0
    backoff_multiplier: float = 2.0
    jitter: bool = True

    # Exception types that should trigger a retry
    retryable_exceptions: Tuple[Type[Exception], ...] = (
        ConnectionError,
        ConnectionResetError,
        ConnectionAbortedError,
        TimeoutError,
        OSError,
    )

    # Exception types that should NOT trigger a retry
    non_retryable_exceptions: Tuple[Type[Exception], ...] = (
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
    )


def _calculate_delay(attempt: int, config: RetryConfig) -> float:
    """Calculate delay with exponential backoff and optional jitter"""
    delay = min(
        config.initial_delay * (config.backoff_multiplier ** attempt),
        config.max_delay
    )

    if config.jitter:
        import random
        # Add up to 25% jitter
        jitter_amount = delay * 0.25
        delay = delay + random.uniform(-jitter_amount, jitter_amount)

    return max(0, delay)


def _is_retryable_exception(exception: Exception, config: RetryConfig) -> bool:
    """Determine if an exception should trigger a retry"""
    # Never retry non-retryable exceptions
    if isinstance(exception, config.non_retryable_exceptions):
        return False

    # Always retry explicitly retryable exceptions
    if isinstance(exception, config.retryable_exceptions):
        return True

    # Check for common transient error indicators in the error message
    error_str = str(exception).lower()
    transient_indicators = [
        'connection reset',
        'connection aborted',
        'connection refused',
        'timeout',
        'timed out',
        'temporary failure',
        'try again',
        'rate limit',
        'too many requests',
        '429',
        '503',
        '504',
        'service unavailable',
        'gateway timeout',
        'ssl',
        'certificate',
        'proxy',
    ]

    return any(indicator in error_str for indicator in transient_indicators)


def with_retry(
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 60.0,
    backoff_multiplier: float = 2.0,
    jitter: bool = True,
    retryable_exceptions: Optional[Tuple[Type[Exception], ...]] = None,
    non_retryable_exceptions: Optional[Tuple[Type[Exception], ...]] = None,
    on_retry: Optional[Callable[[int, Exception, float], None]] = None,
    on_failure: Optional[Callable[[Exception, int], None]] = None,
) -> Callable:
    """
    Decorator that adds retry logic to a function

    Args:
        max_attempts: Maximum number of attempts (including initial attempt)
        initial_delay: Initial delay in seconds before first retry
        max_delay: Maximum delay in seconds between retries
        backoff_multiplier: Multiplier for exponential backoff
        jitter: Add random jitter to delays to avoid thundering herd
        retryable_exceptions: Tuple of exception types that should trigger retry
        non_retryable_exceptions: Tuple of exception types that should never retry
        on_retry: Optional callback(attempt, exception, delay) called before each retry
        on_failure: Optional callback(exception, total_attempts) called on final failure

    Returns:
        Decorated function with retry logic

    Example:
        @with_retry(max_attempts=3, initial_delay=1.0)
        def send_message(room_id, text):
            webex_api.messages.create(roomId=room_id, text=text)
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # Build config
            config = RetryConfig(
                max_attempts=max_attempts,
                initial_delay=initial_delay,
                max_delay=max_delay,
                backoff_multiplier=backoff_multiplier,
                jitter=jitter,
            )

            if retryable_exceptions is not None:
                config.retryable_exceptions = retryable_exceptions
            if non_retryable_exceptions is not None:
                config.non_retryable_exceptions = non_retryable_exceptions

            last_exception = None

            for attempt in range(max_attempts):
                try:
                    result = func(*args, **kwargs)

                    # Success - log if this was a retry
                    if attempt > 0:
                        func_name = getattr(func, '__name__', 'function')
                        logger.info(
                            f"✅ {func_name} succeeded on attempt {attempt + 1}/{max_attempts}"
                        )

                    return result

                except Exception as e:
                    last_exception = e

                    # Get function name safely
                    func_name = getattr(func, '__name__', 'function')

                    # Check if we should retry
                    if not _is_retryable_exception(e, config):
                        logger.warning(
                            f"❌ {func_name} failed with non-retryable exception: {type(e).__name__}: {e}"
                        )
                        raise

                    # Check if we have more attempts
                    if attempt >= max_attempts - 1:
                        break

                    # Calculate delay and log
                    delay = _calculate_delay(attempt, config)
                    logger.warning(
                        f"⚠️ {func_name} attempt {attempt + 1}/{max_attempts} failed: "
                        f"{type(e).__name__}: {e}. Retrying in {delay:.2f}s..."
                    )

                    # Call on_retry callback if provided
                    if on_retry:
                        try:
                            on_retry(attempt + 1, e, delay)
                        except Exception as callback_error:
                            logger.warning(f"on_retry callback failed: {callback_error}")

                    # Wait before retry
                    time.sleep(delay)

            # All attempts exhausted
            func_name = getattr(func, '__name__', 'function')
            logger.error(
                f"❌ {func_name} failed after {max_attempts} attempts. "
                f"Last error: {type(last_exception).__name__}: {last_exception}"
            )

            # Call on_failure callback if provided
            if on_failure:
                try:
                    on_failure(last_exception, max_attempts)
                except Exception as callback_error:
                    logger.warning(f"on_failure callback failed: {callback_error}")

            # Re-raise the last exception
            raise last_exception

        return wrapper
    return decorator


def with_webex_retry(
    max_attempts: int = 3,
    initial_delay: float = 2.0,
    on_retry: Optional[Callable[[int, Exception, float], None]] = None,
    on_failure: Optional[Callable[[Exception, int], None]] = None,
) -> Callable:
    """
    Specialized retry decorator for Webex API calls with appropriate defaults

    This uses settings optimized for Webex API:
    - Handles connection errors and rate limits
    - Uses longer initial delay (2s) for API rate limiting
    - Adds jitter to avoid thundering herd

    Args:
        max_attempts: Maximum number of attempts (default: 3)
        initial_delay: Initial delay in seconds (default: 2.0)
        on_retry: Optional callback(attempt, exception, delay) called before each retry
        on_failure: Optional callback(exception, total_attempts) called on final failure

    Example:
        @with_webex_retry(max_attempts=3)
        def send_chart(room_id, chart_path):
            webex_api.messages.create(roomId=room_id, files=[chart_path])
    """

    # Import here to avoid circular dependencies
    try:
        from requests.exceptions import RequestException, Timeout, ConnectionError as RequestsConnectionError
        from urllib3.exceptions import ProtocolError

        webex_retryable = (
            ConnectionError,
            ConnectionResetError,
            ConnectionAbortedError,
            TimeoutError,
            OSError,
            RequestException,
            Timeout,
            RequestsConnectionError,
            ProtocolError,
        )
    except ImportError:
        webex_retryable = (
            ConnectionError,
            ConnectionResetError,
            ConnectionAbortedError,
            TimeoutError,
            OSError,
        )

    return with_retry(
        max_attempts=max_attempts,
        initial_delay=initial_delay,
        max_delay=30.0,  # Cap at 30 seconds for API calls
        backoff_multiplier=2.0,
        jitter=True,
        retryable_exceptions=webex_retryable,
        on_retry=on_retry,
        on_failure=on_failure,
    )


class RetryContext:
    """
    Context manager for retry logic (alternative to decorator)

    Usage:
        with RetryContext(max_attempts=3) as retry:
            while retry.should_retry():
                try:
                    # Your code here
                    result = api_call()
                    retry.success()
                    return result
                except Exception as e:
                    retry.failed(e)
    """

    def __init__(self, config: Optional[RetryConfig] = None):
        self.config = config or RetryConfig()
        self.attempt = 0
        self.last_exception = None
        self._should_continue = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Don't suppress exceptions
        return False

    def should_retry(self) -> bool:
        """Check if another attempt should be made"""
        if self.attempt >= self.config.max_attempts:
            return False
        return self._should_continue

    def success(self):
        """Mark the current attempt as successful"""
        if self.attempt > 0:
            logger.info(f"✅ Operation succeeded on attempt {self.attempt + 1}")
        self._should_continue = False

    def failed(self, exception: Exception):
        """Handle a failed attempt"""
        self.last_exception = exception
        self.attempt += 1

        # Check if retryable
        if not _is_retryable_exception(exception, self.config):
            logger.warning(
                f"❌ Operation failed with non-retryable exception: "
                f"{type(exception).__name__}: {exception}"
            )
            self._should_continue = False
            raise exception

        # Check if we have more attempts
        if self.attempt >= self.config.max_attempts:
            logger.error(
                f"❌ Operation failed after {self.config.max_attempts} attempts. "
                f"Last error: {type(exception).__name__}: {exception}"
            )
            self._should_continue = False
            raise exception

        # Calculate and apply delay
        delay = _calculate_delay(self.attempt - 1, self.config)
        logger.warning(
            f"⚠️ Attempt {self.attempt}/{self.config.max_attempts} failed: "
            f"{type(exception).__name__}: {exception}. Retrying in {delay:.2f}s..."
        )
        time.sleep(delay)
