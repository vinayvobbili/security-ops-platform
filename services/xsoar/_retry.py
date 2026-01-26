"""
XSOAR Retry Logic and Error Handling

Shared retry logic with exponential backoff for XSOAR API operations.
"""
import logging
import time
from functools import wraps
from http.client import RemoteDisconnected
from typing import Any, Callable, Optional, TypeVar

import requests
from urllib3.exceptions import ProtocolError

from ._client import ApiException

log = logging.getLogger(__name__)

# Type variable for generic return type
T = TypeVar('T')

# Default retry configuration
DEFAULT_MAX_RETRIES = 3
RETRYABLE_STATUS_CODES = {429, 502, 503, 504}
CONNECTION_ERRORS = (RemoteDisconnected, ProtocolError, ConnectionError, requests.exceptions.ConnectionError)


def truncate_error_message(error: Exception, max_length: int = 500) -> str:
    """
    Truncate error messages containing HTML/SVG content to prevent log pollution.

    Args:
        error: The exception object
        max_length: Maximum length of error message (default: 500 chars)

    Returns:
        Truncated error message suitable for logging
    """
    error_str = str(error)

    # If error contains HTML tags, heavily truncate it
    if '<html>' in error_str.lower() or '<svg' in error_str.lower():
        # Extract just the HTTP status code and reason if present
        lines = error_str.split('\n')
        first_line = lines[0] if lines else error_str

        # Truncate to first line + indication of HTML content
        if len(first_line) > 200:
            first_line = first_line[:200]

        return f"{first_line} [HTML response body truncated to prevent log pollution]"

    # For non-HTML errors, still apply reasonable truncation
    if len(error_str) > max_length:
        return error_str[:max_length] + "... [truncated]"

    return error_str


def calculate_backoff(retry_count: int, base_seconds: int = 5) -> int:
    """
    Calculate exponential backoff time.

    Args:
        retry_count: Current retry attempt (1-indexed)
        base_seconds: Base backoff time in seconds

    Returns:
        Backoff time in seconds
    """
    return base_seconds * (2 ** (retry_count - 1))


def is_retryable_error(error: ApiException) -> bool:
    """
    Check if an API error is retryable.

    Args:
        error: The ApiException to check

    Returns:
        True if the error can be retried
    """
    return error.status in RETRYABLE_STATUS_CODES


def with_retry(
    max_retries: int = DEFAULT_MAX_RETRIES,
    base_backoff: int = 5,
    operation_name: str = "API call"
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator for adding retry logic with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts
        base_backoff: Base backoff time in seconds
        operation_name: Name of operation for logging

    Returns:
        Decorated function with retry logic
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            retry_count = 0

            while True:
                try:
                    return func(*args, **kwargs)

                except CONNECTION_ERRORS as e:
                    retry_count += 1
                    if retry_count > max_retries:
                        log.error(f"Exceeded max connection error retries ({max_retries}) for {operation_name}")
                        raise

                    backoff_time = calculate_backoff(retry_count, base_backoff)
                    log.warning(
                        f"Connection error during {operation_name}: {type(e).__name__}: {e}. "
                        f"Retry {retry_count}/{max_retries}. "
                        f"Backing off for {backoff_time} seconds..."
                    )
                    time.sleep(backoff_time)

                except ApiException as e:
                    if is_retryable_error(e):
                        retry_count += 1
                        if retry_count > max_retries:
                            log.error(f"Exceeded max retries ({max_retries}) for {operation_name} due to status {e.status}")
                            raise

                        backoff_time = calculate_backoff(retry_count, base_backoff)
                        log.warning(
                            f"Server error {e.status} during {operation_name}. "
                            f"Retry {retry_count}/{max_retries}. "
                            f"Backing off for {backoff_time} seconds..."
                        )
                        time.sleep(backoff_time)
                    else:
                        # Non-retryable error
                        log.error(f"Error during {operation_name}: {truncate_error_message(e)}")
                        raise

        return wrapper
    return decorator


def retry_on_error(
    func: Callable[..., T],
    max_retries: int = DEFAULT_MAX_RETRIES,
    operation_name: str = "API call",
    context: Optional[str] = None
) -> T:
    """
    Execute a function with retry logic (non-decorator version).

    Args:
        func: Function to execute
        max_retries: Maximum number of retry attempts
        operation_name: Name of operation for logging
        context: Optional context string for error messages

    Returns:
        Result of the function

    Raises:
        ApiException: If all retries are exhausted
    """
    retry_count = 0
    context_str = f" ({context})" if context else ""

    while True:
        try:
            return func()

        except CONNECTION_ERRORS as e:
            retry_count += 1
            if retry_count > max_retries:
                log.error(f"Exceeded max connection error retries ({max_retries}) for {operation_name}{context_str}")
                raise

            backoff_time = calculate_backoff(retry_count)
            log.warning(
                f"Connection error during {operation_name}{context_str}: {type(e).__name__}: {e}. "
                f"Retry {retry_count}/{max_retries}. "
                f"Backing off for {backoff_time} seconds..."
            )
            time.sleep(backoff_time)

        except ApiException as e:
            if is_retryable_error(e):
                retry_count += 1
                if retry_count > max_retries:
                    log.error(f"Exceeded max retries ({max_retries}) for {operation_name}{context_str} due to status {e.status}")
                    raise

                backoff_time = calculate_backoff(retry_count)
                log.warning(
                    f"Server error {e.status} during {operation_name}{context_str}. "
                    f"Retry {retry_count}/{max_retries}. "
                    f"Backing off for {backoff_time} seconds..."
                )
                time.sleep(backoff_time)
            else:
                # Non-retryable error
                log.error(f"Error during {operation_name}{context_str}: {truncate_error_message(e)}")
                raise
