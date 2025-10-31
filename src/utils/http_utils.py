"""
HTTP utilities with robust error handling and retry logic.
"""
import time
import logging
from typing import Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import ConnectionError, ProtocolError

logger = logging.getLogger(__name__)


class RobustHTTPSession:
    """HTTP session with built-in retry logic and connection error handling."""

    def __init__(self,
                 max_retries: int = 3,
                 backoff_factor: float = 0.3,
                 timeout: int = 120,
                 verify_ssl: bool = True):
        """
        Initialize the robust HTTP session.

        Args:
            max_retries: Maximum number of retry attempts
            backoff_factor: Factor to apply between retry attempts
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.session = requests.Session()
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=backoff_factor,
            raise_on_status=False
        )

        # Mount adapter with retry strategy and larger connection pool
        # pool_maxsize should match or exceed max_workers in concurrent operations
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,  # Number of connection pools to cache
            pool_maxsize=60  # Maximum connections in each pool (supports 50+ workers)
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _handle_connection_error(self, error: Exception, attempt: int, max_attempts: int) -> bool:
        """
        Handle connection errors with exponential backoff.

        Args:
            error: The exception that occurred
            attempt: Current attempt number
            max_attempts: Maximum number of attempts

        Returns:
            True if should retry, False otherwise
        """
        if attempt >= max_attempts:
            logger.error(f"Max retry attempts ({max_attempts}) reached. Final error: {error}")
            return False

        # Calculate backoff time with jitter
        backoff_time = (2 ** attempt) + (time.time() % 1)
        logger.warning(f"Connection error on attempt {attempt}/{max_attempts}: {error}. "
                       f"Retrying in {backoff_time:.2f} seconds...")
        time.sleep(backoff_time)
        return True

    def request(self, method: str, url: str, max_attempts: int = 3, **kwargs) -> Optional[requests.Response]:
        """
        Make an HTTP request with retry logic for connection errors.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            max_attempts: Maximum number of attempts for connection errors
            **kwargs: Additional arguments passed to requests

        Returns:
            Response object or None if all attempts failed
        """
        # Set default timeout and SSL verification
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', self.verify_ssl)

        for attempt in range(1, max_attempts + 1):
            try:
                response = self.session.request(method, url, **kwargs)

                # Log successful request after previous failures
                if attempt > 1:
                    logger.info(f"Request succeeded on attempt {attempt}")

                return response

            except (ConnectionError, ProtocolError, requests.exceptions.ConnectionError) as e:
                if not self._handle_connection_error(e, attempt, max_attempts):
                    break
                continue

            except requests.exceptions.Timeout as e:
                logger.warning(f"Request timeout on attempt {attempt}/{max_attempts}: {e}")
                if attempt >= max_attempts:
                    logger.error(f"Request failed after {max_attempts} timeout attempts")
                    raise
                time.sleep(1)  # Brief pause before retry
                continue

            except requests.exceptions.RequestException as e:
                logger.error(f"Request failed with non-recoverable error: {e}")
                raise

        return None

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a GET request with retry logic."""
        return self.request('GET', url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a POST request with retry logic."""
        return self.request('POST', url, **kwargs)

    def put(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a PUT request with retry logic."""
        return self.request('PUT', url, **kwargs)

    def delete(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a DELETE request with retry logic."""
        return self.request('DELETE', url, **kwargs)

    def close(self):
        """Close the session."""
        self.session.close()


# Global session instance for reuse
_global_session = None


def get_session() -> RobustHTTPSession:
    """Get a global HTTP session instance."""
    global _global_session
    if _global_session is None:
        _global_session = RobustHTTPSession()
    return _global_session


def robust_request(method: str, url: str, **kwargs) -> Optional[requests.Response]:
    """
    Make a robust HTTP request using the global session.

    Args:
        method: HTTP method
        url: Request URL
        **kwargs: Additional arguments

    Returns:
        Response object or None if failed
    """
    session = get_session()
    return session.request(method, url, **kwargs)
