"""
Utility to configure WebexTeamsAPI with larger connection pool.

This prevents connection pool exhaustion when multiple bots run on the same VM
and process WebSocket messages concurrently.
"""
import requests.adapters
from urllib3.util.retry import Retry


def configure_webex_api_session(api_instance, pool_connections=50, pool_maxsize=50, max_retries=3):
    """
    Configure the requests session in a WebexTeamsAPI instance with larger connection pool.

    Args:
        api_instance: WebexTeamsAPI instance to configure
        pool_connections: Number of connection pools to cache (default: 50, increased from 10)
        pool_maxsize: Maximum connections per pool (default: 50, increased from 10)
        max_retries: Number of retry attempts for failed requests (default: 3)

    Returns:
        The configured API instance
    """
    # Access the internal requests session
    session = api_instance._session._req_session

    # Configure retry strategy
    retry_strategy = Retry(
        total=max_retries,
        backoff_factor=1,  # Wait 1s, 2s, 4s between retries
        status_forcelist=[429, 500, 502, 503, 504],  # Retry on these HTTP status codes
        allowed_methods=["GET", "POST", "PUT", "DELETE"]  # Retry on all methods
    )

    # Create new adapter with larger pool
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=pool_connections,
        pool_maxsize=pool_maxsize,
        max_retries=retry_strategy,
        pool_block=False  # Don't block when pool is full, fail fast instead
    )

    # Mount adapter for both http and https
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    return api_instance
