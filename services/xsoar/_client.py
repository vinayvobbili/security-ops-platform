"""
XSOAR Client Configuration and Initialization

This module handles:
- SSL context creation for corporate proxies (Zscaler)
- demisto-py client initialization for prod and dev environments
- Connection pool configuration and patching
- Timeout and retry configuration
"""
import functools
import logging
import os
import platform
import ssl
from typing import Any

import certifi
import demisto_client
import urllib3
from demisto_client.demisto_api import rest
from urllib3.exceptions import InsecureRequestWarning

from my_config import get_config
from src.config import XsoarConfig

# For easier access to ApiException
ApiException = rest.ApiException

# Suppress InsecureRequestWarning when SSL verification is disabled
urllib3.disable_warnings(InsecureRequestWarning)

CONFIG = get_config()
log = logging.getLogger(__name__)

# Set urllib3 logging to WARNING to reduce log noise
urllib3_logger = logging.getLogger("urllib3.connectionpool")
urllib3_logger.setLevel(logging.WARNING)


def create_ssl_context_for_proxy():
    """Create SSL context compatible with Zscaler/corporate proxies."""
    ctx = ssl.create_default_context()
    # Load system certificates (includes the Zscaler cert we added to certifi)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    # Allow TLS 1.0+ for compatibility with proxies
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    # Load CA certificates from certifi (which now includes Zscaler cert)
    ctx.load_verify_locations(cafile=certifi.where())
    return ctx


# Create the custom SSL context
_ssl_context = create_ssl_context_for_proxy()


# Configure connection pool size to match parallel workers
CONNECTION_POOL_SIZE = XsoarConfig.get_pool_size()

log.debug(f"XSOAR connection pool configuration: MAX_WORKERS={XsoarConfig.MAX_WORKERS}, POOL_SIZE={CONNECTION_POOL_SIZE}")

_original_pool_manager_init = urllib3.PoolManager.__init__


@functools.wraps(_original_pool_manager_init)
def _patched_pool_manager_init(self, *args, **kwargs):
    """Patched PoolManager init with dynamic maxsize based on worker count."""
    # Set maxsize based on XsoarConfig.MAX_WORKERS if not explicitly provided
    if 'maxsize' not in kwargs:
        kwargs['maxsize'] = CONNECTION_POOL_SIZE
    return _original_pool_manager_init(self, *args, **kwargs)


urllib3.PoolManager.__init__ = _patched_pool_manager_init


# Detect if we're behind Zscaler/corporate proxy by checking environment
# Auto-detection logic:
# - macOS (Darwin) = local dev environment with Zscaler = disable SSL verification
# - Linux = VM/server environment without Zscaler = enable SSL verification
# - Override with DISABLE_SSL_VERIFY environment variable
system_platform = platform.system()

# Auto-detect based on platform if DISABLE_SSL_VERIFY not explicitly set
if 'DISABLE_SSL_VERIFY' in os.environ:
    # Explicit configuration takes precedence
    DISABLE_SSL_VERIFY = os.getenv('DISABLE_SSL_VERIFY').lower() == 'true'
    config_source = "environment variable"
else:
    # Auto-detect: macOS = disable (Zscaler), Linux = enable (no Zscaler)
    DISABLE_SSL_VERIFY = system_platform == 'Darwin'  # Darwin = macOS
    config_source = f"auto-detected ({system_platform})"

if DISABLE_SSL_VERIFY:
    log.info(f"SSL verification DISABLED ({config_source}) - corporate proxy/Zscaler environment")
else:
    log.info(f"SSL verification ENABLED ({config_source}) - direct connection to XSOAR")

# Initialize demisto-py clients for prod and dev environments with timeout
prod_client = demisto_client.configure(
    base_url=CONFIG.xsoar_prod_api_base_url,
    api_key=CONFIG.xsoar_prod_auth_key,
    auth_id=CONFIG.xsoar_prod_auth_id,
    verify_ssl=not DISABLE_SSL_VERIFY
)

dev_client = demisto_client.configure(
    base_url=CONFIG.xsoar_dev_api_base_url,
    api_key=CONFIG.xsoar_dev_auth_key,
    auth_id=CONFIG.xsoar_dev_auth_id,
    verify_ssl=not DISABLE_SSL_VERIFY
)

# Configure connection and read timeouts for both clients
for client in [prod_client, dev_client]:
    if hasattr(client, 'api_client') and hasattr(client.api_client, 'rest_client'):
        rest_client = client.api_client.rest_client
        # Set timeout: (connect_timeout, read_timeout) in seconds
        read_timeout = int(os.getenv('XSOAR_READ_TIMEOUT', '30'))
        rest_client.timeout = (30, read_timeout)

# Configure retry strategy for connection resilience
retry_strategy = urllib3.Retry(
    total=3,  # Max 3 retries
    connect=3,  # Retry connection failures
    read=2,  # Retry read timeouts
    status=0,  # Don't retry on HTTP status codes (handle in application logic)
    backoff_factor=1,  # Wait 1s, 2s, 4s between retries
    allowed_methods=["GET", "POST", "PUT", "DELETE"],  # Retry on all methods
    raise_on_status=False  # Don't raise exception on retry exhaustion, let app handle it
)

# Configure pool manager for both clients with retry strategy
for client in [prod_client, dev_client]:
    if hasattr(client, 'api_client') and hasattr(client.api_client, 'rest_client'):
        rest_client = client.api_client.rest_client
        if hasattr(rest_client, 'pool_manager'):
            read_timeout = int(os.getenv('XSOAR_READ_TIMEOUT', '30'))
            pool_kwargs = {
                'num_pools': 10,
                'maxsize': CONNECTION_POOL_SIZE,  # Dynamic: MAX_WORKERS + 5 buffer
                'timeout': urllib3.Timeout(connect=30.0, read=float(read_timeout)),
                'retries': retry_strategy,
            }

            if not DISABLE_SSL_VERIFY:
                # Enable SSL verification for VM/direct connections
                pool_kwargs['cert_reqs'] = 'CERT_REQUIRED'
                pool_kwargs['ca_certs'] = None  # Use system default (certifi)
                pool_kwargs['ssl_context'] = _ssl_context
            else:
                # Disable SSL verification for corporate proxy (Zscaler)
                pool_kwargs['cert_reqs'] = 'CERT_NONE'

            rest_client.pool_manager = urllib3.PoolManager(**pool_kwargs)


def get_prod_client() -> Any:
    """Get the production XSOAR client."""
    return prod_client


def get_dev_client() -> Any:
    """Get the development XSOAR client."""
    return dev_client


def get_config():
    """Get the XSOAR configuration."""
    return CONFIG
