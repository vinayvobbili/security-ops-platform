"""
SSL Configuration for Corporate Proxy Environments

This module provides SSL configuration for applications running behind corporate
proxies like Zscaler that perform SSL/TLS inspection. It configures Python's
SSL libraries to work properly in these environments.

Usage:
    from src.utils.ssl_config import configure_ssl_for_corporate_proxy

    # Call this at the beginning of your application
    configure_ssl_for_corporate_proxy()
"""

import os
import ssl
import urllib3
import urllib3.util.ssl_
import requests.sessions


def configure_ssl_for_corporate_proxy(verbose=False):
    """
    Configure SSL settings for applications running behind corporate proxies.

    This function disables SSL verification and configures SSL contexts to
    work with corporate proxies like Zscaler that perform SSL/TLS inspection.

    Args:
        verbose (bool): If True, print configuration status messages

    Note:
        This disables SSL certificate verification, which is acceptable in
        corporate environments with trusted proxy infrastructure but should
        not be used in untrusted networks.
    """
    if verbose:
        print("🔧 Configuring SSL for corporate proxy environment...")

    # Configure environment variables for corporate proxy
    os.environ['PYTHONHTTPSVERIFY'] = '0'
    os.environ['SSL_VERIFY'] = 'false'
    os.environ['REQUESTS_CA_BUNDLE'] = ''
    os.environ['CURL_CA_BUNDLE'] = ''

    # Set default SSL context to unverified for corporate proxy compatibility
    ssl._create_default_https_context = ssl._create_unverified_context

    # Disable SSL warnings to reduce noise in logs
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Monkey patch urllib3 SSL context creation for corporate proxy compatibility
    original_create_urllib3_context = urllib3.util.ssl_.create_urllib3_context

    def create_unverified_context(*args, **kwargs):
        """Create SSL context that accepts any certificate (for corporate proxy)"""
        ctx = original_create_urllib3_context(*args, **kwargs)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    urllib3.util.ssl_.create_urllib3_context = create_unverified_context

    # Monkey patch requests Session to disable SSL verification
    original_request = requests.sessions.Session.request

    def patched_request(self, method, url, **kwargs):
        """Patch requests to disable SSL verification for corporate proxy"""
        kwargs.setdefault('verify', False)
        return original_request(self, method, url, **kwargs)

    requests.sessions.Session.request = patched_request

    if verbose:
        print("✅ SSL configuration complete for corporate proxy environment")


def is_corporate_proxy_detected():
    """
    Detect if we're running behind a corporate proxy.

    Returns:
        bool: True if corporate proxy is detected, False otherwise
    """
    try:
        import subprocess

        # Check for ZScaler process
        result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
        if "zscaler" in result.stdout.lower():
            return True

        # Check environment variables for proxy
        proxy_vars = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']
        for var in proxy_vars:
            if os.environ.get(var):
                return True

        return False
    except Exception:
        return False


def configure_ssl_if_needed(verbose=False):
    """
    Automatically configure SSL if a corporate proxy is detected.

    Args:
        verbose (bool): If True, print detection and configuration messages
    """
    if is_corporate_proxy_detected():
        if verbose:
            print("🛡️ Corporate proxy detected - configuring SSL compatibility")
        configure_ssl_for_corporate_proxy(verbose=verbose)
    elif verbose:
        print("🌐 No corporate proxy detected - using default SSL configuration")