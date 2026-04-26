"""Zscaler web proxy tools.

Zscaler requires an auth session. The lazy getter handles authentication
and re-authenticates on session expiry.
"""

import logging
from typing import List

from mcp_server.server import mcp

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        from services.zscaler import ZscalerClient
        _client = ZscalerClient()
        _client.authenticate()
    elif not _client.is_authenticated():
        _client.authenticate()
    return _client


@mcp.tool()
def zscaler_lookup_url(urls: List[str]) -> dict:
    """Look up URL categorization in Zscaler (batch).

    Args:
        urls: List of URLs to classify
    """
    client = _get_client()
    results = client.url_lookup(urls)
    return {"results": results}


@mcp.tool()
def zscaler_get_sandbox_report(md5_hash: str, report_type: str = "full") -> dict:
    """Get Zscaler Cloud Sandbox analysis report for a file.

    Args:
        md5_hash: MD5 hash of the file
        report_type: Report type ('full' or 'summary')
    """
    client = _get_client()
    return client.get_sandbox_report(md5_hash, report_type=report_type)


@mcp.tool()
def zscaler_get_blocklist() -> dict:
    """Get the current Zscaler URL blocklist."""
    client = _get_client()
    return client.get_url_blocklist()


@mcp.tool()
def zscaler_add_to_blocklist(urls: List[str]) -> dict:
    """Add URLs to the Zscaler blocklist.

    Args:
        urls: List of URLs to block
    """
    client = _get_client()
    return client.add_urls_to_blocklist(urls)
