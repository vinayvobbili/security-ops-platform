"""URLScan.io website scanning tools."""

import logging

from mcp_server.server import mcp

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        from services.urlscan import URLScanClient
        _client = URLScanClient()
    return _client


@mcp.tool(tags={"readonly"})
def urlscan_search(domain: str, size: int = 10) -> dict:
    """Search URLScan.io for historical scans of a domain.

    Returns past scan results including page titles, technologies detected,
    IPs served from, and threat verdicts for the domain.

    Args:
        domain: Domain to search for historical scans
        size: Number of results to return (default 10)
    """
    client = _get_client()
    return client.search_domain(domain, size=size)


@mcp.tool(tags={"mutating"})
def urlscan_submit(url: str, visibility: str = "public") -> dict:
    """Submit a URL to URLScan.io for live scanning.

    Triggers a fresh scan and returns the scan UUID and result URL.
    Results may take 30–60 seconds to become available.

    Args:
        url: Full URL to scan (e.g. 'https://suspicious-site.com/path')
        visibility: Scan visibility — 'public', 'unlisted', or 'private'
    """
    client = _get_client()
    return client.submit_scan(url, visibility=visibility)
