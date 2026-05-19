"""Shodan internet exposure tools."""

import logging

from mcp_server.server import mcp

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        from services.shodan_monitor import ShodanClient
        _client = ShodanClient()
    return _client


@mcp.tool(tags={"readonly"})
def shodan_lookup_ip(ip_address: str) -> dict:
    """Look up an IP address on Shodan for open ports, services, and vulnerabilities.

    Returns open ports, running services, banners, software versions,
    and known CVEs for the IP. Useful for assessing external attack surface.

    Args:
        ip_address: IPv4 address to look up
    """
    client = _get_client()
    return client.lookup_ip(ip_address)


@mcp.tool(tags={"readonly"})
def shodan_lookup_domain(domain: str) -> dict:
    """Look up a domain on Shodan for infrastructure and exposure details.

    Resolves the domain and returns Shodan data for all associated IPs,
    including open ports, services, and geographic distribution.

    Args:
        domain: Domain name to look up (e.g. 'example.com')
    """
    client = _get_client()
    return client.lookup_domain(domain)
