"""AbuseIPDB internet reputation tools."""

import logging

from mcp_server.server import mcp
from my_bot.utils.verify_links import attach_verify, abuseipdb_line

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        from services.abuseipdb import AbuseIPDBClient
        _client = AbuseIPDBClient()
    return _client


@mcp.tool(tags={"readonly"})
def abuseipdb_check_ip(ip_address: str) -> dict:
    """Check an IP address against AbuseIPDB for community-reported abuse.

    Returns abuse confidence score, country, ISP, total reports,
    and a sample of recent abuse report comments (spam, brute force, DDoS, etc.).

    Args:
        ip_address: IPv4 or IPv6 address to check
    """
    client = _get_client()
    ip_address = ip_address.strip()
    return attach_verify(client.check_ip(ip_address), abuseipdb_line(ip_address))


@mcp.tool(tags={"readonly"})
def abuseipdb_check_domain(domain: str) -> dict:
    """Check a domain's IPs against AbuseIPDB for abuse reports.

    Resolves the domain to its IP addresses, then checks each against
    AbuseIPDB. Returns aggregate abuse scores across all resolved IPs.

    Args:
        domain: Domain name to check (e.g. 'example.com')
    """
    client = _get_client()
    domain = domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = domain.split("//", 1)[1]
    if "/" in domain:
        domain = domain.split("/", 1)[0]
    return client.check_domain(domain)
