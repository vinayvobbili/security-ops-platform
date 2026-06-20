"""Abuse.ch malware and botnet threat intelligence tools.

Covers URLhaus (malicious URLs), ThreatFox (IOCs), and Feodo Tracker (botnet C2s).
All sources are free — no API key required.
"""

import logging

from mcp_server.server import mcp
from my_bot.utils.verify_links import attach_verify, threatfox_line

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        from services.abusech import AbuseCHClient
        _client = AbuseCHClient()
    return _client


@mcp.tool(tags={"readonly"})
def abusech_check_domain(domain: str) -> dict:
    """Check a domain against Abuse.ch threat intelligence databases.

    Queries URLhaus (malicious URLs), ThreatFox (malware IOCs), and
    Feodo Tracker (botnet C2s) for the domain. Returns malware family
    associations, C2 activity, and malicious URL records.

    Args:
        domain: Domain to check (e.g. 'suspicious-domain.com')
    """
    client = _get_client()
    return attach_verify(client.check_domain_all(domain), threatfox_line(domain))


@mcp.tool(tags={"readonly"})
def abusech_check_ip(ip_address: str) -> dict:
    """Check an IP address against Abuse.ch threat intelligence databases.

    Queries ThreatFox (malware IOCs) and Feodo Tracker (botnet C2 servers)
    for the IP. Identifies if the IP is a known malware C2, Emotet node,
    Dridex server, TrickBot host, or QakBot infrastructure.

    Args:
        ip_address: IPv4 address to check
    """
    client = _get_client()
    return attach_verify(client.check_ip_all(ip_address), threatfox_line(ip_address))
