"""VirusTotal threat intelligence tools."""

import logging

from mcp_server.server import mcp
from my_bot.utils.verify_links import attach_verify, virustotal_line

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        from services.virustotal import VirusTotalClient
        _client = VirusTotalClient()
    return _client


@mcp.tool(tags={"readonly"})
def virustotal_lookup_ip(ip_address: str) -> dict:
    """Get VirusTotal reputation and analysis for an IP address."""
    client = _get_client()
    return attach_verify(client.lookup_ip(ip_address), virustotal_line(ip_address, "ip"))


@mcp.tool(tags={"readonly"})
def virustotal_lookup_domain(domain: str) -> dict:
    """Get VirusTotal reputation and analysis for a domain."""
    client = _get_client()
    return attach_verify(client.lookup_domain(domain), virustotal_line(domain, "domain"))


@mcp.tool(tags={"readonly"})
def virustotal_lookup_url(url: str) -> dict:
    """Get VirusTotal reputation and analysis for a URL."""
    client = _get_client()
    return attach_verify(client.lookup_url(url), virustotal_line(url, "url"))


@mcp.tool(tags={"readonly"})
def virustotal_lookup_hash(file_hash: str) -> dict:
    """Get VirusTotal analysis for a file hash (MD5/SHA1/SHA256)."""
    client = _get_client()
    return attach_verify(client.lookup_hash(file_hash), virustotal_line(file_hash, "hash"))


@mcp.tool(tags={"readonly"})
def virustotal_search_malware(name: str, limit: int = 5) -> dict:
    """Search VirusTotal for malware families by name.

    Args:
        name: Malware family name to search for
        limit: Max results to return
    """
    client = _get_client()
    return client.search_malware_name(name, limit=limit)


@mcp.tool(tags={"mutating"})
def virustotal_reanalyze(indicator: str) -> dict:
    """Request VirusTotal to re-scan an indicator with the latest engines.

    Submits the indicator for fresh analysis. Useful when a previous result
    is stale or was scanned before new detections were available.
    Auto-detects indicator type (IP, domain, URL, or file hash).

    Args:
        indicator: IP address, domain, URL, or file hash (MD5/SHA1/SHA256)
    """
    client = _get_client()
    import re

    indicator = indicator.strip()

    # Detect indicator type
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', indicator):
        return client.reanalyze_ip(indicator)
    elif indicator.startswith(('http://', 'https://')):
        return client.reanalyze_url(indicator)
    elif re.match(r'^[0-9a-fA-F]{32,64}$', indicator):
        return client.reanalyze_hash(indicator)
    else:
        return client.reanalyze_domain(indicator)
