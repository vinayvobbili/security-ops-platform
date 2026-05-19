"""Intelligence X (IntelX) dark web and data leak search tools."""

import logging

from mcp_server.server import mcp

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        from services.intelx import get_client
        _client = get_client()
    return _client


@mcp.tool(tags={"readonly"})
def intelx_search(term: str, max_results: int = 50) -> dict:
    """Search IntelX for a term across dark web, leaks, and paste sites.

    Searches Intelligence X for the given term across dark web (.onion),
    I2P, public data leaks, paste sites, and public web sources.
    Useful for checking if credentials, company data, or IOCs appear
    in breach datasets.

    Args:
        term: Search term — domain, email, IP, keyword, or hash
        max_results: Maximum results to return (default 50)
    """
    client = _get_client()
    return client.search(term, max_results=max_results)


@mcp.tool(tags={"readonly"})
def intelx_search_domain(domain: str) -> dict:
    """Search IntelX for mentions of a domain across dark web and data leaks.

    Targeted domain search across IntelX sources. Returns documents,
    pastes, and leak records mentioning the domain. Useful for brand
    monitoring and checking for credential exposure.

    Args:
        domain: Domain name to search for (e.g. 'company.com')
    """
    client = _get_client()
    return client.search_domain(domain)
