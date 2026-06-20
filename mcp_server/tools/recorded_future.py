"""Recorded Future threat intelligence tools."""

import logging
from typing import Optional

from mcp_server.server import mcp
from my_bot.utils.verify_links import attach_verify, recorded_future_line

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        from services.recorded_future import RecordedFutureClient
        _client = RecordedFutureClient()
    return _client


@mcp.tool(tags={"readonly"})
def recorded_future_search_actor(
    name: str, limit: int = 100, category: Optional[str] = None
) -> dict:
    """Search Recorded Future for threat actors by name.

    Args:
        name: Actor name or keyword to search
        limit: Max results
        category: Optional category filter
    """
    client = _get_client()
    return client.search_actor(name, limit=limit, category=category)


@mcp.tool(tags={"readonly"})
def recorded_future_get_actor(actor_id: str) -> dict:
    """Get detailed information about a Recorded Future threat actor.

    Args:
        actor_id: The Recorded Future actor ID
    """
    client = _get_client()
    return client.get_actor_details(actor_id)


@mcp.tool(tags={"readonly"})
def recorded_future_enrich(
    ips: Optional[list] = None,
    domains: Optional[list] = None,
    hashes: Optional[list] = None,
    urls: Optional[list] = None,
    vulnerabilities: Optional[list] = None,
    include_metadata: bool = False,
) -> dict:
    """Batch enrich IOCs via Recorded Future. Provide one or more lists.

    Args:
        ips: List of IP addresses
        domains: List of domains
        hashes: List of file hashes
        urls: List of URLs
        vulnerabilities: List of CVE IDs
        include_metadata: Include extra metadata in response
    """
    client = _get_client()
    result = client.enrich(
        ips=ips,
        domains=domains,
        hashes=hashes,
        urls=urls,
        vulnerabilities=vulnerabilities,
        include_metadata=include_metadata,
    )
    # The Intelligence Card deep link targets ONE entity; only attach it when the
    # batch enriched a single indicator (the common single-IOC case). RF's own
    # entity id is authoritative, so no URL guessing.
    try:
        normalized = client.extract_enrichment_results(result)
        if len(normalized) == 1:
            result = attach_verify(result, recorded_future_line(normalized[0].get("entity_id")))
    except Exception:
        pass
    return result


@mcp.tool(tags={"readonly"})
def recorded_future_triage_phishing(
    domains: Optional[list] = None,
    urls: Optional[list] = None,
    ips: Optional[list] = None,
    threshold: int = 25,
) -> dict:
    """Triage IOCs for phishing risk using Recorded Future.

    Args:
        domains: List of domains to check
        urls: List of URLs to check
        ips: List of IPs to check
        threshold: Minimum risk score threshold
    """
    client = _get_client()
    return client.triage_for_phishing(
        domains=domains, urls=urls, ips=ips, threshold=threshold
    )


@mcp.tool(tags={"readonly"})
def recorded_future_search_brand(
    brand: str,
    legitimate_domains: Optional[list] = None,
    min_risk_score: int = 0,
    limit: int = 100,
) -> dict:
    """Search Recorded Future for brand impersonation domains.

    Args:
        brand: Brand name to search for
        legitimate_domains: Known legitimate domains to exclude
        min_risk_score: Minimum risk score filter
        limit: Max results
    """
    client = _get_client()
    return client.search_brand_domains(
        brand,
        legitimate_domains=legitimate_domains,
        min_risk_score=min_risk_score,
        limit=limit,
    )
