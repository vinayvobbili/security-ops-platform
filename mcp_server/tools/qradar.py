"""QRadar SIEM tools."""

import logging
from typing import Optional

from mcp_server.server import mcp

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        from services.qradar import QRadarClient
        _client = QRadarClient()
    return _client


@mcp.tool(tags={"readonly"})
def qradar_run_aql(
    aql_query: str, timeout: int = 300, max_results: int = 100
) -> dict:
    """Execute a raw AQL query against QRadar.

    Args:
        aql_query: The AQL query string
        timeout: Query timeout in seconds
        max_results: Max rows to return
    """
    client = _get_client()
    return client.run_aql_search(aql_query, timeout=timeout, max_results=max_results)


@mcp.tool(tags={"readonly"})
def qradar_get_offenses(
    filter_query: Optional[str] = None,
    fields: Optional[str] = None,
    sort: Optional[str] = None,
    start: int = 0,
    limit: int = 50,
) -> dict:
    """List QRadar offenses with optional FQL filter.

    Args:
        filter_query: Optional filter expression
        fields: Comma-separated fields to return
        sort: Sort expression
        start: Pagination offset
        limit: Max offenses to return
    """
    client = _get_client()
    return client.get_offenses(
        filter_query=filter_query, fields=fields, sort=sort, start=start, limit=limit
    )


@mcp.tool(tags={"readonly"})
def qradar_get_offense(offense_id: int, fields: Optional[str] = None) -> dict:
    """Get details for a single QRadar offense.

    Args:
        offense_id: The offense ID
        fields: Optional comma-separated fields to return
    """
    client = _get_client()
    return client.get_offense(offense_id, fields=fields)


@mcp.tool(tags={"readonly"})
def qradar_search_by_ip(
    ip_address: str, hours: int = 24, max_results: int = 100
) -> dict:
    """Search QRadar events involving a specific IP address.

    Args:
        ip_address: IP to search for
        hours: Hours of history to search
        max_results: Max events to return
    """
    client = _get_client()
    return client.search_events_by_ip(ip_address, hours=hours, max_results=max_results)


@mcp.tool(tags={"readonly"})
def qradar_search_by_domain(
    domain: str, hours: int = 24, max_results: int = 100
) -> dict:
    """Search QRadar web proxy events by domain.

    Args:
        domain: Domain to search for
        hours: Hours of history
        max_results: Max events
    """
    client = _get_client()
    return client.search_events_by_domain(domain, hours=hours, max_results=max_results)


@mcp.tool(tags={"readonly"})
def qradar_search_email_by_sender(
    sender_domain: str, hours: int = 168, max_results: int = 100
) -> dict:
    """Search QRadar email events by sender domain.

    Args:
        sender_domain: Sender domain to search for
        hours: Hours of history (default 7 days)
        max_results: Max events
    """
    client = _get_client()
    return client.search_email_by_sender(
        sender_domain, hours=hours, max_results=max_results
    )


@mcp.tool(tags={"readonly"})
def qradar_search_email_by_subject(
    subject_pattern: str, hours: int = 168, max_results: int = 100
) -> dict:
    """Search QRadar email events by subject pattern.

    Args:
        subject_pattern: Subject text to search for
        hours: Hours of history (default 7 days)
        max_results: Max events
    """
    client = _get_client()
    return client.search_email_by_subject(
        subject_pattern, hours=hours, max_results=max_results
    )


@mcp.tool(tags={"readonly"})
def qradar_search_by_hash(
    file_hash: str, hours: int = 168, max_results: int = 100
) -> dict:
    """Search QRadar endpoint events by file hash.

    Args:
        file_hash: File hash to search for
        hours: Hours of history
        max_results: Max events
    """
    client = _get_client()
    return client.search_endpoint_by_hash(
        file_hash, hours=hours, max_results=max_results
    )


@mcp.tool(tags={"readonly"})
def qradar_search_entra_by_user(
    username: str, hours: int = 168, max_results: int = 100
) -> dict:
    """Search QRadar Entra ID (Azure AD) events by username.

    Args:
        username: Username or UPN to search for
        hours: Hours of history
        max_results: Max events
    """
    client = _get_client()
    return client.search_entra_by_user(
        username, hours=hours, max_results=max_results
    )


@mcp.tool(tags={"readonly"})
def qradar_search_zpa_by_user(
    username: str, hours: int = 168, max_results: int = 100
) -> dict:
    """Search QRadar VPN logs logon events by username.

    Args:
        username: Username to search for
        hours: Hours of history
        max_results: Max events
    """
    client = _get_client()
    return client.search_zpa_logons_by_user(
        username, hours=hours, max_results=max_results
    )


@mcp.tool(tags={"readonly"})
def qradar_get_reference_set(name: str) -> dict:
    """Get the values in a QRadar reference set.

    Args:
        name: Reference set name
    """
    client = _get_client()
    return client.get_reference_set(name)


@mcp.tool(tags={"mutating"})
def qradar_add_to_reference_set(
    name: str, value: str, source: Optional[str] = None
) -> dict:
    """Add a value to a QRadar reference set.

    Args:
        name: Reference set name
        value: Value to add
        source: Optional source label
    """
    client = _get_client()
    return client.add_to_reference_set(name, value, source=source)
