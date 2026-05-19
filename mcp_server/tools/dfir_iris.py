"""DFIR-IRIS case management tools."""

import logging
from typing import Optional

from mcp_server.server import mcp

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        from services.dfir_iris import DFIRIrisClient
        _client = DFIRIrisClient()
    return _client


@mcp.tool(tags={"readonly"})
def iris_list_cases(limit: int = 50) -> dict:
    """List all DFIR-IRIS cases.

    Args:
        limit: Max cases to return
    """
    client = _get_client()
    cases = client.list_cases(limit=limit)
    return {"count": len(cases), "cases": cases}


@mcp.tool(tags={"readonly"})
def iris_get_case(case_id: int) -> dict:
    """Get full details for a DFIR-IRIS case.

    Args:
        case_id: The case ID
    """
    client = _get_client()
    return client.get_case(case_id)


@mcp.tool(tags={"mutating"})
def iris_create_case(
    name: str,
    description: str,
    customer_id: int = 1,
    classification_id: int = 1,
    soc_id: str = "",
    severity_id: int = 4,
    tags: Optional[list] = None,
) -> dict:
    """Create a new DFIR-IRIS case.

    Args:
        name: Case name/title
        description: Case description
        customer_id: Customer ID (default 1)
        classification_id: Classification ID (default 1)
        soc_id: Optional SOC ticket reference
        severity_id: Severity (1=Unspecified, 2=Info, 3=Low, 4=Medium, 5=High, 6=Critical)
        tags: Optional list of tag strings
    """
    client = _get_client()
    return client.create_case(
        name=name,
        description=description,
        customer_id=customer_id,
        classification_id=classification_id,
        soc_id=soc_id,
        severity_id=severity_id,
        tags=tags,
    )


@mcp.tool(tags={"mutating"})
def iris_add_ioc(
    case_id: int,
    ioc_value: str,
    ioc_type: str,
    ioc_description: str = "",
    ioc_tlp_id: int = 2,
    ioc_tags: Optional[list] = None,
) -> dict:
    """Add an IOC to a DFIR-IRIS case.

    Args:
        case_id: The case ID
        ioc_value: IOC value (e.g. IP, domain, hash)
        ioc_type: IOC type string (e.g. 'ip-dst', 'domain', 'md5')
        ioc_description: Optional description
        ioc_tlp_id: TLP level (1=Red, 2=Amber, 3=Green, 4=White)
        ioc_tags: Optional list of tags
    """
    client = _get_client()
    return client.add_ioc(
        case_id=case_id,
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        ioc_description=ioc_description,
        ioc_tlp_id=ioc_tlp_id,
        ioc_tags=ioc_tags,
    )


@mcp.tool(tags={"mutating"})
def iris_add_note(
    case_id: int, note_title: str, note_content: str, group_id: int = 1
) -> dict:
    """Add a note to a DFIR-IRIS case.

    Args:
        case_id: The case ID
        note_title: Note title
        note_content: Note body (supports markdown)
        group_id: Note group ID
    """
    client = _get_client()
    return client.add_note(
        case_id=case_id,
        note_title=note_title,
        note_content=note_content,
        group_id=group_id,
    )


@mcp.tool(tags={"mutating"})
def iris_add_timeline(
    case_id: int,
    event_title: str,
    event_date: str,
    event_content: str = "",
    event_category_id: int = 5,
) -> dict:
    """Add a timeline event to a DFIR-IRIS case.

    Args:
        case_id: The case ID
        event_title: Event title
        event_date: Event date/time (ISO 8601)
        event_content: Optional event description
        event_category_id: Event category ID
    """
    client = _get_client()
    return client.add_timeline_event(
        case_id=case_id,
        event_title=event_title,
        event_date=event_date,
        event_content=event_content,
        event_category_id=event_category_id,
    )


@mcp.tool(tags={"mutating"})
def iris_create_alert(
    title: str,
    description: str,
    source: str,
    source_ref: str,
    severity_id: int = 4,
    status_id: int = 2,
    customer_id: int = 1,
    iocs: Optional[list] = None,
) -> dict:
    """Create an alert in DFIR-IRIS.

    Args:
        title: Alert title
        description: Alert description
        source: Alert source (e.g. 'CrowdStrike', 'QRadar')
        source_ref: Source reference ID
        severity_id: Severity level
        status_id: Alert status
        customer_id: Customer ID
        iocs: Optional list of IOC dicts
    """
    client = _get_client()
    return client.create_alert(
        title=title,
        description=description,
        source=source,
        source_ref=source_ref,
        severity_id=severity_id,
        status_id=status_id,
        customer_id=customer_id,
        iocs=iocs,
    )


@mcp.tool(tags={"mutating"})
def iris_add_asset(
    case_id: int,
    asset_name: str,
    asset_type_id: int,
    asset_description: str = "",
    asset_ip: str = "",
    asset_domain: str = "",
    asset_tags: Optional[list] = None,
) -> dict:
    """Add an asset to a DFIR-IRIS case.

    Args:
        case_id: The case ID
        asset_name: Asset name (hostname, username, etc.)
        asset_type_id: Asset type ID (1=Windows, 2=Linux, 3=Mac, 4=Account, etc.)
        asset_description: Optional description
        asset_ip: Optional IP address
        asset_domain: Optional domain
        asset_tags: Optional list of tags
    """
    client = _get_client()
    return client.add_asset(
        case_id=case_id,
        asset_name=asset_name,
        asset_type_id=asset_type_id,
        asset_description=asset_description,
        asset_ip=asset_ip,
        asset_domain=asset_domain,
        asset_tags=asset_tags,
    )


@mcp.tool(tags={"readonly"})
def iris_search_cases(query: str, limit: int = 20) -> dict:
    """Search DFIR-IRIS cases by keyword or filter.

    Args:
        query: Search query (case name, description, or status filter)
        limit: Max results to return
    """
    client = _get_client()
    # list_cases returns all; filter client-side if service lacks search
    cases = client.list_cases(limit=limit)
    if query:
        q_lower = query.lower()
        cases = [
            c for c in cases
            if q_lower in str(c.get("case_name", "")).lower()
            or q_lower in str(c.get("case_description", "")).lower()
        ]
    return {"count": len(cases), "cases": cases}


@mcp.tool(tags={"mutating"})
def iris_close_case(case_id: int) -> dict:
    """Close a DFIR-IRIS case.

    Args:
        case_id: The case ID to close
    """
    client = _get_client()
    return client.close_case(case_id)
