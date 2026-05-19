"""TheHive case management tools."""

import logging
from typing import Optional

from mcp_server.server import mcp

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        from services.thehive import TheHiveClient
        _client = TheHiveClient()
    return _client


@mcp.tool(tags={"readonly"})
def thehive_search_cases(
    query: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[int] = None,
    tags: Optional[list] = None,
    limit: int = 20,
) -> dict:
    """Search TheHive cases with filters.

    Args:
        query: Free-text search query
        status: Filter by status (e.g. 'Open', 'Resolved')
        severity: Filter by severity (1=Low, 2=Medium, 3=High, 4=Critical)
        tags: Filter by tag list
        limit: Max results
    """
    client = _get_client()
    cases = client.search_cases(
        query=query, status=status, severity=severity, tags=tags, limit=limit
    )
    return {"count": len(cases), "cases": cases}


@mcp.tool(tags={"readonly"})
def thehive_get_case(case_id: str) -> dict:
    """Get full details for a TheHive case.

    Args:
        case_id: The case ID
    """
    client = _get_client()
    return client.get_case(case_id)


@mcp.tool(tags={"mutating"})
def thehive_create_case(
    title: str,
    description: str,
    severity: int = 2,
    tlp: int = 2,
    pap: int = 2,
    tags: Optional[list] = None,
) -> dict:
    """Create a new TheHive case.

    Args:
        title: Case title
        description: Case description
        severity: 1=Low, 2=Medium, 3=High, 4=Critical
        tlp: Traffic Light Protocol (0=White, 1=Green, 2=Amber, 3=Red)
        pap: Permissible Actions Protocol (0=White, 1=Green, 2=Amber, 3=Red)
        tags: Optional list of tags
    """
    client = _get_client()
    return client.create_case(
        title=title,
        description=description,
        severity=severity,
        tlp=tlp,
        pap=pap,
        tags=tags,
    )


@mcp.tool(tags={"mutating"})
def thehive_add_observable(
    case_id: str,
    data_type: str,
    value: str,
    message: str = "",
    tlp: int = 2,
    ioc: bool = False,
    sighted: bool = False,
    tags: Optional[list] = None,
) -> dict:
    """Add an observable to a TheHive case.

    Args:
        case_id: The case ID
        data_type: Observable type (e.g. 'ip', 'domain', 'hash', 'url', 'mail')
        value: Observable value
        message: Optional description
        tlp: Traffic Light Protocol level
        ioc: Whether this is an indicator of compromise
        sighted: Whether this observable has been sighted
        tags: Optional tags
    """
    client = _get_client()
    return client.add_observable(
        case_id=case_id,
        data_type=data_type,
        value=value,
        message=message,
        tlp=tlp,
        ioc=ioc,
        sighted=sighted,
        tags=tags,
    )


@mcp.tool(tags={"mutating"})
def thehive_add_task(
    case_id: str,
    title: str,
    description: str = "",
    status: str = "Waiting",
    flag: bool = False,
) -> dict:
    """Add a task to a TheHive case.

    Args:
        case_id: The case ID
        title: Task title
        description: Task description
        status: Task status ('Waiting', 'InProgress', 'Completed', 'Cancel')
        flag: Whether to flag the task
    """
    client = _get_client()
    return client.add_task(
        case_id=case_id,
        title=title,
        description=description,
        status=status,
        flag=flag,
    )


@mcp.tool(tags={"mutating"})
def thehive_create_alert(
    title: str,
    description: str,
    source: str,
    source_ref: str,
    severity: int = 2,
    tlp: int = 2,
    pap: int = 2,
    alert_type: str = "external",
    tags: Optional[list] = None,
    observables: Optional[list] = None,
) -> dict:
    """Create an alert in TheHive.

    Args:
        title: Alert title
        description: Alert description
        source: Alert source name
        source_ref: Source reference ID
        severity: 1=Low, 2=Medium, 3=High, 4=Critical
        tlp: Traffic Light Protocol level
        pap: Permissible Actions Protocol level
        alert_type: Alert type label
        tags: Optional tags
        observables: Optional list of observable dicts
    """
    client = _get_client()
    return client.create_alert(
        title=title,
        description=description,
        source=source,
        source_ref=source_ref,
        severity=severity,
        tlp=tlp,
        pap=pap,
        alert_type=alert_type,
        tags=tags,
        observables=observables,
    )


@mcp.tool(tags={"mutating"})
def thehive_promote_alert(alert_id: str) -> dict:
    """Promote a TheHive alert to a full case.

    Args:
        alert_id: The alert ID to promote
    """
    client = _get_client()
    return client.promote_alert_to_case(alert_id)


@mcp.tool(tags={"mutating"})
def thehive_add_comment(case_id: str, comment: str) -> dict:
    """Add a comment/note to an existing TheHive case.

    Args:
        case_id: The case ID
        comment: Comment text to add
    """
    client = _get_client()
    return client.add_comment(case_id, comment)


@mcp.tool(tags={"mutating"})
def thehive_update_case(
    case_id: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    severity: Optional[int] = None,
    status: Optional[str] = None,
    tags: Optional[list] = None,
    tlp: Optional[int] = None,
    pap: Optional[int] = None,
) -> dict:
    """Update fields on an existing TheHive case.

    Args:
        case_id: The case ID
        title: New title (optional)
        description: New description (optional)
        severity: New severity 1=Low, 2=Medium, 3=High, 4=Critical (optional)
        status: New status e.g. 'Open', 'Resolved', 'TruePositive' (optional)
        tags: New tag list (optional)
        tlp: New TLP level (optional)
        pap: New PAP level (optional)
    """
    client = _get_client()
    updates = {}
    if title is not None:
        updates["title"] = title
    if description is not None:
        updates["description"] = description
    if severity is not None:
        updates["severity"] = severity
    if status is not None:
        updates["status"] = status
    if tags is not None:
        updates["tags"] = tags
    if tlp is not None:
        updates["tlp"] = tlp
    if pap is not None:
        updates["pap"] = pap
    return client.update_case(case_id, **updates)


@mcp.tool(tags={"mutating"})
def thehive_close_case(
    case_id: str,
    status: str = "TruePositive",
    summary: str = "",
) -> dict:
    """Close a TheHive case with a resolution status.

    Args:
        case_id: The case ID
        status: Resolution status — 'TruePositive', 'FalsePositive', 'Indeterminate'
        summary: Optional closing summary/notes
    """
    client = _get_client()
    return client.close_case(case_id, status=status, summary=summary)
