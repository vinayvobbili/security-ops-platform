"""Vectra NDR tools."""

import logging
from typing import Optional

from mcp_server.server import mcp

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        from services.vectra import VectraClient
        _client = VectraClient()
    return _client


@mcp.tool(tags={"readonly"})
def vectra_get_detections(
    limit: int = 50,
    state: Optional[str] = None,
    threat_gte: Optional[int] = None,
    certainty_gte: Optional[int] = None,
    tags: Optional[str] = None,
    detection_type: Optional[str] = None,
    is_triaged: Optional[bool] = None,
) -> dict:
    """List Vectra network detections with optional filters.

    Args:
        limit: Max detections to return
        state: Filter by state
        threat_gte: Minimum threat score
        certainty_gte: Minimum certainty score
        tags: Filter by tag
        detection_type: Filter by detection type
        is_triaged: Filter by triage status
    """
    client = _get_client()
    return client.get_detections(
        limit=limit,
        state=state,
        threat_gte=threat_gte,
        certainty_gte=certainty_gte,
        tags=tags,
        detection_type=detection_type,
        is_triaged=is_triaged,
    )


@mcp.tool(tags={"readonly"})
def vectra_get_detection(detection_id: int) -> dict:
    """Get details for a specific Vectra detection.

    Args:
        detection_id: The detection ID
    """
    client = _get_client()
    return client.get_detection_by_id(detection_id)


@mcp.tool(tags={"readonly"})
def vectra_search_entity(name: str, entity_type: Optional[str] = None) -> dict:
    """Search Vectra entities by name.

    Args:
        name: Entity name to search for
        entity_type: Optional entity type filter ('host', 'account')
    """
    client = _get_client()
    return client.search_entity_by_name(name, entity_type=entity_type)


@mcp.tool(tags={"readonly"})
def vectra_search_by_ip(ip_address: str) -> dict:
    """Search Vectra entities by IP address.

    Args:
        ip_address: IP address to search for
    """
    client = _get_client()
    return client.search_entity_by_ip(ip_address)


@mcp.tool(tags={"readonly"})
def vectra_get_prioritized(limit: int = 20) -> dict:
    """Get Vectra entities prioritized by risk score.

    Args:
        limit: Max entities to return
    """
    client = _get_client()
    return client.get_prioritized_entities(limit=limit)


@mcp.tool(tags={"mutating"})
def vectra_mark_fixed(detection_id: int) -> dict:
    """Mark a Vectra detection as fixed/resolved.

    Args:
        detection_id: The detection ID to resolve
    """
    client = _get_client()
    return client.mark_detection_as_fixed(detection_id)


@mcp.tool(tags={"readonly"})
def vectra_get_high_threat(min_threat: int = 50, limit: int = 20) -> dict:
    """Get Vectra detections with high threat scores.

    Returns detections above the minimum threat score threshold,
    sorted by threat level. Use this for prioritizing incident response.

    Args:
        min_threat: Minimum threat score to include (default 50, range 0-100)
        limit: Max detections to return
    """
    client = _get_client()
    return client.get_high_threat_detections(min_threat=min_threat, limit=limit)


@mcp.tool(tags={"readonly"})
def vectra_get_entity(entity_id: int) -> dict:
    """Get full details for a specific Vectra entity (host or account).

    Returns entity profile including threat score, certainty score,
    detection history, tags, and associated assignments.

    Args:
        entity_id: The entity ID
    """
    client = _get_client()
    return client.get_entity_by_id(entity_id)
