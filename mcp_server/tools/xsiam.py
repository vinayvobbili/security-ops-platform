"""Cortex XSIAM / XDR tools."""

import logging
from typing import Optional

from mcp_server.server import mcp

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        from services.xsiam import XsiamClient

        _client = XsiamClient()
    return _client


@mcp.tool()
def xsiam_validate() -> dict:
    """Validate XSIAM API key and signing flow."""
    return _get_client().validate_auth()


@mcp.tool()
def xsiam_get_incidents(
    hours_back: int = 24, status: Optional[str] = None, limit: int = 50
) -> dict:
    """List Cortex XSIAM incidents.

    Args:
        hours_back: Look-back window in hours (0 = no filter, max 720)
        status: Optional status filter (e.g., "new", "under_investigation")
        limit: Max incidents to return (max 100)
    """
    client = _get_client()
    return client.get_incidents(
        hours=hours_back if hours_back and hours_back > 0 else None,
        status=status,
        limit=limit,
    )


@mcp.tool()
def xsiam_get_incident(incident_id: str, alerts_limit: int = 50) -> dict:
    """Get a single XSIAM incident with related alerts and artifacts.

    Args:
        incident_id: XSIAM incident ID
        alerts_limit: Max related alerts to include
    """
    return _get_client().get_incident_extra_data(
        incident_id, alerts_limit=alerts_limit
    )


@mcp.tool()
def xsiam_update_incident(
    incident_id: str,
    status: Optional[str] = None,
    assigned_user_mail: Optional[str] = None,
    severity: Optional[str] = None,
    resolve_comment: Optional[str] = None,
) -> dict:
    """Update an XSIAM incident. Only provided fields are sent.

    Args:
        incident_id: XSIAM incident ID
        status: e.g. "new", "under_investigation", "resolved_true_positive"
        assigned_user_mail: Email of user to assign
        severity: "informational" | "low" | "medium" | "high" | "critical"
        resolve_comment: Comment when resolving
    """
    return _get_client().update_incident(
        incident_id,
        status=status,
        assigned_user_mail=assigned_user_mail,
        severity=severity,
        resolve_comment=resolve_comment,
    )


@mcp.tool()
def xsiam_get_alerts(
    hours_back: int = 24, severity: Optional[str] = None, limit: int = 100
) -> dict:
    """List Cortex XSIAM alerts (multi-event alert format).

    Args:
        hours_back: Look-back window in hours (max 720)
        severity: Optional severity filter
        limit: Max alerts to return (max 100)
    """
    client = _get_client()
    return client.get_alerts(
        hours=hours_back if hours_back and hours_back > 0 else None,
        severity=severity,
        limit=limit,
    )


@mcp.tool()
def xsiam_get_endpoint(
    hostname: Optional[str] = None,
    ip: Optional[str] = None,
    endpoint_id: Optional[str] = None,
) -> dict:
    """Look up XSIAM endpoints by hostname, IP, or endpoint_id.

    Args:
        hostname: Endpoint hostname
        ip: IPv4 address
        endpoint_id: XSIAM endpoint id
    """
    return _get_client().get_endpoint(
        hostname=hostname, ip=ip, endpoint_id=endpoint_id
    )
