"""Cortex XSIAM / XDR tools."""

import logging
from datetime import datetime, timezone
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


@mcp.tool(tags={"readonly"})
def xsiam_validate() -> dict:
    """Validate XSIAM API key and signing flow."""
    return _get_client().validate_auth()


@mcp.tool(tags={"readonly"})
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


@mcp.tool(tags={"readonly"})
def xsiam_get_incident(incident_id: str, alerts_limit: int = 50) -> dict:
    """Get a single XSIAM incident with related alerts and artifacts.

    Args:
        incident_id: XSIAM incident ID
        alerts_limit: Max related alerts to include
    """
    return _get_client().get_incident_extra_data(
        incident_id, alerts_limit=alerts_limit
    )


@mcp.tool(tags={"mutating"})
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


@mcp.tool(tags={"readonly"})
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


# Disabled to preserve Cortex query token budget. Re-enable by restoring @mcp.tool().
# @mcp.tool(tags={"readonly"})
def xsiam_run_xql(query: str, hours_back: int = 24, limit: int = 1000) -> dict:
    """Run an XQL query against XSIAM and return result rows.

    Use this for ad-hoc dataset searches (e.g. `dataset = proxy_zpa_raw | fields ... | limit 100`).
    Orchestrates start_xql_query, polls get_query_results until the query
    finishes, and pulls the gzipped stream if the result set exceeds the inline
    1000-row cap.

    Args:
        query: XQL query string. Include your own `| limit N` to bound the result.
        hours_back: Look-back window in hours (default 24, max 720). Mapped to _time from/to.
        limit: Max rows to return (default 1000, max 5000). Truncates after fetch — does not push down to XQL.

    Returns:
        dict with keys: query_id, row_count, truncated (bool), rows (list of dicts).
        On error: {"error": "..."}.
    """
    client = _get_client()
    if not client.is_configured():
        return {"error": "XSIAM not configured"}

    hours_back = max(1, min(hours_back, 720))
    limit = max(1, min(limit, 5000))

    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    start = client.start_xql_query(
        query=query,
        time_from_ms=now_ms - hours_back * 3600 * 1000,
        time_to_ms=now_ms,
    )
    if "error" in start:
        return start

    query_id = start.get("reply")
    if not query_id or not isinstance(query_id, str):
        return {"error": f"Unexpected start_xql_query response: {start}"}

    res = client.get_query_results(query_id)
    if "error" in res:
        return res

    results = (res.get("reply") or {}).get("results") or {}
    rows = results.get("data") or []
    stream_id = results.get("stream_id")

    if stream_id:
        stream = client.get_query_results_stream(stream_id)
        if "error" in stream:
            return stream
        rows = stream.get("data") or []

    truncated = len(rows) > limit
    return {
        "query_id": query_id,
        "row_count": len(rows[:limit]),
        "truncated": truncated,
        "rows": rows[:limit],
    }


@mcp.tool(tags={"readonly"})
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
