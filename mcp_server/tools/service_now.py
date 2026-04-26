"""ServiceNow ITSM tools."""

import logging

from mcp_server.server import mcp

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        from services.service_now import ServiceNowClient
        _client = ServiceNowClient()
    return _client


@mcp.tool()
def servicenow_get_host(hostname: str) -> dict:
    """Look up a host in the ServiceNow CMDB.

    Args:
        hostname: Hostname to look up
    """
    client = _get_client()
    return client.get_host_details(hostname)


@mcp.tool()
def servicenow_get_incidents(
    assignment_group_name: str, minutes: int = 15
) -> dict:
    """Get recent ServiceNow incidents assigned to a group.

    Args:
        assignment_group_name: Assignment group name
        minutes: Look back window in minutes
    """
    client = _get_client()
    result = client.get_recent_incidents(assignment_group_name, minutes=minutes)
    if isinstance(result, list):
        return {"count": len(result), "incidents": result}
    return result
