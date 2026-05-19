"""Varonis DatAlert data activity monitoring tools."""

import logging

from mcp_server.server import mcp

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        from services.varonis import VaronisClient
        _client = VaronisClient()
    return _client


@mcp.tool(tags={"readonly"})
def varonis_get_user_alerts(username: str, days: int = 7) -> dict:
    """Get Varonis security alerts for a specific user.

    Returns DatAlert security alerts triggered by the user's data access
    activity, including access violations, ransomware indicators, and
    abnormal behavior patterns.

    Args:
        username: Username or SAM account name to check
        days: Number of days back to query (default 7)
    """
    client = _get_client()
    return client.get_user_alerts(username, days=days)


@mcp.tool(tags={"readonly"})
def varonis_get_data_activity(username: str, days: int = 7) -> dict:
    """Get Varonis data access activity for a user.

    Returns file and folder access events for the user, showing which
    data stores were accessed, what files were read/modified/deleted,
    and access patterns over time.

    Args:
        username: Username or SAM account name to check
        days: Number of days back to query (default 7)
    """
    client = _get_client()
    return client.get_data_activity(username, days=days)
