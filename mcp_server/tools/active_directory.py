"""Active Directory user and computer lookup tools (via XSOAR)."""

import logging

from mcp_server.server import mcp

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        from services.active_directory import ActiveDirectoryClient
        _client = ActiveDirectoryClient()
    return _client


@mcp.tool()
def ad_get_user(username: str) -> dict:
    """Look up an Active Directory user by username or email.

    Returns account details including display name, department, manager,
    groups, account status, last logon, and password expiry.
    Queries AD via the XSOAR Active Directory integration.

    Args:
        username: SAM account name, UPN (user@domain), or email address
    """
    client = _get_client()
    return client.get_user(username)


@mcp.tool()
def ad_get_computer(hostname: str) -> dict:
    """Look up an Active Directory computer account by hostname.

    Returns computer account details including OS version, last logon,
    OU path, and account status.
    Queries AD via the XSOAR Active Directory integration.

    Args:
        hostname: Computer hostname (e.g. 'DESKTOP-ABC123')
    """
    client = _get_client()
    return client.get_computer(hostname)
