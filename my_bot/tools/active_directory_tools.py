"""
Active Directory Tools Module

Provides Active Directory integration via XSOAR war room commands.
Supports querying user account details and computer object attributes.
"""

import logging
from typing import Optional

from langchain_core.tools import tool

from services.active_directory import ActiveDirectoryClient
from src.utils.tool_decorator import log_tool_call

# Lazy-initialized AD client
_ad_client: Optional[ActiveDirectoryClient] = None


def _get_ad_client() -> Optional[ActiveDirectoryClient]:
    """Get Active Directory client (lazy initialization)."""
    global _ad_client
    if _ad_client is None:
        try:
            _ad_client = ActiveDirectoryClient()
        except Exception as e:
            logging.error(f"Failed to initialize Active Directory client: {e}")
    return _ad_client


@tool
@log_tool_call
def get_ad_user(username: str, ticket_id: str) -> str:
    """Fetch Active Directory user object details for a username.

    Use this tool when:
    - User asks about an AD account's status, group memberships, or OU placement
    - User wants to check if an account is enabled or disabled
    - User is investigating whether observed activity matches the account's role
    - User asks "what groups is user X in?" or "is this AD account active?"

    Fires the !ad-get-user command via XSOAR and reads the result from the
    incident context. Requires a valid XSOAR ticket ID to run the command.

    Returns account status, group memberships, OU, last logon, and other AD attributes.

    Args:
        username: sAMAccountName or UPN (domain prefix stripped automatically)
        ticket_id: XSOAR incident ID to run the command against
    """
    client = _get_ad_client()
    if not client:
        return "Error: Active Directory service is not available."

    if not username or not ticket_id:
        return "Error: Both username and ticket_id are required."

    logging.info(f"Fetching AD user details for '{username}' via ticket {ticket_id}")

    user = client.get_user(username=username, ticket_id=ticket_id)

    if user is None:
        return f"No Active Directory user found for `{username}`."

    lines = [
        f"## Active Directory User: `{username}`",
        "",
    ]

    for key, value in user.items():
        if value not in (None, "", [], {}):
            lines.append(f"**{key}:** {value}")

    return "\n".join(lines)


@tool
@log_tool_call
def get_ad_computer(hostname: str, ticket_id: str) -> str:
    """Fetch Active Directory computer object details for a hostname.

    Use this tool when:
    - User asks about a computer's OU placement (workstation vs server)
    - User wants to check OS version, last logon, or enabled status of a machine
    - User is assessing whether an alert matches the host's expected role
    - User asks "what OU is this computer in?" or "what OS does host X run?"

    Fires the !ad-get-computer command via XSOAR and reads the result from the
    incident context. Requires a valid XSOAR ticket ID to run the command.

    Returns OU path, OS version, last logon, enabled status, and other AD attributes.

    Args:
        hostname: Computer name or FQDN (domain suffix stripped automatically)
        ticket_id: XSOAR incident ID to run the command against
    """
    client = _get_ad_client()
    if not client:
        return "Error: Active Directory service is not available."

    if not hostname or not ticket_id:
        return "Error: Both hostname and ticket_id are required."

    logging.info(f"Fetching AD computer details for '{hostname}' via ticket {ticket_id}")

    computer = client.get_computer(hostname=hostname, ticket_id=ticket_id)

    if computer is None:
        return f"No Active Directory computer found for `{hostname}`."

    lines = [
        f"## Active Directory Computer: `{hostname}`",
        "",
    ]

    for key, value in computer.items():
        if value not in (None, "", [], {}):
            lines.append(f"**{key}:** {value}")

    return "\n".join(lines)
