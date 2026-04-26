"""Tanium endpoint management tools."""

import logging
from typing import Optional

from mcp_server.server import mcp

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        from services.tanium import TaniumClient
        _client = TaniumClient()
    return _client


def _computer_to_dict(computer) -> dict:
    """Convert a Computer dataclass to a plain dict."""
    if computer is None:
        return None
    return {
        "name": computer.name,
        "id": computer.id,
        "ip": computer.ip,
        "eidLastSeen": computer.eidLastSeen,
        "source": computer.source,
        "os_platform": computer.os_platform,
        "eid_status": computer.eid_status,
        "custom_tags": computer.custom_tags,
    }


@mcp.tool()
def tanium_get_computer(hostname: str, instance: Optional[str] = None) -> dict:
    """Get endpoint details from Tanium by hostname.

    Args:
        hostname: The computer name to look up
        instance: Optional Tanium instance name (uses all instances if omitted)
    """
    client = _get_client()
    computer = client.get_computer_by_name(hostname.strip(), instance_name=instance)
    if computer is None:
        return {"error": f"Host '{hostname}' not found in Tanium"}
    return _computer_to_dict(computer)


@mcp.tool()
def tanium_search_computers(
    search_term: str, instance: Optional[str] = None, limit: int = 10
) -> dict:
    """Search Tanium endpoints by hostname pattern.

    Args:
        search_term: Search string to match against hostnames
        instance: Optional Tanium instance name
        limit: Max results to return
    """
    client = _get_client()
    computers = client.get_computers_by_search(
        search_term, instance_name=instance, limit=limit
    )
    return {"results": [_computer_to_dict(c) for c in computers]}


@mcp.tool()
def tanium_list_signals() -> dict:
    """List all Tanium Threat Response signals across instances."""
    client = _get_client()
    return client.list_all_signals()


@mcp.tool()
def tanium_add_tag(hostname: str, tag: str, instance: Optional[str] = None) -> dict:
    """Add a tag to a Tanium endpoint.

    Args:
        hostname: Target computer name
        tag: Tag string to add
        instance: Optional Tanium instance name
    """
    client = _get_client()
    inst = client.get_instance_by_name(instance) if instance else None
    if instance and inst is None:
        return {"error": f"Tanium instance '{instance}' not found"}
    target = inst or client._instances[0] if client._instances else None
    if target is None:
        return {"error": "No Tanium instances configured"}
    return target.add_tag_by_name(hostname.strip(), tag)


@mcp.tool()
def tanium_remove_tag(hostname: str, tag: str, instance: Optional[str] = None) -> dict:
    """Remove a tag from a Tanium endpoint.

    Args:
        hostname: Target computer name
        tag: Tag string to remove
        instance: Optional Tanium instance name
    """
    client = _get_client()
    inst = client.get_instance_by_name(instance) if instance else None
    if instance and inst is None:
        return {"error": f"Tanium instance '{instance}' not found"}
    target = inst or client._instances[0] if client._instances else None
    if target is None:
        return {"error": "No Tanium instances configured"}
    return target.remove_tag_by_name(hostname.strip(), tag)


@mcp.tool()
def tanium_validate() -> dict:
    """Check connectivity to all configured Tanium instances."""
    client = _get_client()
    return client.validate_all_tokens()
