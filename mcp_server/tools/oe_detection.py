"""OE Detection composite tools.

These are the tools the OE detection rules call directly. They compose data
from underlying services (CrowdStrike LogScale, Tanium).
"""

import logging
from typing import Optional

from mcp_server.server import mcp

logger = logging.getLogger(__name__)

_cs_client = None
_tanium_client = None


def _get_cs_client():
    global _cs_client
    if _cs_client is None:
        from services.crowdstrike import CrowdStrikeClient
        _cs_client = CrowdStrikeClient()
    return _cs_client


def _get_tanium_client():
    global _tanium_client
    if _tanium_client is None:
        from services.tanium import TaniumClient
        _tanium_client = TaniumClient()
    return _tanium_client


def _resolve_hostname(employee_id: str) -> Optional[str]:
    """Resolve an employee ID to their primary device hostname via CrowdStrike.

    Searches CrowdStrike for devices whose assigned user matches the employee_id,
    returning the most recently seen hostname.
    """
    client = _get_cs_client()
    # employee_id could already be a hostname — try device lookup first
    device_id = client.get_device_id(employee_id.strip().upper())
    if device_id:
        return employee_id.strip().upper()

    # Otherwise search by username across devices
    try:
        result = client.get_detections(
            limit=1,
            filter_query=f"assigned_to_name:*{employee_id}*",
        )
        resources = result.get("resources", [])
        if resources:
            details = client.get_device_details(resources[0])
            return details.get("hostname", employee_id)
    except Exception:
        pass

    # Fallback: use the employee_id as-is (may be a hostname already)
    return employee_id


@mcp.tool(tags={"readonly"})
def get_network_connections(
    employee_id: str, days: int = 30, limit: int = 100
) -> dict:
    """Get network connection events for an employee's device from CrowdStrike LogScale.

    Used by OE-NET-001 to detect shared IPs with non-corporate VPN.

    Args:
        employee_id: Employee identifier (username or hostname)
        days: Days of history to query
        limit: Max events to return
    """
    hostname = _resolve_hostname(employee_id)
    if not hostname:
        return {"error": f"Could not resolve device for employee '{employee_id}'"}

    client = _get_cs_client()
    hours = days * 24
    query = (
        f'#event_simpleName=NetworkConnectIP4 '
        f'| ComputerName=/{hostname}/i '
        f'| select([@timestamp, ComputerName, RemoteAddressIP4, RemotePort, '
        f'LocalAddressIP4, LocalPort, Protocol])'
    )
    return client.run_logscale_query(
        query=query,
        start=f"{hours}h",
        end="now",
        limit=limit,
    )


@mcp.tool(tags={"readonly"})
def get_process_timeline(
    employee_id: str, days: int = 30, summary_only: bool = False, limit: int = 100
) -> dict:
    """Get process execution timeline for an employee's device from CrowdStrike LogScale.

    Used by OE-NET-002 to detect idle/active cycling patterns.

    Args:
        employee_id: Employee identifier (username or hostname)
        days: Days of history to query
        summary_only: If true, return only aggregate stats (cycle counts/averages)
        limit: Max events to return
    """
    hostname = _resolve_hostname(employee_id)
    if not hostname:
        return {"error": f"Could not resolve device for employee '{employee_id}'"}

    client = _get_cs_client()
    hours = days * 24
    query = (
        f'#event_simpleName=ProcessRollup2 '
        f'| ComputerName=/{hostname}/i '
        f'| select([@timestamp, ComputerName, ImageFileName, CommandLine, '
        f'UserName, ParentBaseFileName])'
    )
    return client.run_logscale_query(
        query=query,
        start=f"{hours}h",
        end="now",
        limit=limit,
    )


@mcp.tool(tags={"readonly"})
def get_installed_software(employee_id: str) -> dict:
    """Get installed software inventory for an employee's device from Tanium.

    Used by OE-NET-003 to detect unauthorized remote access tools.

    Args:
        employee_id: Employee identifier (username or hostname)
    """
    hostname = _resolve_hostname(employee_id)
    if not hostname:
        return {"error": f"Could not resolve device for employee '{employee_id}'"}

    client = _get_tanium_client()
    computer = client.get_computer_by_name(hostname.strip(), instance_name=None)
    if computer is None:
        return {"error": f"Host '{hostname}' not found in Tanium"}
    return {
        "hostname": computer.name,
        "id": computer.id,
        "ip": computer.ip,
        "os_platform": computer.os_platform,
        "custom_tags": computer.custom_tags,
        "source": computer.source,
    }
