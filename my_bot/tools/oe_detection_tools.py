"""OE (Operational Environment) detection tools.

Composite tools that draw from CrowdStrike LogScale and Tanium to detect
suspicious activity patterns for insider threat detection rules.
"""

import logging
from typing import Optional

from langchain_core.tools import tool
from my_bot.tools._tagging import readonly_tool, mutating_tool

from src.utils.tool_decorator import log_tool_call

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
    """Resolve employee ID to primary device hostname via CrowdStrike."""
    client = _get_cs_client()
    device_id = client.get_device_id(employee_id.strip().upper())
    if device_id:
        return employee_id.strip().upper()
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
    return employee_id


@readonly_tool
@log_tool_call
def oe_get_network_connections(employee_id: str, days: int = 30) -> str:
    """Get network connection events for an employee's device from CrowdStrike LogScale.

    Used for OE detection rules to identify suspicious network activity patterns,
    such as connections to non-corporate VPN IPs or unusual external connections.

    Args:
        employee_id: Employee username or hostname to investigate
        days: Number of days of history to query (default 30)
    """
    try:
        hostname = _resolve_hostname(employee_id)
        if not hostname:
            return f"Could not resolve device for employee '{employee_id}'"

        client = _get_cs_client()
        hours = days * 24
        query = (
            f'#event_simpleName=NetworkConnectIP4 '
            f'| ComputerName=/{hostname}/i '
            f'| select([@timestamp, ComputerName, RemoteAddressIP4, RemotePort, '
            f'LocalAddressIP4, LocalPort, Protocol])'
        )
        result = client.run_logscale_query(query=query, start=f"{hours}h", end="now", limit=100)
        return str(result)
    except Exception as e:
        logger.error(f"oe_get_network_connections failed: {e}")
        return f"Error fetching network connections for {employee_id}: {e}"


@readonly_tool
@log_tool_call
def oe_get_process_timeline(employee_id: str, days: int = 30) -> str:
    """Get process execution timeline for an employee's device from CrowdStrike LogScale.

    Used for OE detection to identify idle/active cycling patterns, unusual process
    chains, or execution of unauthorized tools.

    Args:
        employee_id: Employee username or hostname to investigate
        days: Number of days of history to query (default 30)
    """
    try:
        hostname = _resolve_hostname(employee_id)
        if not hostname:
            return f"Could not resolve device for employee '{employee_id}'"

        client = _get_cs_client()
        hours = days * 24
        query = (
            f'#event_simpleName=ProcessRollup2 '
            f'| ComputerName=/{hostname}/i '
            f'| select([@timestamp, ComputerName, ImageFileName, CommandLine, '
            f'UserName, ParentBaseFileName])'
        )
        result = client.run_logscale_query(query=query, start=f"{hours}h", end="now", limit=100)
        return str(result)
    except Exception as e:
        logger.error(f"oe_get_process_timeline failed: {e}")
        return f"Error fetching process timeline for {employee_id}: {e}"


@readonly_tool
@log_tool_call
def oe_get_installed_software(employee_id: str) -> str:
    """Get installed software inventory for an employee's device from Tanium.

    Used for OE detection to identify unauthorized remote access tools
    (e.g. personal VPNs, remote desktop apps) installed on corporate devices.

    Args:
        employee_id: Employee username or hostname to investigate
    """
    try:
        hostname = _resolve_hostname(employee_id)
        if not hostname:
            return f"Could not resolve device for employee '{employee_id}'"

        client = _get_tanium_client()
        computer = client.get_computer_by_name(hostname.strip(), instance_name=None)
        if computer is None:
            return f"Host '{hostname}' not found in Tanium"
        return (
            f"Host: {computer.name}\n"
            f"IP: {computer.ip}\n"
            f"OS: {computer.os_platform}\n"
            f"Tags: {computer.custom_tags}"
        )
    except Exception as e:
        logger.error(f"oe_get_installed_software failed: {e}")
        return f"Error fetching installed software for {employee_id}: {e}"
