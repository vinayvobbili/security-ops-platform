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


def _resolve_hostname(host_or_employee: str) -> Optional[str]:
    """Resolve a hostname or employee ID to a device hostname via CrowdStrike.

    If the value is already a hostname known to CrowdStrike, it is returned
    as-is; otherwise it is treated as an employee/username and resolved to
    that person's primary device.
    """
    client = _get_cs_client()
    device_id = client.get_device_id(host_or_employee.strip().upper())
    if device_id:
        return host_or_employee.strip().upper()
    try:
        result = client.get_detections(
            limit=1,
            filter_query=f"assigned_to_name:*{host_or_employee}*",
        )
        resources = result.get("resources", [])
        if resources:
            details = client.get_device_details(resources[0])
            return details.get("hostname", host_or_employee)
    except Exception:
        pass
    return host_or_employee


@readonly_tool
@log_tool_call
def oe_get_network_connections(host_or_employee: str, days: int = 30) -> str:
    """Get network connection events for a device from CrowdStrike LogScale.

    Per-host endpoint telemetry. Accepts a HOSTNAME directly (e.g. a host
    surfaced by search_crowdstrike_detections_by_ioc) or an employee
    username, which is resolved to that person's primary device. Use this in
    incident host-sweeps to see what a host connected to (e.g. confirm a host
    actually reached a suspicious domain/IP), and for OE/insider-threat rules
    (non-corporate VPN IPs, unusual external connections).

    Args:
        host_or_employee: Hostname (e.g. PMLIOPSVDI150) or employee username
        days: Number of days of history to query (default 30)
    """
    try:
        hostname = _resolve_hostname(host_or_employee)
        if not hostname:
            return f"Could not resolve a device for '{host_or_employee}'"

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
        return f"Error fetching network connections for {host_or_employee}: {e}"


@readonly_tool
@log_tool_call
def oe_get_process_timeline(host_or_employee: str, days: int = 30) -> str:
    """Get process execution timeline for a device from CrowdStrike LogScale.

    Per-host endpoint telemetry. Accepts a HOSTNAME directly (e.g. a host
    surfaced by search_crowdstrike_detections_by_ioc) or an employee
    username, which is resolved to that person's primary device. Use this in
    incident host-sweeps to see what ran on a host (process chains, command
    lines, parent processes — e.g. what executed after a suspicious download),
    and for OE/insider-threat rules (idle/active cycling, unauthorized tools).

    Args:
        host_or_employee: Hostname (e.g. PMLIOPSVDI150) or employee username
        days: Number of days of history to query (default 30)
    """
    try:
        hostname = _resolve_hostname(host_or_employee)
        if not hostname:
            return f"Could not resolve a device for '{host_or_employee}'"

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
        return f"Error fetching process timeline for {host_or_employee}: {e}"


@readonly_tool
@log_tool_call
def oe_get_installed_software(host_or_employee: str) -> str:
    """Get installed software inventory for a device from Tanium.

    Per-host endpoint telemetry. Accepts a HOSTNAME directly (e.g. a host
    surfaced by search_crowdstrike_detections_by_ioc) or an employee
    username, which is resolved to that person's primary device. Use this in
    incident host-sweeps to see what is installed on a host, and for
    OE/insider-threat rules (unauthorized remote-access tools, personal VPNs).

    Args:
        host_or_employee: Hostname (e.g. PMLIOPSVDI150) or employee username
    """
    try:
        hostname = _resolve_hostname(host_or_employee)
        if not hostname:
            return f"Could not resolve a device for '{host_or_employee}'"

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
        return f"Error fetching installed software for {host_or_employee}: {e}"
