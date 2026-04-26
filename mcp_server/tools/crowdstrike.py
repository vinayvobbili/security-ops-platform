"""CrowdStrike EDR + RTR tools."""

import logging
from typing import Optional

from mcp_server.server import mcp

logger = logging.getLogger(__name__)

_client = None
_write_client = None


def _get_client():
    global _client
    if _client is None:
        from services.crowdstrike import CrowdStrikeClient
        _client = CrowdStrikeClient()
    return _client


def _get_write_client():
    global _write_client
    if _write_client is None:
        from services.crowdstrike import CrowdStrikeClient, CSCredentialProfile
        _write_client = CrowdStrikeClient(credential_profile=CSCredentialProfile.WRITE)
    return _write_client


@mcp.tool()
def crowdstrike_get_device_details(hostname: str) -> dict:
    """Get full device details from CrowdStrike EDR by hostname."""
    client = _get_client()
    device_id = client.get_device_id(hostname.strip().upper())
    if not device_id:
        return {"error": f"Host '{hostname}' not found in CrowdStrike"}
    return client.get_device_details(device_id)


@mcp.tool()
def crowdstrike_get_containment_status(hostname: str) -> dict:
    """Get network containment status for a host."""
    client = _get_client()
    status = client.get_device_containment_status(hostname.strip().upper())
    if status is None:
        return {"error": f"Host '{hostname}' not found in CrowdStrike"}
    return {"hostname": hostname, "containment_status": status}


@mcp.tool()
def crowdstrike_get_online_state(hostname: str) -> dict:
    """Get the online/offline state of a host."""
    client = _get_client()
    state = client.get_device_online_state(hostname.strip().upper())
    if state is None:
        return {"error": f"Host '{hostname}' not found in CrowdStrike"}
    return {"hostname": hostname, "online_state": state}


@mcp.tool()
def crowdstrike_get_detections(
    limit: int = 20,
    filter_query: Optional[str] = None,
    sort: str = "created_timestamp|desc",
) -> dict:
    """Get recent CrowdStrike EDR detections. Optional FQL filter_query."""
    client = _get_client()
    return client.get_detections(limit=limit, filter_query=filter_query, sort=sort)


@mcp.tool()
def crowdstrike_get_detection_details(detection_id: str) -> dict:
    """Get details for a single CrowdStrike detection by ID."""
    client = _get_client()
    return client.get_detection_by_id(detection_id)


@mcp.tool()
def crowdstrike_get_detections_by_host(hostname: str, limit: int = 20) -> dict:
    """Get CrowdStrike detections for a specific hostname."""
    client = _get_client()
    return client.get_detections_by_hostname(hostname.strip().upper(), limit=limit)


@mcp.tool()
def crowdstrike_get_incidents(
    limit: int = 20,
    filter_query: Optional[str] = None,
    sort: str = "start|desc",
) -> dict:
    """Get recent CrowdStrike incidents. Optional FQL filter_query."""
    client = _get_client()
    return client.get_incidents(limit=limit, filter_query=filter_query, sort=sort)


@mcp.tool()
def crowdstrike_get_incident_details(incident_id: str) -> dict:
    """Get details for a single CrowdStrike incident by ID."""
    client = _get_client()
    return client.get_incident_by_id(incident_id)


@mcp.tool()
def crowdstrike_search_ioc(ioc_value: str, ioc_type: Optional[str] = None) -> dict:
    """Search CrowdStrike custom IOC indicators by value. Optional ioc_type filter."""
    client = _get_client()
    return client.search_ioc_by_value(ioc_value, ioc_type=ioc_type)


@mcp.tool()
def crowdstrike_search_by_ip(ip: str, hours: int = 168) -> dict:
    """Search CrowdStrike detections involving a specific IP address."""
    client = _get_client()
    return client.search_detections_by_ip(ip, hours=hours)


@mcp.tool()
def crowdstrike_search_by_hash(file_hash: str, hours: int = 168) -> dict:
    """Search CrowdStrike detections involving a file hash (SHA256/MD5)."""
    client = _get_client()
    return client.search_detections_by_hash(file_hash, hours=hours)


@mcp.tool()
def crowdstrike_search_threatgraph(domain: str) -> dict:
    """Search CrowdStrike ThreatGraph for a domain."""
    client = _get_client()
    return client.search_threatgraph_domain(domain)


@mcp.tool()
def crowdstrike_update_tags(action_name: str, ids: list, tags: list) -> dict:
    """Add or remove grouping tags on CrowdStrike devices.

    Args:
        action_name: 'add' or 'remove'
        ids: List of device IDs
        tags: List of tag strings (e.g. ['FalconGroupingTags/my-tag'])
    """
    client = _get_write_client()
    return client.update_device_tags(action_name, ids, tags)


@mcp.tool()
def crowdstrike_rtr_run_script(
    hostname: str, cloud_script_name: str, command_line: str = ""
) -> dict:
    """Execute a CrowdStrike Real Time Response script on a host.

    Args:
        hostname: Target hostname
        cloud_script_name: Name of the cloud script to execute
        command_line: Optional command line arguments
    """
    from services.crowdstrike_rtr import run_rtr_script
    return run_rtr_script(hostname, cloud_script_name, command_line=command_line)
