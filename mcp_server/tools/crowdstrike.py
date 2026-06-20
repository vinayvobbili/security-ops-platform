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


@mcp.tool(tags={"readonly"})
def crowdstrike_get_device_details(hostname: str) -> dict:
    """Get full device details from CrowdStrike EDR by hostname."""
    client = _get_client()
    device_id = client.get_device_id(hostname.strip().upper())
    if not device_id:
        return {"error": f"Host '{hostname}' not found in CrowdStrike"}
    return client.get_device_details(device_id)


@mcp.tool(tags={"readonly"})
def crowdstrike_get_containment_status(hostname: str) -> dict:
    """Get network containment status for a host."""
    client = _get_client()
    status = client.get_device_containment_status(hostname.strip().upper())
    if status is None:
        return {"error": f"Host '{hostname}' not found in CrowdStrike"}
    return {"hostname": hostname, "containment_status": status}


@mcp.tool(tags={"readonly"})
def crowdstrike_get_online_state(hostname: str) -> dict:
    """Get the online/offline state of a host."""
    client = _get_client()
    state = client.get_device_online_state(hostname.strip().upper())
    if state is None:
        return {"error": f"Host '{hostname}' not found in CrowdStrike"}
    return {"hostname": hostname, "online_state": state}


@mcp.tool(tags={"readonly"})
def crowdstrike_get_detections(
    limit: int = 20,
    filter_query: Optional[str] = None,
    sort: str = "created_timestamp|desc",
) -> dict:
    """Get recent CrowdStrike EDR detections. Optional FQL filter_query."""
    client = _get_client()
    return client.get_detections(limit=limit, filter_query=filter_query, sort=sort)


@mcp.tool(tags={"readonly"})
def crowdstrike_get_detection_details(detection_id: str) -> dict:
    """Get details for a single CrowdStrike detection by ID."""
    client = _get_client()
    return client.get_detection_by_id(detection_id)


@mcp.tool(tags={"readonly"})
def crowdstrike_get_detections_by_host(hostname: str, limit: int = 20) -> dict:
    """Get CrowdStrike detections for a specific hostname."""
    client = _get_client()
    return client.get_detections_by_hostname(hostname.strip().upper(), limit=limit)


@mcp.tool(tags={"readonly"})
def crowdstrike_get_incidents(
    limit: int = 20,
    filter_query: Optional[str] = None,
    sort: str = "start|desc",
) -> dict:
    """Get recent CrowdStrike incidents. Optional FQL filter_query."""
    client = _get_client()
    return client.get_incidents(limit=limit, filter_query=filter_query, sort=sort)


@mcp.tool(tags={"readonly"})
def crowdstrike_get_incident_details(incident_id: str) -> dict:
    """Get details for a single CrowdStrike incident by ID."""
    client = _get_client()
    return client.get_incident_by_id(incident_id)


@mcp.tool(tags={"readonly"})
def crowdstrike_search_ioc(ioc_value: str, ioc_type: Optional[str] = None) -> dict:
    """Search CrowdStrike custom IOC indicators by value. Optional ioc_type filter."""
    client = _get_client()
    return client.search_ioc_by_value(ioc_value, ioc_type=ioc_type)


@mcp.tool(tags={"readonly"})
def crowdstrike_search_by_ip(ip: str, hours: int = 168) -> dict:
    """Search CrowdStrike detections involving a specific IP address."""
    client = _get_client()
    return client.search_detections_by_ip(ip, hours=hours)


@mcp.tool(tags={"readonly"})
def crowdstrike_search_by_hash(file_hash: str, hours: int = 168) -> dict:
    """Search CrowdStrike detections involving a file hash (SHA256/MD5)."""
    client = _get_client()
    return client.search_detections_by_hash(file_hash, hours=hours)


@mcp.tool(tags={"readonly"})
def crowdstrike_search_threatgraph(domain: str) -> dict:
    """Search CrowdStrike ThreatGraph for a domain."""
    client = _get_client()
    return client.search_threatgraph_domain(domain)


@mcp.tool(tags={"readonly"})
def crowdstrike_get_host_vulnerabilities(
    hostname: str, status: str = "open,reopen", limit: int = 100
) -> dict:
    """List Spotlight vulnerabilities exposed on a host, most severe first.

    Args:
        hostname: Target device hostname.
        status: Comma-separated Spotlight statuses (default 'open,reopen'; '' = all).
        limit: Max vulnerabilities to return.
    """
    client = _get_client()
    return client.get_host_vulnerabilities(hostname.strip().upper(), status=status, limit=limit)


@mcp.tool(tags={"readonly"})
def crowdstrike_search_vulns_by_cve(
    cve_id: str, status: str = "open,reopen", limit: int = 500
) -> dict:
    """Find which hosts are exposed to a CVE via Spotlight (CVE -> hosts pivot).

    Args:
        cve_id: CVE identifier, e.g. 'CVE-2024-3094'.
        status: Comma-separated Spotlight statuses (default 'open,reopen'; '' = all).
        limit: Max records to return.
    """
    client = _get_client()
    return client.search_vulnerabilities_by_cve(cve_id, status=status, limit=limit)


@mcp.tool(tags={"readonly"})
def crowdstrike_get_quarantine_files(
    hostname: Optional[str] = None,
    sha256: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """List files CrowdStrike has quarantined, optionally scoped to a host/hash/status.

    Args:
        hostname: Filter to a single device hostname.
        sha256: Filter to a specific file hash.
        status: Filter by state ('quarantined', 'released', 'deleted').
        limit: Max files to return.
    """
    client = _get_client()
    hn = hostname.strip().upper() if hostname else None
    return client.query_quarantine_files(hostname=hn, sha256=sha256, status=status, limit=limit)


@mcp.tool(tags={"readonly"})
def crowdstrike_get_identity_entity_risk(name: str, limit: int = 10) -> dict:
    """Look up Falcon Identity Protection risk for an entity by display name.

    Returns risk score, severity and contributing risk factors for matching
    user/endpoint entities, riskiest first.

    Args:
        name: Entity display name (user or endpoint).
        limit: Max matching entities to return.
    """
    client = _get_client()
    return client.get_identity_entity_risk(name, limit=limit)


@mcp.tool(tags={"readonly"})
def crowdstrike_get_high_risk_identities(min_severity: str = "HIGH", limit: int = 20) -> dict:
    """List the highest-risk identity entities in the tenant (Identity Protection).

    Args:
        min_severity: Lowest severity to include ('LOW','MEDIUM','HIGH'). Default HIGH.
        limit: Max entities to return.
    """
    client = _get_client()
    return client.get_high_risk_identities(min_severity=min_severity, limit=limit)


@mcp.tool(tags={"mutating"})
def crowdstrike_update_quarantine_files(action: str, ids: list, comment: str = "") -> dict:
    """Release, unrelease, or DELETE quarantined files (mutates endpoint state).

    Args:
        action: One of 'release' (restore — false positive), 'unrelease'
            (re-quarantine), or 'delete' (permanent, irreversible removal).
        ids: List of quarantine file IDs (from crowdstrike_get_quarantine_files).
        comment: Audit comment recorded with the action.
    """
    client = _get_write_client()
    return client.update_quarantine_files(action, ids, comment=comment)


@mcp.tool(tags={"mutating"})
def crowdstrike_update_tags(action_name: str, ids: list, tags: list) -> dict:
    """Add or remove grouping tags on CrowdStrike devices.

    Args:
        action_name: 'add' or 'remove'
        ids: List of device IDs
        tags: List of tag strings (e.g. ['FalconGroupingTags/my-tag'])
    """
    client = _get_write_client()
    return client.update_device_tags(action_name, ids, tags)


@mcp.tool(tags={"mutating"})
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


@mcp.tool(tags={"mutating"})
def crowdstrike_rtr_run_command(
    hostname: str, command: str, timeout: int = 120
) -> dict:
    """Run an ad-hoc command on a live endpoint via CrowdStrike RTR.

    Unlike crowdstrike_rtr_run_script (which runs a pre-uploaded CloudFile), this
    runs an inline command — use for one-off host/network diagnostics such as
    'tracert -d 8.8.8.8', 'ipconfig /all', 'route print', 'netstat -ano', 'ping',
    'arp -a', or a short PowerShell snippet. The command runs in PowerShell on the
    host; raw text output is returned. The host must be online.

    This executes an arbitrary command on a real endpoint — the highest-privilege
    action in the toolset. It is tagged mutating (never exposed to readonly/public
    clients) and, on the Sleuth bot surface, is gated to administrators only.

    Args:
        hostname: Target Windows host (e.g. 'US2XB6W64'). Must be online.
        command: Command to run (PowerShell/native), e.g. 'tracert -d -h 20 -w 1000 8.8.8.8'.
        timeout: Max seconds to wait for completion (default 120).
    """
    from services.crowdstrike_rtr import run_rtr_raw_command
    return run_rtr_raw_command(hostname, command, timeout=timeout)
