# /services/crowdstrike_tools.py
"""
CrowdStrike Integration Tools

This module provides CrowdStrike-specific tools for the security operations bot.
All tools focus on defensive security operations including device monitoring,
containment status checking, and device information retrieval.
"""

import logging
from typing import Optional
from langchain_core.tools import tool

# Import CrowdStrike client
from services.crowdstrike import CrowdStrikeClient

# Import tool logging decorator
from src.utils.tool_decorator import log_tool_call

# Initialize CrowdStrike client once
_crowdstrike_client: Optional[CrowdStrikeClient] = None

try:
    logging.info("Initializing CrowdStrike client...")
    _crowdstrike_client = CrowdStrikeClient()
    
    # Test the connection
    token = _crowdstrike_client.get_access_token()
    if token:
        logging.info("CrowdStrike client initialized successfully.")
    else:
        logging.warning("CrowdStrike client failed to get access token. Tools will be disabled.")
        _crowdstrike_client = None
        
except Exception as e:
    logging.error(f"Failed to initialize CrowdStrike client: {e}")
    _crowdstrike_client = None


@tool
@log_tool_call
def get_device_containment_status(hostname: str) -> str:
    """Get device containment status from CrowdStrike."""
    if not _crowdstrike_client:
        return "Error: CrowdStrike service is not initialized."

    hostname = hostname.strip().upper()
    status = _crowdstrike_client.get_device_containment_status(hostname)

    if status == 'Host not found in CS':
        return f"Hostname '{hostname}' was not found in CrowdStrike."

    if status:
        return f"Containment status for '{hostname}': {status}"

    return f"Unable to retrieve containment status for hostname '{hostname}'."


@tool
@log_tool_call
def get_device_online_status(hostname: str) -> str:
    """Get device online status from CrowdStrike."""
    if not _crowdstrike_client:
        return "Error: CrowdStrike service is not initialized."

    hostname = hostname.strip().upper()
    status = _crowdstrike_client.get_device_online_state(hostname)

    if status:
        return f"Online status for '{hostname}': {status}"

    return f"Unable to retrieve online status for hostname '{hostname}'. Device may not exist in CrowdStrike."


@tool
@log_tool_call
def get_device_details_cs(hostname: str) -> str:
    """Get detailed device information from CrowdStrike."""
    if not _crowdstrike_client:
        return "Error: CrowdStrike service is not initialized."

    hostname = hostname.strip().upper()
    device_id = _crowdstrike_client.get_device_id(hostname)

    if not device_id:
        return f"Hostname '{hostname}' was not found in CrowdStrike."

    details = _crowdstrike_client.get_device_details(device_id)

    if details:
        info_parts = [
            f"Device Details for '{hostname}':",
            f"• Device ID: {device_id}",
            f"• Status: {details.get('status', 'Unknown')}",
            f"• Last Seen: {details.get('last_seen', 'Unknown')}",
            f"• OS Version: {details.get('os_version', 'Unknown')}",
            f"• Product Type: {details.get('product_type_desc', 'Unknown')}",
            f"• Chassis Type: {details.get('chassis_type_desc', 'Unknown')}",
        ]

        # Owner/assignment fields
        if details.get('assigned_to_name'):
            info_parts.append(f"• Assigned To: {details.get('assigned_to_name')}")
        if details.get('assigned_to_uid'):
            info_parts.append(f"• Assigned UID: {details.get('assigned_to_uid')}")
        if details.get('email'):
            info_parts.append(f"• Email: {details.get('email')}")
        if details.get('ou'):
            info_parts.append(f"• OU: {', '.join(details.get('ou', []))}")
        if details.get('machine_domain'):
            info_parts.append(f"• Domain: {details.get('machine_domain')}")

        tags = details.get('tags', [])
        if tags:
            info_parts.append(f"• Tags: {', '.join(tags)}")
        else:
            info_parts.append("• Tags: None")

        return "\n".join(info_parts)

    return f"Unable to retrieve detailed information for hostname '{hostname}'."


# =============================================================================
# CROWDSTRIKE DETECTION TOOLS
# =============================================================================


def _get_severity_label(severity: int) -> str:
    """Convert numeric severity to label."""
    if severity >= 80:
        return "CRITICAL"
    elif severity >= 60:
        return "HIGH"
    elif severity >= 40:
        return "MEDIUM"
    elif severity >= 20:
        return "LOW"
    return "INFORMATIONAL"


def _format_cs_detection_result(detections: list) -> str:
    """Format CrowdStrike alert/detection results for display (Alerts API v2)."""
    if not detections:
        return "No CrowdStrike alerts found matching the criteria."

    lines = [f"## CrowdStrike Alerts ({len(detections)} found)", ""]

    for det in detections:
        # New Alerts API field names
        alert_name = det.get("display_name") or det.get("name", "Unknown")
        composite_id = det.get("composite_id", "Unknown")
        severity = det.get("severity", 0)
        severity_name = det.get("severity_name", _get_severity_label(severity))
        status = det.get("status", "unknown")

        # Hostnames (can be multiple)
        hostnames = det.get("host_names") or det.get("source_hosts", [])
        hostname_str = ", ".join(hostnames[:3]) if hostnames else "Unknown"
        if len(hostnames) > 3:
            hostname_str += f" (+{len(hostnames) - 3} more)"

        # MITRE ATT&CK info
        tactic = det.get("tactic", "Unknown")
        technique = det.get("technique", "Unknown")

        # Description
        description = det.get("description", "No description available")

        # Timestamps
        start_time = det.get("start_time", "Unknown")
        end_time = det.get("end_time", "Unknown")

        # Truncate composite ID for display
        display_id = composite_id[:60] + "..." if len(composite_id) > 60 else composite_id

        lines.append(f"### {alert_name}")
        lines.append(f"**ID:** {display_id}")
        lines.append(f"**Hosts:** {hostname_str}")
        lines.append(f"**Severity:** {severity_name} ({severity}/100)")
        lines.append(f"**Status:** {status}")
        lines.append(f"**Tactic:** {tactic} | **Technique:** {technique}")
        lines.append(f"**Started:** {start_time}")
        lines.append(f"**Last Activity:** {end_time}")
        lines.append(f"**Description:** {description[:250]}{'...' if len(description) > 250 else ''}")
        lines.append("")

    return "\n".join(lines)


def _format_cs_incident_result(incidents: list) -> str:
    """Format CrowdStrike incident results for display."""
    if not incidents:
        return "No CrowdStrike incidents found matching the criteria."

    lines = [f"## CrowdStrike Incidents ({len(incidents)} found)", ""]

    # Status mapping for readability
    status_map = {
        "20": "New",
        "25": "Reopened",
        "30": "In Progress",
        "40": "Closed"
    }

    for inc in incidents:
        inc_id = inc.get("incident_id", "Unknown")
        fine_score = inc.get("fine_score", 0)
        severity_label = _get_severity_label(fine_score)
        status_code = str(inc.get("status", ""))
        status = status_map.get(status_code, status_code)

        # Get host info
        hosts = inc.get("hosts", [])
        host_count = len(hosts)
        hostnames = [h.get("hostname", "Unknown") for h in hosts[:3]]

        # Tactics and techniques
        tactics = inc.get("tactics", [])
        techniques = inc.get("techniques", [])

        # Timestamps
        start_time = inc.get("start", "Unknown")
        end_time = inc.get("end", "Unknown")

        lines.append(f"### Incident: {inc_id}")
        lines.append(f"**Severity:** {severity_label} ({fine_score}/100)")
        lines.append(f"**Status:** {status}")
        lines.append(f"**Hosts Involved:** {host_count} ({', '.join(hostnames)}{'...' if host_count > 3 else ''})")
        if tactics:
            lines.append(f"**Tactics:** {', '.join(tactics[:5])}")
        if techniques:
            lines.append(f"**Techniques:** {', '.join(techniques[:5])}")
        lines.append(f"**Started:** {start_time}")
        lines.append(f"**Last Activity:** {end_time}")
        lines.append("")

    return "\n".join(lines)


@tool
@log_tool_call
def get_crowdstrike_detections(limit: int = 20, status: str = "") -> str:
    """Get recent detections from CrowdStrike Falcon EDR platform.

    USE THIS TOOL when the user asks for CrowdStrike detections, CS detections,
    Falcon detections, or EDR detections. This retrieves endpoint threat detections
    from CrowdStrike sorted by most recent activity.

    Do NOT use Vectra tools for CrowdStrike detection requests.

    Args:
        limit: Maximum number of detections to return (default 20, max 100)
        status: Filter by status - "new", "in_progress", "true_positive",
                "false_positive", "closed", or empty for all
    """
    if not _crowdstrike_client:
        return "Error: CrowdStrike service is not initialized."

    # Validate and cap limit
    limit = min(max(1, limit), 100)

    # Build filter query if status provided
    filter_query = None
    if status:
        filter_query = f"status:'{status}'"

    data = _crowdstrike_client.get_detections(limit=limit, filter_query=filter_query)

    if "error" in data:
        return f"Error: {data['error']}"

    detections = data.get("results", [])
    return _format_cs_detection_result(detections)


@tool
@log_tool_call
def get_crowdstrike_detection_details(detection_id: str) -> str:
    """Get detailed information about a specific CrowdStrike alert/detection.

    USE THIS TOOL when user asks for details about a specific CrowdStrike
    alert by ID. Returns full alert info including MITRE info, hosts, and timeline.

    Args:
        detection_id: The CrowdStrike alert composite ID
    """
    if not _crowdstrike_client:
        return "Error: CrowdStrike service is not initialized."

    data = _crowdstrike_client.get_detection_by_id(detection_id.strip())

    if "error" in data:
        return f"Error: {data['error']}"

    det = data
    alert_name = det.get("display_name") or det.get("name", "Unknown")
    composite_id = det.get("composite_id", "Unknown")
    severity = det.get("severity", 0)
    severity_name = det.get("severity_name", _get_severity_label(severity))
    status = det.get("status", "unknown")
    description = det.get("description", "No description available")

    # Hostnames and IPs
    hostnames = det.get("host_names") or det.get("source_hosts", [])
    source_ips = det.get("source_ips", [])
    usernames = det.get("usernames", [])

    lines = [
        f"## CrowdStrike Alert Details",
        "",
        f"**Alert Name:** {alert_name}",
        f"**Composite ID:** {composite_id}",
        f"**Severity:** {severity_name} ({severity}/100)",
        f"**Status:** {status}",
        f"**Type:** {det.get('type', 'Unknown')}",
        f"**Product:** {det.get('product', 'Unknown')}",
        "",
        "### Description",
        description,
        "",
        "### Timeline",
        f"**Started:** {det.get('start_time', 'Unknown')}",
        f"**Last Activity:** {det.get('end_time', 'Unknown')}",
        f"**Created:** {det.get('created_timestamp', 'Unknown')}",
        "",
        "### Affected Systems",
        f"**Hosts:** {', '.join(hostnames) if hostnames else 'Unknown'}",
        f"**Source IPs:** {', '.join(source_ips[:5]) if source_ips else 'N/A'}",
        f"**Users:** {', '.join(usernames[:5]) if usernames else 'N/A'}",
    ]

    # MITRE ATT&CK info
    tactic = det.get("tactic")
    technique = det.get("technique")
    if tactic or technique:
        lines.append("")
        lines.append("### MITRE ATT&CK")
        if tactic:
            lines.append(f"**Tactic:** {tactic} ({det.get('tactic_id', '')})")
        if technique:
            lines.append(f"**Technique:** {technique} ({det.get('technique_id', '')})")

    # Falcon link
    falcon_link = det.get("falcon_host_link")
    if falcon_link:
        lines.append("")
        lines.append(f"**[View in Falcon Console]({falcon_link})**")

    return "\n".join(lines)


@tool
@log_tool_call
def search_crowdstrike_detections_by_hostname(hostname: str, limit: int = 20) -> str:
    """Search CrowdStrike detections for a specific hostname.

    USE THIS TOOL when user asks for CrowdStrike detections on a specific host
    or device. Returns all detections associated with the given hostname.

    Args:
        hostname: The hostname to search for
        limit: Maximum number of detections to return (default 20)
    """
    if not _crowdstrike_client:
        return "Error: CrowdStrike service is not initialized."

    hostname = hostname.strip().upper()
    limit = min(max(1, limit), 100)

    data = _crowdstrike_client.get_detections_by_hostname(hostname, limit=limit)

    if "error" in data:
        return f"Error: {data['error']}"

    detections = data.get("results", [])

    if not detections:
        return f"No CrowdStrike detections found for hostname '{hostname}'."

    return _format_cs_detection_result(detections)


@tool
@log_tool_call
def get_crowdstrike_incidents(limit: int = 20, status: str = "") -> str:
    """Get recent incidents from CrowdStrike Falcon platform.

    USE THIS TOOL when the user asks for CrowdStrike incidents, CS incidents,
    or Falcon incidents. Incidents are aggregated groups of related detections.

    Do NOT use Vectra tools for CrowdStrike incident requests.

    Args:
        limit: Maximum number of incidents to return (default 20, max 100)
        status: Filter by status - "20" (New), "25" (Reopened),
                "30" (In Progress), "40" (Closed), or empty for all
    """
    if not _crowdstrike_client:
        return "Error: CrowdStrike service is not initialized."

    # Validate and cap limit
    limit = min(max(1, limit), 100)

    # Build filter query if status provided
    filter_query = None
    if status:
        filter_query = f"status:'{status}'"

    data = _crowdstrike_client.get_incidents(limit=limit, filter_query=filter_query)

    if "error" in data:
        return f"Error: {data['error']}"

    incidents = data.get("results", [])
    return _format_cs_incident_result(incidents)


@tool
@log_tool_call
def get_crowdstrike_incident_details(incident_id: str) -> str:
    """Get detailed information about a specific CrowdStrike incident.

    USE THIS TOOL when user asks for details about a specific CrowdStrike
    incident by ID. Returns full incident info including hosts, tactics, and timeline.

    Args:
        incident_id: The CrowdStrike incident ID
    """
    if not _crowdstrike_client:
        return "Error: CrowdStrike service is not initialized."

    data = _crowdstrike_client.get_incident_by_id(incident_id.strip())

    if "error" in data:
        return f"Error: {data['error']}"

    inc = data
    inc_id = inc.get("incident_id", "Unknown")
    fine_score = inc.get("fine_score", 0)
    severity_label = _get_severity_label(fine_score)

    status_map = {"20": "New", "25": "Reopened", "30": "In Progress", "40": "Closed"}
    status = status_map.get(str(inc.get("status", "")), str(inc.get("status", "Unknown")))

    lines = [
        f"## CrowdStrike Incident Details",
        "",
        f"**Incident ID:** {inc_id}",
        f"**Severity:** {severity_label} ({fine_score}/100)",
        f"**Status:** {status}",
        "",
        "### Timeline",
        f"**Started:** {inc.get('start', 'Unknown')}",
        f"**Last Activity:** {inc.get('end', 'Unknown')}",
        "",
        "### Hosts Involved",
    ]

    hosts = inc.get("hosts", [])
    for host in hosts[:10]:
        lines.append(f"- **{host.get('hostname', 'Unknown')}** (ID: {host.get('device_id', 'N/A')[:20]}...)")

    tactics = inc.get("tactics", [])
    if tactics:
        lines.append("")
        lines.append("### Tactics")
        lines.append(", ".join(tactics))

    techniques = inc.get("techniques", [])
    if techniques:
        lines.append("")
        lines.append("### Techniques")
        lines.append(", ".join(techniques))

    objectives = inc.get("objectives", [])
    if objectives:
        lines.append("")
        lines.append("### Objectives")
        lines.append(", ".join(objectives))

    return "\n".join(lines)


# =============================================================================
# SAMPLE PROMPTS FOR LLM GUIDANCE
# =============================================================================
# Use these prompts to help users discover CrowdStrike capabilities:
#
# --- Device Tools ---
# - "Check CrowdStrike containment status for HOST123"
# - "Is HOST123 contained in CrowdStrike?"
# - "Get CrowdStrike device details for SERVER01"
# - "Is LAPTOP-XYZ online in CrowdStrike?"
# - "What's the status of HOST123 in CrowdStrike?"
# - "Look up HOST123 in CrowdStrike"
# - "Who owns WORKSTATION-001 according to CrowdStrike?"
# - "Check online status for HOST123 in CS"
#
# --- Detection Tools ---
# - "Get me the latest detections from CrowdStrike"
# - "Show CrowdStrike detections"
# - "What are the recent CS detections?"
# - "Get CrowdStrike Falcon detections"
# - "Show me EDR detections from CrowdStrike"
# - "Get CrowdStrike detections for HOST123"
# - "Search CrowdStrike detections by hostname WORKSTATION01"
# - "Get details for CrowdStrike detection ldt:abc123:456"
#
# --- Incident Tools ---
# - "Get me the latest incidents from CrowdStrike"
# - "Show CrowdStrike incidents"
# - "What are the recent CS incidents?"
# - "Get new CrowdStrike incidents"
# - "Show me CrowdStrike Falcon incidents"
# - "Get details for CrowdStrike incident inc:abc123"
#
# =============================================================================