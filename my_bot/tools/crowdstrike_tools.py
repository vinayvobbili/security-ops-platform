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

# Lazy-initialized CrowdStrike client
_crowdstrike_client: Optional[CrowdStrikeClient] = None


def _get_crowdstrike_client() -> Optional[CrowdStrikeClient]:
    """Get CrowdStrike client (lazy initialization)."""
    global _crowdstrike_client
    if _crowdstrike_client is None:
        try:
            _crowdstrike_client = CrowdStrikeClient()
        except Exception as e:
            logging.error(f"Failed to initialize CrowdStrike client: {e}")
    return _crowdstrike_client


@tool
@log_tool_call
def get_device_containment_status(hostname: str) -> str:
    """Get device containment status from CrowdStrike.

    IMPORTANT: The hostname parameter must be an actual device hostname (e.g., 'WORKSTATION01',
    'SERVER-NYC-001'), NOT a ticket number or ID. If you have a ticket ID, first use
    get_xsoar_ticket to retrieve the ticket and extract the hostname field from it.

    Args:
        hostname: The device hostname to check. Must be a valid hostname, not a ticket ID.
    """
    client = _get_crowdstrike_client()
    if not client:
        return "Error: CrowdStrike service is not available."

    hostname = hostname.strip().upper()
    status = client.get_device_containment_status(hostname)

    if status == 'Host not found in CS console or an error occurred.':
        return f"Hostname '{hostname}' was not found in CrowdStrike."

    if status:
        result = f"Containment status for '{hostname}': {status}"

        # If containment is pending, automatically check online status to explain why
        if status == 'containment_pending':
            online_status = client.get_device_online_state(hostname)
            if online_status:
                result += f"\nDevice online status: {online_status}"
                if online_status == 'offline':
                    result += "\nNote: Containment is pending because the device is offline. It will complete when the device reconnects."
                elif online_status == 'online':
                    result += "\nNote: Device is online but containment is still pending. This may indicate a delay or issue with the CrowdStrike agent."

        return result

    return f"Unable to retrieve containment status for hostname '{hostname}'."


@tool
@log_tool_call
def get_device_online_status(hostname: str) -> str:
    """Get device online status from CrowdStrike.

    IMPORTANT: The hostname must be an actual device hostname (e.g., 'WORKSTATION01'),
    NOT a ticket number. If you have a ticket ID, first fetch the ticket to get the hostname.

    Args:
        hostname: The device hostname to check. Must be a valid hostname, not a ticket ID.
    """
    client = _get_crowdstrike_client()
    if not client:
        return "Error: CrowdStrike service is not available."

    hostname = hostname.strip().upper()
    status = client.get_device_online_state(hostname)

    if status:
        return f"Online status for '{hostname}': {status}"

    return f"Unable to retrieve online status for hostname '{hostname}'. Device may not exist in CrowdStrike."


@tool
@log_tool_call
def get_device_details_cs(hostname: str) -> str:
    """Get detailed device information from CrowdStrike."""
    client = _get_crowdstrike_client()
    if not client:
        return "Error: CrowdStrike service is not available."

    hostname = hostname.strip().upper()
    device_id = client.get_device_id(hostname)

    if not device_id:
        return f"Hostname '{hostname}' was not found in CrowdStrike."

    details = client.get_device_details(device_id)

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
    client = _get_crowdstrike_client()
    if not client:
        return "Error: CrowdStrike service is not available."

    # Validate and cap limit
    limit = min(max(1, limit), 100)

    # Build filter query if status provided
    filter_query = None
    if status:
        filter_query = f"status:'{status}'"

    data = client.get_detections(limit=limit, filter_query=filter_query)

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
    client = _get_crowdstrike_client()
    if not client:
        return "Error: CrowdStrike service is not available."

    data = client.get_detection_by_id(detection_id.strip())

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
    client = _get_crowdstrike_client()
    if not client:
        return "Error: CrowdStrike service is not available."

    hostname = hostname.strip().upper()
    limit = min(max(1, limit), 100)

    data = client.get_detections_by_hostname(hostname, limit=limit)

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
    client = _get_crowdstrike_client()
    if not client:
        return "Error: CrowdStrike service is not available."

    # Validate and cap limit
    limit = min(max(1, limit), 100)

    # Build filter query if status provided
    filter_query = None
    if status:
        filter_query = f"status:'{status}'"

    data = client.get_incidents(limit=limit, filter_query=filter_query)

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
    client = _get_crowdstrike_client()
    if not client:
        return "Error: CrowdStrike service is not available."

    data = client.get_incident_by_id(incident_id.strip())

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
# CROWDSTRIKE RTR (REAL TIME RESPONSE) TOOLS
# =============================================================================

# Threshold for switching from table to Excel file
BROWSER_HISTORY_TABLE_LIMIT = 25

# Module-level variable to track generated file paths for Webex upload
_last_generated_file_path = None


def get_and_clear_generated_file_path():
    """Get the last generated file path and clear it."""
    global _last_generated_file_path
    path = _last_generated_file_path
    _last_generated_file_path = None
    return path


@tool
@log_tool_call
def collect_browser_history(hostname: str, days: int = 7) -> str:
    """Collect browser history from a device using CrowdStrike RTR.

    USE THIS TOOL when user asks for browser history, browsing history,
    web history, or visited sites from a specific device/host.

    Args:
        hostname: The target device hostname (e.g., 'LAPTOP123', 'US24J65C4')
        days: Number of days of history to retrieve (default: 7, max: 90)
    """
    global _last_generated_file_path
    import time
    import sqlite3
    import tempfile
    import os
    from datetime import datetime, timedelta
    from pathlib import Path
    from services.crowdstrike_rtr import run_rtr_script, download_rtr_file

    hostname = hostname.strip().upper()
    days = min(max(1, days), 90)
    cutoff_date = datetime.now() - timedelta(days=days)

    # Step 1: Run staging script to copy history files to temp location
    logging.info(f"Staging browser history files on {hostname}")
    result = run_rtr_script(
        hostname=hostname,
        cloud_script_name="Stage_Browser_History",
        command_line=""
    )

    if not result["success"]:
        error = result["error"]
        if "offline" in error.lower():
            return f"❌ Cannot collect browser history: Device **{hostname}** is offline. RTR requires the device to be online."
        elif "not found" in error.lower():
            return f"❌ Cannot collect browser history: Hostname **{hostname}** was not found in CrowdStrike."
        else:
            return f"❌ Failed to stage browser history from **{hostname}**: {error}"

    output = result["output"]
    if "NO_HISTORY_FILES_FOUND" in output:
        return f"⚠️ No browser history databases found on **{hostname}**."

    # Step 2: Parse staged file paths from output
    staged_files = []
    in_files_section = False
    for line in output.split('\n'):
        line = line.strip()
        if line == "STAGED_FILES_START":
            in_files_section = True
            continue
        if line == "STAGED_FILES_END":
            in_files_section = False
            continue
        if in_files_section and '|' in line:
            parts = line.split('|')
            if len(parts) >= 3:
                staged_files.append({
                    'browser': parts[0],
                    'user': parts[1],
                    'remote_path': parts[2],
                    'size_kb': float(parts[3]) if len(parts) > 3 and parts[3] else 0
                })

    if not staged_files:
        return f"⚠️ No browser history files were staged on **{hostname}**.\n\nOutput: {output[:1000]}"

    logging.info(f"Found {len(staged_files)} staged files on {hostname}")

    # Step 3: Download each file and parse locally
    all_entries = []
    temp_dir = tempfile.mkdtemp(prefix="browser_history_", dir="/tmp")

    try:
        for staged in staged_files:
            remote_path = staged['remote_path']
            browser = staged['browser']
            user = staged['user']
            local_filename = f"{browser}_{user}_{os.path.basename(remote_path)}"
            local_path = os.path.join(temp_dir, local_filename)

            logging.info(f"Downloading {remote_path} from {hostname}")
            download_result = download_rtr_file(hostname, remote_path, local_path)

            if not download_result['success']:
                logging.warning(f"Failed to download {remote_path}: {download_result['error']}")
                continue

            # Step 4: Parse SQLite database
            entries = _parse_sqlite_history(local_path, browser, user, cutoff_date)
            all_entries.extend(entries)
            logging.info(f"Parsed {len(entries)} entries from {browser} ({user})")

    finally:
        # Cleanup temp files
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

    if not all_entries:
        return f"⚠️ No browser history entries found on **{hostname}** for the last {days} days."

    # Sort by timestamp descending
    all_entries.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

    # Step 5: Generate output
    if len(all_entries) > BROWSER_HISTORY_TABLE_LIMIT:
        file_path = save_to_excel(
            all_entries,
            f"browser_history_{hostname}",
            columns=['Browser', 'URL', 'Title', 'Timestamp', 'Visit Count'],
            column_widths={'browser': 20, 'url': 60, 'title': 40, 'timestamp': 20, 'visit count': 12},
            wrap_columns={'url', 'title'},
            date_columns={'timestamp'}
        )
        if file_path:
            _last_generated_file_path = file_path
            return f"✅ Collected **{len(all_entries)}** browser history entries from **{hostname}** (last {days} days). Results saved to Excel file."

    # Return as markdown table
    lines = [f"## 🌐 Browser History from {hostname} (Last {days} days)", ""]
    lines.append("| Time | Browser | URL | Title |")
    lines.append("|------|---------|-----|-------|")
    for entry in all_entries[:BROWSER_HISTORY_TABLE_LIMIT]:
        time_str = entry.get("timestamp", "")[:19]
        browser = entry.get("browser", "")[:15]
        url = entry.get("url", "")[:50] + ("..." if len(entry.get("url", "")) > 50 else "")
        title = entry.get("title", "")[:30] + ("..." if len(entry.get("title", "")) > 30 else "")
        lines.append(f"| {time_str} | {browser} | {url} | {title} |")

    if len(all_entries) > BROWSER_HISTORY_TABLE_LIMIT:
        lines.append(f"\n*Showing {BROWSER_HISTORY_TABLE_LIMIT} of {len(all_entries)} entries*")

    return "\n".join(lines)


def _parse_sqlite_history(db_path: str, browser: str, user: str, cutoff_date) -> list:
    """Parse browser history from a SQLite database file."""
    import sqlite3
    from datetime import datetime, timedelta

    entries = []
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        if browser.lower() in ['chrome', 'edge']:
            # Chrome/Edge: timestamps are WebKit format (microseconds since 1601-01-01)
            # Convert cutoff to WebKit timestamp
            webkit_epoch = datetime(1601, 1, 1)
            webkit_cutoff = int((cutoff_date - webkit_epoch).total_seconds() * 1000000)

            cursor.execute("""
                SELECT url, title, last_visit_time, visit_count
                FROM urls
                WHERE last_visit_time > ?
                ORDER BY last_visit_time DESC
                LIMIT 1000
            """, (webkit_cutoff,))

            for row in cursor.fetchall():
                url, title, visit_time, visit_count = row
                # Convert WebKit timestamp to datetime
                if visit_time:
                    try:
                        ts = datetime(1601, 1, 1) + timedelta(microseconds=visit_time)
                        timestamp = ts.strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        timestamp = str(visit_time)
                else:
                    timestamp = ""

                entries.append({
                    'browser': f"{browser} ({user})",
                    'url': url or "",
                    'title': title or "",
                    'timestamp': timestamp,
                    'visit_count': visit_count or 0
                })

        elif browser.lower() == 'firefox':
            # Firefox: timestamps are microseconds since Unix epoch
            unix_cutoff = int((cutoff_date - datetime(1970, 1, 1)).total_seconds() * 1000000)

            cursor.execute("""
                SELECT url, title, last_visit_date, visit_count
                FROM moz_places
                WHERE last_visit_date > ? AND visit_count > 0
                ORDER BY last_visit_date DESC
                LIMIT 1000
            """, (unix_cutoff,))

            for row in cursor.fetchall():
                url, title, visit_time, visit_count = row
                if visit_time:
                    try:
                        ts = datetime(1970, 1, 1) + timedelta(microseconds=visit_time)
                        timestamp = ts.strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        timestamp = str(visit_time)
                else:
                    timestamp = ""

                entries.append({
                    'browser': f"{browser} ({user})",
                    'url': url or "",
                    'title': title or "",
                    'timestamp': timestamp,
                    'visit_count': visit_count or 0
                })

        conn.close()
    except Exception as e:
        logging.error(f"Error parsing {browser} history: {e}")

    return entries


def is_browser_history_command(message: str) -> tuple[bool, str, int]:
    """Check if message is a browser history command.

    Returns:
        Tuple of (is_command, hostname, days)
    """
    import re
    message_lower = message.lower().strip()

    # Patterns: "browser history <hostname>" or "browser history <hostname> <days>"
    patterns = [
        r"^browser\s+history\s+(\S+)(?:\s+(\d+)\s*(?:days?)?)?$",
        r"^browsing\s+history\s+(\S+)(?:\s+(\d+)\s*(?:days?)?)?$",
        r"^get\s+browser\s+history\s+(?:from\s+)?(\S+)(?:\s+(\d+)\s*(?:days?)?)?$",
        r"^collect\s+browser\s+history\s+(?:from\s+)?(\S+)(?:\s+(\d+)\s*(?:days?)?)?$",
    ]

    for pattern in patterns:
        match = re.match(pattern, message_lower)
        if match:
            hostname = match.group(1).upper()
            days = int(match.group(2)) if match.group(2) else 7
            return True, hostname, days

    return False, "", 0


def _parse_browser_history_output(output: str) -> list[dict]:
    """Parse RTR script output into structured data."""
    entries = []
    lines = output.strip().split('\n')

    for line in lines:
        line = line.strip()
        if not line or line.startswith('===') or line.startswith('Found') or line.startswith('No browser'):
            continue

        # Try to parse table-like output (URL | Title | Visit Time | Count)
        if '|' in line:
            parts = [p.strip() for p in line.split('|')]
            if len(parts) >= 3:
                entries.append({
                    'url': parts[0][:200],  # Truncate long URLs
                    'title': parts[1][:100] if len(parts) > 1 else '',
                    'visit_time': parts[2] if len(parts) > 2 else '',
                    'visit_count': parts[3] if len(parts) > 3 else ''
                })
        # Handle space/tab separated output
        elif '\t' in line:
            parts = line.split('\t')
            if len(parts) >= 2 and parts[0].startswith('http'):
                entries.append({
                    'url': parts[0][:200],
                    'title': parts[1][:100] if len(parts) > 1 else '',
                    'visit_time': parts[2] if len(parts) > 2 else '',
                    'visit_count': parts[3] if len(parts) > 3 else ''
                })

    return entries


def _format_history_as_markdown_table(entries: list[dict], hostname: str, days: int) -> str:
    """Format browser history entries as a Webex markdown table."""
    if not entries:
        return f"No browser history entries found for {hostname} in the last {days} days."

    lines = [
        f"## 🌐 Browser History from {hostname} (Last {days} days)",
        f"Found **{len(entries)}** entries:\n",
        "| URL | Title | Last Visit |",
        "|-----|-------|------------|"
    ]

    for entry in entries[:BROWSER_HISTORY_TABLE_LIMIT]:
        url = entry.get('url', '')[:50] + ('...' if len(entry.get('url', '')) > 50 else '')
        title = entry.get('title', '')[:30] + ('...' if len(entry.get('title', '')) > 30 else '')
        visit_time = entry.get('visit_time', 'N/A')
        lines.append(f"| {url} | {title} | {visit_time} |")

    if len(entries) > BROWSER_HISTORY_TABLE_LIMIT:
        lines.append(f"\n*Showing first {BROWSER_HISTORY_TABLE_LIMIT} of {len(entries)} entries*")

    return '\n'.join(lines)


def save_to_excel(entries: list[dict], filename_prefix: str, columns: list[str] = None,
                   column_widths: dict = None, wrap_columns: set = None, date_columns: set = None) -> str:
    """Save a list of dicts to Excel file with professional formatting.

    Generic utility function for saving data to Excel.

    Args:
        entries: List of dictionaries to save
        filename_prefix: Prefix for the filename (e.g., 'browser_history_HOSTNAME')
        columns: Optional list of column names. If not provided, uses dict keys.
        column_widths: Optional dict mapping column names (lowercase) to widths
        wrap_columns: Optional set of column names (lowercase) that should wrap text
        date_columns: Optional set of column names (lowercase) that contain dates

    Returns:
        Path to the saved Excel file
    """
    import pandas as pd
    from pathlib import Path
    from datetime import datetime
    from src.utils.excel_formatting import apply_professional_formatting

    # Create output directory in /tmp for auto-cleanup
    output_dir = Path("/tmp/excel_exports")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Create filename with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{filename_prefix}_{timestamp}.xlsx"
    filepath = output_dir / filename

    # Create DataFrame and save
    df = pd.DataFrame(entries)
    if columns and len(columns) == len(df.columns):
        df.columns = columns
    df.to_excel(filepath, index=False, engine='openpyxl')

    # Apply professional formatting
    apply_professional_formatting(
        str(filepath),
        column_widths=column_widths,
        wrap_columns=wrap_columns,
        date_columns=date_columns
    )

    return str(filepath)


# =============================================================================
# LogScale Event Search Tool
# =============================================================================

@tool
@log_tool_call
def search_falcon_events(
    hostname: str,
    start_time: str = "24h",
    end_time: str = "now",
    query_filter: str = "",
    limit: int = 50
) -> str:
    """Search CrowdStrike Falcon LogScale events for a specific host.

    Use this tool when users want to search for EDR telemetry events from a specific
    endpoint in CrowdStrike Falcon. This searches the LogScale event store which contains
    detailed endpoint activity like process executions, network connections, file writes, etc.

    Args:
        hostname: The device hostname to search events for (e.g., 'US12345', 'WORKSTATION01')
        start_time: Start of time range. Supports relative times like '24h', '7d', '1h'
                   or absolute ISO timestamps like '2024-01-15T00:00:00Z'. Default: '24h'
        end_time: End of time range. Use 'now' for current time, or relative/absolute times.
                 Default: 'now'
        query_filter: Optional additional LogScale query filter to narrow results.
                     Examples: '#event_simpleName=ProcessRollup2' for process events,
                              '#event_simpleName=NetworkConnectIP4' for network connections,
                              '#event_simpleName=DnsRequest' for DNS queries.
                     Leave empty to get all event types.
        limit: Maximum number of events to return (default: 50, max: 100)

    Returns:
        Formatted string with event results or error message.

    Examples:
        - "Get me events from host US12345 from the last 24 hours"
        - "Search falcon events for WORKSTATION01 from 7d ago"
        - "Get network connection events from SERVER01 in the last hour"
    """
    client = _get_crowdstrike_client()
    if not client:
        return "Error: CrowdStrike service is not available."

    hostname = hostname.strip().upper()
    limit = min(max(1, limit), 100)  # Clamp between 1 and 100

    # Build the LogScale query
    # ComputerName is the field for hostname in Falcon telemetry
    base_query = f'ComputerName="{hostname}"'

    if query_filter:
        # Combine with user-provided filter
        query = f'{query_filter} | {base_query}'
    else:
        query = base_query

    # Add sorting and limit
    query = f'{query} | sort(@timestamp, order=desc, limit={limit})'

    logging.info(f"[LogScale] Searching events for hostname={hostname}, start={start_time}, end={end_time}")

    result = client.run_logscale_query(
        query=query,
        start=start_time,
        end=end_time,
        limit=limit
    )

    # Handle errors
    if result.get('access_denied'):
        if result.get('not_configured'):
            return ("Error: LogScale API is not configured. The cs_foundry_app_id setting "
                    "is required for LogScale queries. Contact your CrowdStrike administrator.")
        return f"Error: LogScale API access denied - {result.get('error', 'missing required scope')}"

    if 'error' in result:
        return f"Error running LogScale query: {result['error']}"

    events = result.get('events', [])
    count = result.get('count', 0)

    if count == 0:
        return (f"No events found for hostname '{hostname}' in the specified time range "
                f"({start_time} to {end_time}).\n\n"
                f"**Query executed:** `{query}`")

    # Format results
    output_lines = [
        f"## Falcon LogScale Events for {hostname}",
        f"**Found {count} event(s)** (showing up to {limit})",
        f"**Time range:** {start_time} to {end_time}",
        f"**Query:** `{query}`",
        ""
    ]

    # Format each event
    for i, event in enumerate(events[:limit], 1):
        event_name = event.get('event_simpleName', event.get('#event_simpleName', 'Unknown'))
        timestamp = event.get('@timestamp', event.get('timestamp', 'N/A'))
        aid = event.get('aid', 'N/A')

        output_lines.append(f"### Event {i}: {event_name}")
        output_lines.append(f"- **Timestamp:** {timestamp}")
        output_lines.append(f"- **Agent ID:** {aid}")

        # Add relevant fields based on event type
        if 'ProcessRollup2' in event_name or 'SyntheticProcessRollup2' in event_name:
            output_lines.append(f"- **File Name:** {event.get('FileName', 'N/A')}")
            output_lines.append(f"- **File Path:** {event.get('FilePath', 'N/A')}")
            output_lines.append(f"- **Command Line:** {event.get('CommandLine', 'N/A')}")
            output_lines.append(f"- **SHA256:** {event.get('SHA256HashData', 'N/A')}")
            output_lines.append(f"- **Parent Process:** {event.get('ParentBaseFileName', 'N/A')}")
        elif 'NetworkConnect' in event_name:
            output_lines.append(f"- **Remote IP:** {event.get('RemoteAddressIP4', event.get('RemoteAddressIP6', 'N/A'))}")
            output_lines.append(f"- **Remote Port:** {event.get('RemotePort', 'N/A')}")
            output_lines.append(f"- **Local Port:** {event.get('LocalPort', 'N/A')}")
            output_lines.append(f"- **Protocol:** {event.get('Protocol', 'N/A')}")
        elif 'DnsRequest' in event_name:
            output_lines.append(f"- **Domain:** {event.get('DomainName', 'N/A')}")
            output_lines.append(f"- **Query Type:** {event.get('QueryType', 'N/A')}")
            output_lines.append(f"- **Response:** {event.get('IP4Records', event.get('IP6Records', 'N/A'))}")
        elif 'FileWrite' in event_name or 'NewExecutable' in event_name:
            output_lines.append(f"- **File Name:** {event.get('FileName', 'N/A')}")
            output_lines.append(f"- **File Path:** {event.get('FilePath', 'N/A')}")
            output_lines.append(f"- **SHA256:** {event.get('SHA256HashData', 'N/A')}")
        else:
            # Generic fields for other event types
            important_fields = ['FileName', 'FilePath', 'CommandLine', 'UserName',
                               'DomainName', 'RemoteAddressIP4', 'SHA256HashData']
            for field in important_fields:
                if field in event and event[field]:
                    output_lines.append(f"- **{field}:** {event[field]}")

        output_lines.append("")

    return '\n'.join(output_lines)


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
# --- RTR Tools ---
# - "Get browser history from HOST123"
# - "Collect browsing history from WORKSTATION01"
# - "Download browser history for LAPTOP-XYZ for the last 14 days"
# - "What websites did HOST123 visit in the last 30 days?"
# - "Pull Chrome/Edge/Firefox history from SERVER01"
#
# --- LogScale Event Search Tools ---
# - "Get me events from host US12345 from the last 24 hours"
# - "Search falcon events for WORKSTATION01 from 7d ago"
# - "Get falcon events from SERVER01"
# - "Show me process events from HOST123 in the last hour"
# - "Search network connections from LAPTOP-XYZ for the last 7 days"
# - "Get DNS requests from HOST123 from 2024-01-15 to now"
# - "What processes ran on WORKSTATION01 yesterday?"
# - "Get all events from HOST123 between 1h ago and now"
#
# =============================================================================