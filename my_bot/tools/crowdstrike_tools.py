# /services/crowdstrike_tools.py
"""
CrowdStrike Integration Tools

This module provides CrowdStrike-specific tools for the security operations bot.
All tools focus on defensive security operations including device monitoring,
containment status checking, and device information retrieval.
"""

import logging
import re
from datetime import datetime, timezone
from typing import Optional
from zoneinfo import ZoneInfo

from langchain_core.tools import tool
from my_bot.tools._tagging import readonly_tool, mutating_tool

# Import CrowdStrike client
from services.crowdstrike import CrowdStrikeClient

# Import tool logging decorator
from src.utils.tool_decorator import log_tool_call
from src.utils.llm_decorators import validate_args, HOSTNAME_PATTERN
from my_bot.utils.webex_format import defang

_ET = ZoneInfo("America/New_York")


def _fmt_cs_ts(value) -> str:
    """Render a CrowdStrike ISO-8601 timestamp as Eastern (MM/DD/YYYY H:MM AM/PM EDT).

    CrowdStrike returns last_seen as UTC ISO-8601 (e.g. '2026-06-18T17:20:02Z').
    SOC-facing output shows Eastern; falls back to the raw value if unparseable.
    """
    if not value:
        return "?"
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(_ET)
        hour = dt.strftime("%I").lstrip("0") or "12"
        return dt.strftime(f"%m/%d/%Y {hour}:%M %p %Z")
    except (ValueError, TypeError):
        return str(value)

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


@readonly_tool
@validate_args(hostname=HOSTNAME_PATTERN)
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


@readonly_tool
@validate_args(hostname=HOSTNAME_PATTERN)
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


@readonly_tool
@validate_args(hostname=HOSTNAME_PATTERN)
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
            f"• Last Seen: {_fmt_cs_ts(details.get('last_seen')) if details.get('last_seen') else 'Unknown'}",
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


@readonly_tool
@log_tool_call
def get_crowdstrike_detections(limit: int = 10, status: str = "") -> str:
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


@readonly_tool
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


@readonly_tool
@validate_args(hostname=HOSTNAME_PATTERN)
@log_tool_call
def search_crowdstrike_detections_by_hostname(hostname: str, limit: int = 10) -> str:
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


@readonly_tool
@log_tool_call
def search_crowdstrike_detections_by_ioc(ioc: str, ioc_type: str = "") -> str:
    """Find which hosts observed an IOC (domain, IP, or file hash) in CrowdStrike.

    USE THIS TOOL to pivot from an indicator to the affected endpoints — e.g.
    "which hosts connected to yowgames.com?", "what machines saw this hash/IP?",
    "resolve the hosts that had CrowdStrike detections for <domain>". This is the
    IOC -> hosts lookup that answers "who was affected" BEFORE drilling into
    per-host browser history or process timelines.

    It queries CrowdStrike's IOC "devices ran on" index and returns the
    hostnames (with last-seen, platform, IP) of every managed endpoint that
    observed the indicator.

    Args:
        ioc: The indicator value — a domain (e.g. "yowgames.com"), IPv4/IPv6
            address, or MD5/SHA1/SHA256 hash. Pass the LITERAL IOC from the
            ticket/alert; do NOT invent a domain from a product, extension, or
            campaign name.
        ioc_type: Optional explicit type ('domain','ipv4','ipv6','md5','sha1',
            'sha256'); auto-detected from the value when left blank.
    """
    client = _get_crowdstrike_client()
    if not client:
        return "Error: CrowdStrike service is not available."

    ioc = ioc.strip()
    # Normalize a pasted URL down to its host for domain IOCs.
    if "://" in ioc:
        ioc = ioc.split("://", 1)[1].split("/")[0]

    data = client.get_devices_by_ioc(ioc, ioc_type=(ioc_type.strip() or None))

    if "error" in data:
        return f"Error: {data['error']}"

    hosts = data.get("hosts", [])
    count = data.get("device_count", 0)
    itype = data.get("ioc_type", "unknown")
    # Replies post to Webex — defang the malicious indicator we echo back so it
    # can't auto-link/be clicked. Base it on the service's canonical (refanged)
    # value so a defanged search term isn't double-defanged; host IPs stay intact.
    ioc_disp = defang(data.get("ioc") or ioc)

    # Deep link back to the source so an analyst can click through and verify
    # these results in Falcon Advanced Event Search (pre-filled, no copy-paste).
    # Uses the REAL (refanged) indicator — it rides in a URL the analyst clicks —
    # as a markdown link, which the Webex defang passes leave clickable. Most
    # valuable on the no-hosts path: lets someone confirm a *negative* at source.
    verify_line = None
    try:
        from src.components.tipper_analyzer.formatters import _get_falcon_logscale_link
        _vl = _get_falcon_logscale_link(f'"{data.get("ioc") or ioc}"', window="30d")
        if _vl:
            verify_line = f"🔗 Verify at source: [Open in Falcon Advanced Event Search]({_vl})"
    except Exception:
        verify_line = None

    if not hosts:
        msg = (
            f"No managed CrowdStrike hosts observed IOC `{ioc_disp}` (type: {itype}). "
            "Keep this indicator defanged in any reply.\n"
            "Note: this is the IOC 'devices ran on' index — if the indicator is "
            "brand new, was only seen at the proxy/network layer, or wasn't seen "
            "on a managed endpoint, it won't appear here."
        )
        # Surface the index-vs-tenant gap so the LLM never reports phantom hosts.
        if data.get("note"):
            msg += f"\n{data['note']}"
        if verify_line:
            msg += f"\n{verify_line}"
        return msg

    lines = [
        f"## CrowdStrike hosts that observed `{ioc_disp}` (type: {itype})",
        f"**{count} device(s)** observed this indicator. "
        f"(Keep the indicator `{ioc_disp}` defanged in your reply; host IPs are internal — leave them as-is.)",
        "",
        "_The timestamp on each host is its last CrowdStrike check-in — NOT when "
        "it contacted the indicator. This index records *that* a host observed the "
        "IOC, not *when*; use the per-host DNS/process timeline for contact times._",
        "",
    ]
    for h in hosts:
        hn = h.get("hostname") or "(unknown hostname)"
        lines.append(
            f"- **{hn}** — host last checked in {_fmt_cs_ts(h.get('last_seen'))} · "
            f"{h.get('platform', '?')} · {h.get('local_ip', '?')}"
        )
    lines.append("")
    lines.append(
        "Next step: pull per-host browser history and process timelines for these hosts."
    )
    if verify_line:
        lines.append(verify_line)
    return "\n".join(lines)


@readonly_tool
@validate_args(hostname=HOSTNAME_PATTERN)
@log_tool_call
def get_crowdstrike_host_vulnerabilities(hostname: str, status: str = "open,reopen") -> str:
    """List the Spotlight vulnerabilities exposed on a host (the per-host vuln view).

    USE THIS TOOL when asked "what is this host vulnerable to?", "what CVEs are
    open on <hostname>?", or to assess an endpoint's vulnerability posture during
    triage. Returns vulnerabilities sorted most-severe-first with CVE, ExPRT.AI
    rating, CVSS score, exploit status, affected product and remediation.

    Args:
        hostname: The device hostname (e.g. 'WORKSTATION01'), NOT a ticket ID.
        status: Comma-separated Spotlight statuses to include. Defaults to open +
            reopened; pass "" to include closed/expired too.
    """
    client = _get_crowdstrike_client()
    if not client:
        return "Error: CrowdStrike service is not available."

    hostname = hostname.strip().upper()
    data = client.get_host_vulnerabilities(hostname, status=status)

    if "error" in data:
        return f"Error: {data['error']}"

    vulns = data.get("vulnerabilities", [])
    count = data.get("count", 0)

    if not vulns:
        return (
            f"No Spotlight vulnerabilities (status: {status or 'any'}) found for `{hostname}`. "
            "Either the host is clean for that status filter, or it isn't reporting to Spotlight."
        )

    lines = [
        f"## Spotlight vulnerabilities on `{hostname}`",
        f"**{count} vulnerabilit(ies)** (status: {status or 'any'}), most severe first.",
        "",
    ]
    for v in vulns[:50]:
        cve = v.get("cve_id") or "(no CVE)"
        rating = v.get("exprt_rating") or v.get("cve_severity") or "?"
        score = v.get("cvss_base_score")
        score_str = f"CVSS {score}" if score is not None else "CVSS ?"
        exploit = v.get("exploit_status")
        exploit_str = f" · exploit: {exploit}" if exploit else ""
        product = v.get("product") or "?"
        rems = v.get("remediations") or []
        rem_str = f" · fix: {rems[0]}" if rems else ""
        lines.append(
            f"- **{cve}** [{rating}] {score_str}{exploit_str} · {product}{rem_str}"
        )
    if count > 50:
        lines.append(f"\n…and {count - 50} more (showing top 50 by CVSS).")
    return "\n".join(lines)


@readonly_tool
@log_tool_call
def search_crowdstrike_vulns_by_cve(cve_id: str, status: str = "open,reopen") -> str:
    """Find which hosts are exposed to a CVE in CrowdStrike Spotlight (CVE -> hosts).

    USE THIS TOOL to answer "are we vulnerable to CVE-XXXX, and on which boxes?" —
    the exposure question for advisory / vulnerability triage. Returns the affected
    hostnames with their ExPRT.AI rating, CVSS score and exploit status.

    Args:
        cve_id: The CVE identifier, e.g. "CVE-2024-3094". Pass the literal CVE from
            the advisory; do not invent one.
        status: Comma-separated Spotlight statuses to include (default open +
            reopen); pass "" to include closed/expired.
    """
    client = _get_crowdstrike_client()
    if not client:
        return "Error: CrowdStrike service is not available."

    cve_id = cve_id.strip().upper()
    data = client.search_vulnerabilities_by_cve(cve_id, status=status)

    if "error" in data:
        return f"Error: {data['error']}"

    hosts = data.get("hosts", [])
    count = data.get("host_count", 0)

    if not hosts:
        return (
            f"No CrowdStrike hosts are reporting exposure to `{cve_id}` "
            f"(status: {status or 'any'}). Note: this reflects Spotlight's managed-endpoint "
            "coverage — assets without the Spotlight module won't appear."
        )

    lines = [
        f"## Hosts exposed to `{cve_id}` in CrowdStrike Spotlight",
        f"**{count} host(s)** currently exposed (status: {status or 'any'}).",
        "",
    ]
    for h in hosts[:100]:
        hn = h.get("hostname") or "(unknown hostname)"
        rating = h.get("exprt_rating") or h.get("cve_severity") or "?"
        score = h.get("cvss_base_score")
        score_str = f"CVSS {score}" if score is not None else ""
        exploit = h.get("exploit_status")
        exploit_str = f" · exploit: {exploit}" if exploit else ""
        product = h.get("product") or "?"
        lines.append(
            f"- **{hn}** [{rating}] {score_str}{exploit_str} · {product} · {h.get('local_ip', '?')}"
        )
    if count > 100:
        lines.append(f"\n…and {count - 100} more host(s).")
    return "\n".join(lines)


@readonly_tool
@log_tool_call
def get_crowdstrike_quarantine_files(hostname: str = "", sha256: str = "", status: str = "") -> str:
    """List the files CrowdStrike has quarantined (read-only visibility).

    USE THIS TOOL to answer "what has CrowdStrike quarantined on <hostname>?",
    "is this hash quarantined anywhere?", or to review quarantined files during
    triage. Returns the file hash, host, original path, owning user and state.

    This is READ-ONLY. Releasing or deleting a quarantined file is a human-gated
    response action performed via the MCP tool / console, not by this agent.

    Args:
        hostname: Optional device hostname to scope to.
        sha256: Optional file hash to scope to.
        status: Optional state filter ('quarantined', 'released', 'deleted').
    """
    client = _get_crowdstrike_client()
    if not client:
        return "Error: CrowdStrike service is not available."

    hn = hostname.strip().upper() if hostname.strip() else None
    data = client.query_quarantine_files(
        hostname=hn,
        sha256=(sha256.strip() or None),
        status=(status.strip() or None),
    )

    if "error" in data:
        return f"Error: {data['error']}"

    files = data.get("files", [])
    count = data.get("count", 0)

    scope = hn or sha256.strip() or status.strip() or "the tenant"
    if not files:
        return f"No quarantined files found for {scope}."

    lines = [
        f"## CrowdStrike quarantined files ({scope})",
        f"**{count} file(s)** quarantined.",
        "",
    ]
    for f in files[:50]:
        paths = f.get("paths") or []
        path_str = paths[0] if paths else "(unknown path)"
        lines.append(
            f"- **{f.get('sha256', '?')[:16]}…** [{f.get('state', '?')}] on "
            f"{f.get('hostname', '?')} · {f.get('username', '?')} · {path_str}"
        )
    if count > 50:
        lines.append(f"\n…and {count - 50} more.")
    lines.append("")
    lines.append("To release (false positive) or delete one of these, use the gated quarantine action — not this read-only view.")
    return "\n".join(lines)


@readonly_tool
@log_tool_call
def get_crowdstrike_identity_risk(name: str) -> str:
    """Look up Falcon Identity Protection risk for a user/entity by display name.

    USE THIS TOOL to answer "what's the identity risk for <person>?", "is this
    account risky?", or to pull the identity-risk picture during user-centric
    investigations. Returns the risk score, severity and the contributing risk
    factors (e.g. stale account, weak/duplicate password, attack-path exposure).

    Args:
        name: The entity's display name, e.g. "Jane Doe". Pass the actual
            account/person name, not a hostname or ticket ID.
    """
    client = _get_crowdstrike_client()
    if not client:
        return "Error: CrowdStrike service is not available."

    data = client.get_identity_entity_risk(name.strip())
    if "error" in data:
        return f"Error: {data['error']}"

    entities = data.get("entities", [])
    if not entities:
        return f"No Identity Protection entity found matching `{name}`."

    lines = [f"## Identity Protection risk for `{name}`", ""]
    for e in entities[:10]:
        emails = ", ".join(e.get("emails", [])) or "—"
        lines.append(
            f"- **{e.get('name', '?')}** ({e.get('type', '?')}) · "
            f"risk {e.get('risk_score', '?')} [{e.get('risk_severity', '?')}] · {emails}"
        )
        for rf in (e.get("risk_factors") or [])[:8]:
            lines.append(f"    - risk factor: {rf.get('type', '?')} [{rf.get('severity', '?')}]")
    return "\n".join(lines)


@readonly_tool
@log_tool_call
def get_crowdstrike_high_risk_identities(min_severity: str = "HIGH") -> str:
    """List the highest-risk identities in CrowdStrike Identity Protection.

    USE THIS TOOL to answer "who are our riskiest identities/users right now?" —
    the prioritized identity watchlist for threat hunting. Returns entities
    sorted by risk score with their contributing risk factors.

    Args:
        min_severity: Lowest severity to include ('LOW','MEDIUM','HIGH').
            Defaults to HIGH (most urgent only).
    """
    client = _get_crowdstrike_client()
    if not client:
        return "Error: CrowdStrike service is not available."

    data = client.get_high_risk_identities(min_severity=min_severity.strip().upper() or "HIGH")
    if "error" in data:
        return f"Error: {data['error']}"

    entities = data.get("entities", [])
    sev = data.get("min_severity", "HIGH")
    if not entities:
        return f"No identities at or above {sev} risk severity found."

    lines = [
        f"## Highest-risk identities (≥ {sev} severity)",
        f"**{data.get('count', 0)}** entit(ies), riskiest first.",
        "",
    ]
    for e in entities[:50]:
        factors = ", ".join(rf.get("type", "?") for rf in (e.get("risk_factors") or [])[:4]) or "—"
        lines.append(
            f"- **{e.get('name', '?')}** ({e.get('type', '?')}) · "
            f"risk {e.get('risk_score', '?')} [{e.get('risk_severity', '?')}] · factors: {factors}"
        )
    return "\n".join(lines)


@readonly_tool
@log_tool_call
def get_crowdstrike_incidents(limit: int = 10, status: str = "") -> str:
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


@readonly_tool
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


@mutating_tool
@validate_args(hostname=HOSTNAME_PATTERN)
@log_tool_call
def run_endpoint_command(hostname: str, command: str, timeout: int = 120) -> str:
    """Run an ad-hoc diagnostic command on a live endpoint via CrowdStrike RTR.

    USE THIS TOOL for live host/network diagnostics on a specific Windows host:
    traceroute (e.g. 'tracert -d 8.8.8.8'), 'ipconfig /all', 'route print',
    'netstat -ano', 'ping', 'arp -a', or a short PowerShell one-liner. The command
    runs in PowerShell on the host and the raw text output is returned.

    This is a high-privilege action — it executes a command on a live endpoint — so
    it is restricted to administrators and every attempt is audited. The host must
    be online.

    Args:
        hostname: Target Windows host (e.g. 'US2XB6W64'). Must be online.
        command: Command to run (PowerShell/native), e.g. 'tracert -d -h 20 -w 1000 8.8.8.8'.
        timeout: Max seconds to wait for completion (default 120).
    """
    from services.crowdstrike_rtr import run_rtr_raw_command
    hostname = hostname.strip().upper()
    result = run_rtr_raw_command(hostname, command, timeout=timeout)
    if not result.get("success"):
        return f"❌ RTR command failed on **{hostname}**: {result.get('error') or 'unknown error'}"
    out = (result.get("output") or "").strip() or "(no output)"
    return f"✅ `{command}` on **{hostname}** via CrowdStrike RTR:\n\n```\n{out}\n```"


# Allowlisted read-only endpoint diagnostics. The caller picks a diagnostic by
# name and (where relevant) a target; the actual command is constructed HERE,
# server-side — the caller never supplies a free-text command, which is what
# makes this safe to expose without the admin gate that run_endpoint_command
# needs. Each runs as a fixed native Windows command via RTR runscript (so we get
# real `ipconfig /all` / `netstat -ano` output, unlike the RTR base-tier
# reimplementations which take no args). {target} is filled only with a validated
# host/IP, so nothing the caller supplies can change the command shape.
_ENDPOINT_DIAGNOSTICS = {
    "ipconfig": {"cmd": "ipconfig /all", "target": False},
    "netstat":  {"cmd": "netstat -ano", "target": False},
    "tasklist": {"cmd": "tasklist", "target": False},
    "route":    {"cmd": "route print", "target": False},
    "arp":      {"cmd": "arp -a", "target": False},
    "getmac":   {"cmd": "getmac /v", "target": False},
    "tracert":  {"cmd": "tracert -d -h 20 -w 1000 {target}", "target": True},
    "ping":     {"cmd": "ping -n 4 {target}", "target": True},
    "nslookup": {"cmd": "nslookup {target}", "target": True},
}

# IPv4 / hostname / FQDN only. No spaces or shell metacharacters can pass this,
# so a validated target is safe to substitute into a command template.
_DIAG_TARGET_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")


@readonly_tool
@validate_args(hostname=HOSTNAME_PATTERN)
@log_tool_call
def run_endpoint_diagnostic(hostname: str, diagnostic: str, target: str = "") -> str:
    """Run a safe, read-only network diagnostic on a live endpoint via CrowdStrike RTR.

    USE THIS for live host/network diagnostics that do NOT need an arbitrary
    command: ipconfig, netstat, tasklist, route, arp, getmac, tracert, ping,
    nslookup. The command is fixed server-side — you only choose which diagnostic
    to run and (for tracert/ping/nslookup) a target host or IP. This is read-only
    and open to any analyst. For an arbitrary ad-hoc command, use
    run_endpoint_command (which is admin-only).

    Args:
        hostname: Windows host to run the diagnostic ON (e.g. 'US2XB6W64'). Must be online.
        diagnostic: One of: ipconfig, netstat, tasklist, route, arp, getmac, tracert, ping, nslookup.
        target: Destination host/IP for tracert/ping/nslookup (e.g. '8.8.8.8'). Ignored otherwise.
    """
    diag = (diagnostic or "").strip().lower()
    spec = _ENDPOINT_DIAGNOSTICS.get(diag)
    if not spec:
        allowed = ", ".join(sorted(_ENDPOINT_DIAGNOSTICS))
        return f"❌ Unknown diagnostic '{diagnostic}'. Choose one of: {allowed}."

    hostname = hostname.strip().upper()
    target = (target or "").strip()

    if spec["target"]:
        if not target:
            return f"❌ The '{diag}' diagnostic needs a target host or IP (e.g. '8.8.8.8')."
        if not _DIAG_TARGET_RE.match(target):
            return f"❌ Invalid target '{target}'. Use a plain hostname or IP (letters, digits, dot, hyphen only)."
        command = spec["cmd"].format(target=target)
    else:
        command = spec["cmd"]

    from services.crowdstrike_rtr import run_rtr_raw_command
    result = run_rtr_raw_command(hostname, command)

    if not result.get("success"):
        return f"❌ Diagnostic `{diag}` failed on **{hostname}**: {result.get('error') or 'unknown error'}"
    out = (result.get("output") or "").strip() or "(no output)"
    return f"✅ `{command}` on **{hostname}** via CrowdStrike RTR:\n\n```\n{out}\n```"


@readonly_tool
@validate_args(hostname=HOSTNAME_PATTERN)
@log_tool_call
def collect_browser_history(hostname: str, days: int = 7, platform: str = None) -> str:
    """Collect browser history from a device using CrowdStrike RTR.

    USE THIS TOOL when user asks for browser history, browsing history,
    web history, or visited sites from a specific device/host.

    Args:
        hostname: The target device hostname (e.g., 'LAPTOP123', 'US24J65C4')
        days: Number of days of history to retrieve (default: 7, max: 90)
        platform: Device platform ('Windows' or 'Mac'). Auto-detected if not provided.
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

    # Auto-detect platform if not provided
    if not platform:
        from services.crowdstrike import CrowdStrikeClient
        try:
            cs = CrowdStrikeClient()
            device_id = cs.get_device_id(hostname)
            if device_id:
                details = cs.get_device_details(device_id)
                platform = details.get('platform_name', 'Windows')
        except Exception:
            platform = 'Windows'

    # Pick the right staging script based on platform
    script_name = "Stage_Browser_History_Mac" if platform == 'Mac' else "Stage_Browser_History"

    # Resolve local script path for inline fallback (handles CloudFile cache staleness)
    local_script_path = None
    if platform == 'Mac':
        script_file = Path(__file__).resolve().parent.parent.parent / "data" / "scripts" / "Stage_Browser_History_Mac.sh"
        if script_file.is_file():
            local_script_path = str(script_file)

    # Step 1: Run staging script to copy history files to temp location
    logging.info(f"Staging browser history files on {hostname} (platform={platform})")
    result = run_rtr_script(
        hostname=hostname,
        cloud_script_name=script_name,
        command_line="",
        local_script_path=local_script_path
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

        elif browser.lower() == 'safari':
            # Safari: visit_time is seconds since 2001-01-01 (Core Data epoch)
            core_data_epoch = datetime(2001, 1, 1)
            safari_cutoff = (cutoff_date - core_data_epoch).total_seconds()

            cursor.execute("""
                SELECT hi.url, hv.title, hv.visit_time, hi.visit_count
                FROM history_items hi
                JOIN history_visits hv ON hv.history_item = hi.id
                WHERE hv.visit_time > ?
                ORDER BY hv.visit_time DESC
                LIMIT 1000
            """, (safari_cutoff,))

            for row in cursor.fetchall():
                url, title, visit_time, visit_count = row
                if visit_time:
                    try:
                        ts = core_data_epoch + timedelta(seconds=visit_time)
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

@readonly_tool
@validate_args(hostname=HOSTNAME_PATTERN)
@log_tool_call
def search_falcon_events(
    hostname: str,
    start_time: str = "24h",
    end_time: str = "now",
    query_filter: str = "",
    limit: int = 20
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