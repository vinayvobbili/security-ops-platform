"""
DFIR-IRIS Tools Module

Provides DFIR-IRIS integration for incident response case management.
Supports creating cases, adding IOCs, assets, notes, and timeline events.
"""

import logging
import re
from typing import Optional

from langchain_core.tools import tool

from services.dfir_iris import DFIRIrisClient, format_case_summary, format_case_list
from src.utils.tool_decorator import log_tool_call

logger = logging.getLogger(__name__)

# Lazy-initialized DFIR-IRIS client
_iris_client: Optional[DFIRIrisClient] = None


def _get_iris_client() -> Optional[DFIRIrisClient]:
    """Get DFIR-IRIS client (lazy initialization)."""
    global _iris_client
    if _iris_client is None:
        try:
            client = DFIRIrisClient()
            if client.is_configured():
                _iris_client = client
            else:
                logger.warning("DFIR-IRIS client not configured (missing URL or API key)")
        except Exception as e:
            logger.error(f"Failed to initialize DFIR-IRIS client: {e}")
    return _iris_client


def _parse_severity(severity_str: str) -> int:
    """Parse severity string to integer (DFIR-IRIS uses 1-5)."""
    severity_map = {
        "info": 1, "informational": 1, "1": 1,
        "low": 2, "2": 2,
        "medium": 3, "med": 3, "3": 3,
        "high": 4, "4": 4,
        "critical": 5, "crit": 5, "5": 5,
    }
    return severity_map.get(severity_str.lower().strip(), 3)


def _detect_ioc_type(value: str) -> str:
    """Detect the type of an IOC from its value."""
    value = value.strip()

    # URL
    if value.startswith(("http://", "https://")):
        return "url"

    # IP address
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, value):
        return "ip-dst"

    # Hash (MD5=32, SHA1=40, SHA256=64)
    if re.match(r'^[a-fA-F0-9]{32}$', value):
        return "md5"
    if re.match(r'^[a-fA-F0-9]{40}$', value):
        return "sha1"
    if re.match(r'^[a-fA-F0-9]{64}$', value):
        return "sha256"

    # Email
    if "@" in value and "." in value:
        return "email-dst"

    # Domain (fallback)
    if "." in value:
        return "domain"

    return "other"


@tool
@log_tool_call
def create_iris_case(
    name: str,
    description: str,
    severity: str = "medium",
    tags: str = "",
    soc_id: str = ""
) -> str:
    """Create a new case in DFIR-IRIS for incident tracking.

    Use this tool when:
    - Starting a new incident response investigation
    - Creating a case for forensic analysis
    - Documenting a security incident

    Args:
        name: Case name (e.g., "Malware Investigation - HOST123")
        description: Detailed case description (supports markdown)
        severity: Severity level - "info", "low", "medium", "high", or "critical"
        tags: Comma-separated tags (e.g., "malware,phishing,apt")
        soc_id: External SOC ticket reference (e.g., XSOAR ticket ID)

    Returns:
        Created case details or error message
    """
    client = _get_iris_client()
    if not client:
        return "Error: DFIR-IRIS service is not available. Check configuration."

    severity_int = _parse_severity(severity)
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else None

    result = client.create_case(
        name=name,
        description=description,
        severity_id=severity_int,
        tags=tag_list,
        soc_id=soc_id,
    )

    if isinstance(result, dict) and "error" in result:
        return f"Error creating case: {result['error']}"

    return format_case_summary(result)


@tool
@log_tool_call
def get_iris_case(case_id: int) -> str:
    """Get details of a DFIR-IRIS case.

    Use this tool when:
    - Looking up case information
    - Checking case status
    - Getting case details before updating

    Args:
        case_id: DFIR-IRIS case ID (numeric)

    Returns:
        Case details or error message
    """
    client = _get_iris_client()
    if not client:
        return "Error: DFIR-IRIS service is not available."

    result = client.get_case(case_id)

    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"

    return format_case_summary(result)


@tool
@log_tool_call
def add_ioc_to_iris_case(
    case_id: int,
    ioc_value: str,
    ioc_type: str = "",
    description: str = "",
    tags: str = ""
) -> str:
    """Add an IOC (Indicator of Compromise) to a DFIR-IRIS case.

    Use this tool when:
    - Adding indicators to a case (IPs, domains, hashes, URLs)
    - Documenting IOCs found during investigation
    - Linking threat intelligence to a case

    Args:
        case_id: DFIR-IRIS case ID (numeric)
        ioc_value: The indicator value (IP, domain, hash, URL, etc.)
        ioc_type: Type of IOC - "ip", "domain", "md5", "sha256", "url", "email"
                  (auto-detected if not provided)
        description: Description of the IOC
        tags: Comma-separated tags

    Returns:
        Success message or error
    """
    client = _get_iris_client()
    if not client:
        return "Error: DFIR-IRIS service is not available."

    # Auto-detect type if not provided
    if not ioc_type:
        ioc_type = _detect_ioc_type(ioc_value)

    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else None

    result = client.add_ioc(
        case_id=case_id,
        ioc_value=ioc_value.strip(),
        ioc_type=ioc_type,
        ioc_description=description,
        ioc_tags=tag_list,
    )

    if isinstance(result, dict) and "error" in result:
        return f"Error adding IOC: {result['error']}"

    ioc_id = result.get("ioc_id", "unknown") if isinstance(result, dict) else "unknown"
    return f"Added IOC to case {case_id}:\n- **Type:** {ioc_type}\n- **Value:** {ioc_value}\n- **ID:** {ioc_id}"


@tool
@log_tool_call
def add_note_to_iris_case(case_id: int, title: str, content: str) -> str:
    """Add a note to a DFIR-IRIS case.

    Use this tool when:
    - Documenting investigation findings
    - Adding analysis results to a case
    - Leaving notes for other analysts

    Args:
        case_id: DFIR-IRIS case ID (numeric)
        title: Note title
        content: Note content (supports markdown)

    Returns:
        Success message or error
    """
    client = _get_iris_client()
    if not client:
        return "Error: DFIR-IRIS service is not available."

    result = client.add_note(case_id, title, content)

    if isinstance(result, dict) and "error" in result:
        return f"Error adding note: {result['error']}"

    return f"Added note to case {case_id}: **{title}**"


@tool
@log_tool_call
def add_asset_to_iris_case(
    case_id: int,
    asset_name: str,
    asset_type: str = "host",
    description: str = "",
    ip_address: str = "",
    compromised: bool = False
) -> str:
    """Add an asset (host, user, etc.) to a DFIR-IRIS case.

    Use this tool when:
    - Adding affected hosts to a case
    - Documenting compromised assets
    - Tracking users involved in an incident

    Args:
        case_id: DFIR-IRIS case ID (numeric)
        asset_name: Asset name (hostname, username, etc.)
        asset_type: Type - "host", "account", "server", "network" (default: host)
        description: Description of the asset
        ip_address: IP address if applicable
        compromised: Whether the asset is compromised

    Returns:
        Success message or error
    """
    client = _get_iris_client()
    if not client:
        return "Error: DFIR-IRIS service is not available."

    # Map asset type to ID
    type_map = {
        "account": 1,
        "host": 9,
        "server": 10,
        "network": 6,
        "firewall": 4,
        "user": 1,
    }
    asset_type_id = type_map.get(asset_type.lower(), 9)

    result = client.add_asset(
        case_id=case_id,
        asset_name=asset_name,
        asset_type_id=asset_type_id,
        asset_description=description,
        asset_ip=ip_address,
        asset_compromised=compromised,
    )

    if isinstance(result, dict) and "error" in result:
        return f"Error adding asset: {result['error']}"

    asset_id = result.get("asset_id", "unknown") if isinstance(result, dict) else "unknown"
    status = "COMPROMISED" if compromised else "tracked"
    return f"Added {status} asset to case {case_id}:\n- **Name:** {asset_name}\n- **Type:** {asset_type}\n- **ID:** {asset_id}"


@tool
@log_tool_call
def add_timeline_event_to_iris_case(
    case_id: int,
    event_title: str,
    event_date: str,
    event_content: str = ""
) -> str:
    """Add a timeline event to a DFIR-IRIS case.

    Use this tool when:
    - Building an attack timeline
    - Documenting when events occurred
    - Creating a forensic timeline

    Args:
        case_id: DFIR-IRIS case ID (numeric)
        event_title: Event title (e.g., "Initial compromise detected")
        event_date: Event date/time in ISO format (e.g., "2025-01-15T14:30:00")
        event_content: Detailed event description

    Returns:
        Success message or error
    """
    client = _get_iris_client()
    if not client:
        return "Error: DFIR-IRIS service is not available."

    result = client.add_timeline_event(
        case_id=case_id,
        event_title=event_title,
        event_date=event_date,
        event_content=event_content,
    )

    if isinstance(result, dict) and "error" in result:
        return f"Error adding timeline event: {result['error']}"

    return f"Added timeline event to case {case_id}:\n- **Event:** {event_title}\n- **Date:** {event_date}"


@tool
@log_tool_call
def search_iris_cases(
    limit: int = 20
) -> str:
    """List cases in DFIR-IRIS.

    Use this tool when:
    - Looking for existing cases
    - Listing recent cases
    - Getting an overview of active investigations

    Args:
        limit: Maximum number of results (default: 20)

    Returns:
        List of cases or error
    """
    client = _get_iris_client()
    if not client:
        return "Error: DFIR-IRIS service is not available."

    result = client.list_cases(limit=min(limit, 100))

    if isinstance(result, dict) and "error" in result:
        return f"Error searching cases: {result['error']}"

    if isinstance(result, list):
        return format_case_list(result)

    return format_case_list([])


@tool
@log_tool_call
def close_iris_case(case_id: int) -> str:
    """Close a DFIR-IRIS case.

    Use this tool when:
    - Completing an investigation
    - Closing a case as resolved

    Args:
        case_id: DFIR-IRIS case ID (numeric)

    Returns:
        Success message or error
    """
    client = _get_iris_client()
    if not client:
        return "Error: DFIR-IRIS service is not available."

    result = client.close_case(case_id)

    if isinstance(result, dict) and "error" in result:
        return f"Error closing case: {result['error']}"

    return f"Case {case_id} has been closed."


@tool
@log_tool_call
def create_iris_alert(
    title: str,
    description: str,
    source: str,
    source_ref: str,
    severity: str = "medium",
    iocs: str = ""
) -> str:
    """Create an alert in DFIR-IRIS.

    Use this tool when:
    - Sending automated alerts from detection systems
    - Creating alerts that may be escalated to cases
    - Ingesting external threat intelligence

    Args:
        title: Alert title
        description: Alert description (supports markdown)
        source: Source of the alert (e.g., "Pokedex", "CrowdStrike", "QRadar")
        source_ref: Unique reference ID from the source system
        severity: Severity level - "info", "low", "medium", "high", "critical"
        iocs: Comma-separated IOCs in format "type:value" (e.g., "ip:1.2.3.4,domain:evil.com")

    Returns:
        Created alert details or error
    """
    client = _get_iris_client()
    if not client:
        return "Error: DFIR-IRIS service is not available."

    severity_int = _parse_severity(severity)

    # Parse IOCs
    ioc_list = []
    if iocs:
        for ioc in iocs.split(","):
            ioc = ioc.strip()
            if ":" in ioc:
                ioc_type, ioc_value = ioc.split(":", 1)
                ioc_list.append({
                    "ioc_value": ioc_value.strip(),
                    "ioc_type": ioc_type.strip(),
                })
            else:
                ioc_type = _detect_ioc_type(ioc)
                ioc_list.append({
                    "ioc_value": ioc,
                    "ioc_type": ioc_type,
                })

    result = client.create_alert(
        title=title,
        description=description,
        source=source,
        source_ref=source_ref,
        severity_id=severity_int,
        iocs=ioc_list if ioc_list else None,
    )

    if isinstance(result, dict) and "error" in result:
        return f"Error creating alert: {result['error']}"

    alert_id = result.get("alert_id", "unknown") if isinstance(result, dict) else "unknown"
    return f"Created DFIR-IRIS alert:\n- **ID:** {alert_id}\n- **Title:** {title}\n- **Source:** {source}"


# =============================================================================
# SAMPLE PROMPTS FOR LLM GUIDANCE
# =============================================================================
# Use these prompts to help users discover DFIR-IRIS capabilities:
#
# - "Create a new case in DFIR-IRIS for malware investigation"
# - "Add IP 1.2.3.4 as an IOC to DFIR-IRIS case 5"
# - "List all cases in DFIR-IRIS"
# - "Add a timeline event to case 5 for initial compromise"
# - "Add host WORKSTATION01 as a compromised asset to case 5"
# - "Add a note to DFIR-IRIS case 5 with my findings"
# - "Close DFIR-IRIS case 5"
# - "Create a DFIR-IRIS alert for suspicious activity"
# =============================================================================
