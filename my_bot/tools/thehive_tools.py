"""
TheHive Tools Module

Provides TheHive integration for case management operations.
Supports creating cases, adding observables, updating cases, and searching.
"""

import logging
import re
from typing import Optional

from langchain_core.tools import tool

from services.thehive import TheHiveClient, format_case_summary, format_case_list
from src.utils.tool_decorator import log_tool_call

logger = logging.getLogger(__name__)

# Lazy-initialized TheHive client
_thehive_client: Optional[TheHiveClient] = None


def _get_thehive_client() -> Optional[TheHiveClient]:
    """Get TheHive client (lazy initialization)."""
    global _thehive_client
    if _thehive_client is None:
        try:
            client = TheHiveClient()
            if client.is_configured():
                _thehive_client = client
            else:
                logger.warning("TheHive client not configured (missing URL or API key)")
        except Exception as e:
            logger.error(f"Failed to initialize TheHive client: {e}")
    return _thehive_client


def _parse_severity(severity_str: str) -> int:
    """Parse severity string to integer."""
    severity_map = {
        "low": 1, "1": 1,
        "medium": 2, "2": 2, "med": 2,
        "high": 3, "3": 3,
        "critical": 4, "4": 4, "crit": 4,
    }
    return severity_map.get(severity_str.lower().strip(), 2)


def _detect_observable_type(value: str) -> str:
    """Detect the type of an observable from its value."""
    value = value.strip()

    # URL
    if value.startswith(("http://", "https://")):
        return "url"

    # IP address
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, value):
        return "ip"

    # Hash (MD5=32, SHA1=40, SHA256=64)
    hash_pattern = r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'
    if re.match(hash_pattern, value):
        return "hash"

    # Email
    if "@" in value and "." in value:
        return "mail"

    # Domain (fallback)
    if "." in value:
        return "domain"

    return "other"


@tool
@log_tool_call
def create_thehive_case(
    title: str,
    description: str,
    severity: str = "medium",
    tags: str = ""
) -> str:
    """Create a new case in TheHive for incident tracking.

    Use this tool when:
    - Starting a new investigation that needs tracking
    - Creating a case from an IOC investigation
    - Documenting a security incident

    Args:
        title: Case title (e.g., "Malware Investigation - HOST123")
        description: Detailed case description (supports markdown)
        severity: Severity level - "low", "medium", "high", or "critical" (default: medium)
        tags: Comma-separated tags (e.g., "malware,phishing,apt")

    Returns:
        Created case details or error message
    """
    client = _get_thehive_client()
    if not client:
        return "Error: TheHive service is not available. Check configuration."

    # Parse severity
    severity_int = _parse_severity(severity)

    # Parse tags
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []

    result = client.create_case(
        title=title,
        description=description,
        severity=severity_int,
        tags=tag_list,
    )

    if "error" in result:
        return f"Error creating case: {result['error']}"

    return format_case_summary(result)


@tool
@log_tool_call
def get_thehive_case(case_id: str) -> str:
    """Get details of a TheHive case.

    Use this tool when:
    - Looking up case information
    - Checking case status
    - Getting case details before updating

    Args:
        case_id: TheHive case ID (e.g., "~123456") or case number

    Returns:
        Case details or error message
    """
    client = _get_thehive_client()
    if not client:
        return "Error: TheHive service is not available."

    # Handle case number vs case ID
    case_id = case_id.strip()
    if not case_id.startswith("~"):
        # Try to find by case number - for now just prepend ~
        # In a real implementation, you'd search for the case
        pass

    result = client.get_case(case_id)

    if "error" in result:
        return f"Error: {result['error']}"

    return format_case_summary(result)


@tool
@log_tool_call
def add_observable_to_thehive_case(
    case_id: str,
    observable_value: str,
    observable_type: str = "",
    description: str = "",
    is_ioc: bool = True,
    tags: str = ""
) -> str:
    """Add an observable (IOC) to a TheHive case.

    Use this tool when:
    - Adding indicators to a case (IPs, domains, hashes, URLs)
    - Documenting IOCs found during investigation
    - Linking threat intelligence to a case

    Args:
        case_id: TheHive case ID (e.g., "~123456")
        observable_value: The indicator value (IP, domain, hash, URL, etc.)
        observable_type: Type of observable - "ip", "domain", "hash", "url", "mail", "hostname"
                        (auto-detected if not provided)
        description: Description of the observable
        is_ioc: Whether this is an IOC (default: True)
        tags: Comma-separated tags

    Returns:
        Success message or error
    """
    client = _get_thehive_client()
    if not client:
        return "Error: TheHive service is not available."

    # Auto-detect type if not provided
    if not observable_type:
        observable_type = _detect_observable_type(observable_value)

    # Parse tags
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []

    result = client.add_observable(
        case_id=case_id.strip(),
        data_type=observable_type,
        value=observable_value.strip(),
        message=description,
        ioc=is_ioc,
        tags=tag_list,
    )

    # Handle both dict and list responses from TheHive API
    if isinstance(result, dict) and "error" in result:
        return f"Error adding observable: {result['error']}"

    # TheHive may return a list with the created observable
    if isinstance(result, list) and len(result) > 0:
        result = result[0]

    obs_id = result.get("_id", "unknown") if isinstance(result, dict) else "unknown"
    return f"✅ Added observable to case {case_id}:\n- **Type:** {observable_type}\n- **Value:** {observable_value}\n- **ID:** {obs_id}"


@tool
@log_tool_call
def add_comment_to_thehive_case(case_id: str, comment: str) -> str:
    """Add a comment/note to a TheHive case.

    Use this tool when:
    - Documenting investigation findings
    - Adding analysis results to a case
    - Leaving notes for other analysts

    Args:
        case_id: TheHive case ID (e.g., "~123456")
        comment: Comment text (supports markdown)

    Returns:
        Success message or error
    """
    client = _get_thehive_client()
    if not client:
        return "Error: TheHive service is not available."

    result = client.add_comment(case_id.strip(), comment)

    if "error" in result:
        return f"Error adding comment: {result['error']}"

    return f"✅ Added comment to case {case_id}"


@tool
@log_tool_call
def update_thehive_case(
    case_id: str,
    status: str = "",
    severity: str = "",
    title: str = "",
    tags: str = ""
) -> str:
    """Update a TheHive case.

    Use this tool when:
    - Changing case status (e.g., to InProgress or Resolved)
    - Updating case severity
    - Modifying case title or tags

    Args:
        case_id: TheHive case ID (e.g., "~123456")
        status: New status - "New", "InProgress", "Resolved", "Closed" (optional)
        severity: New severity - "low", "medium", "high", "critical" (optional)
        title: New title (optional)
        tags: Comma-separated tags to set (optional)

    Returns:
        Updated case details or error
    """
    client = _get_thehive_client()
    if not client:
        return "Error: TheHive service is not available."

    # Build update parameters
    kwargs = {}

    if status:
        kwargs["status"] = status
    if severity:
        kwargs["severity"] = _parse_severity(severity)
    if title:
        kwargs["title"] = title
    if tags:
        kwargs["tags"] = [t.strip() for t in tags.split(",") if t.strip()]

    if not kwargs:
        return "Error: No update fields provided. Specify status, severity, title, or tags."

    result = client.update_case(case_id.strip(), **kwargs)

    if "error" in result:
        return f"Error updating case: {result['error']}"

    return format_case_summary(result)


@tool
@log_tool_call
def close_thehive_case(
    case_id: str,
    resolution: str = "TruePositive",
    summary: str = ""
) -> str:
    """Close a TheHive case.

    Use this tool when:
    - Completing an investigation
    - Closing a case as resolved

    Args:
        case_id: TheHive case ID (e.g., "~123456")
        resolution: Resolution status - "TruePositive", "FalsePositive", "Indeterminate", "Other"
        summary: Closing summary describing the resolution

    Returns:
        Success message or error
    """
    client = _get_thehive_client()
    if not client:
        return "Error: TheHive service is not available."

    result = client.close_case(
        case_id=case_id.strip(),
        resolution_status=resolution,
        summary=summary,
    )

    if "error" in result:
        return f"Error closing case: {result['error']}"

    return f"✅ Case {case_id} closed as **{resolution}**"


@tool
@log_tool_call
def search_thehive_cases(
    query: str = "",
    status: str = "",
    severity: str = "",
    limit: int = 10
) -> str:
    """Search for cases in TheHive.

    Use this tool when:
    - Looking for existing cases
    - Finding cases by keyword
    - Listing recent cases

    Args:
        query: Search query (searches in title)
        status: Filter by status - "New", "InProgress", "Resolved", "Closed"
        severity: Filter by severity - "low", "medium", "high", "critical"
        limit: Maximum number of results (default: 10)

    Returns:
        List of matching cases or error
    """
    client = _get_thehive_client()
    if not client:
        return "Error: TheHive service is not available."

    # Parse severity if provided
    severity_int = _parse_severity(severity) if severity else None

    result = client.search_cases(
        query=query if query else None,
        status=status if status else None,
        severity=severity_int,
        limit=min(limit, 50),
    )

    # Handle error dict
    if isinstance(result, dict) and "error" in result:
        return f"Error searching cases: {result['error']}"

    # Handle list of cases
    if isinstance(result, list):
        return format_case_list(result)

    return format_case_list([])


@tool
@log_tool_call
def create_thehive_alert(
    title: str,
    description: str,
    source: str,
    source_ref: str,
    severity: str = "medium",
    tags: str = "",
    observables: str = ""
) -> str:
    """Create an alert in TheHive.

    Use this tool when:
    - Sending automated alerts from detection systems
    - Creating alerts that may be promoted to cases later
    - Ingesting external threat intelligence

    Args:
        title: Alert title
        description: Alert description (supports markdown)
        source: Source of the alert (e.g., "Pokedex", "CrowdStrike", "QRadar")
        source_ref: Unique reference ID from the source system
        severity: Severity level - "low", "medium", "high", "critical"
        tags: Comma-separated tags
        observables: Comma-separated observables in format "type:value" (e.g., "ip:1.2.3.4,domain:evil.com")

    Returns:
        Created alert details or error
    """
    client = _get_thehive_client()
    if not client:
        return "Error: TheHive service is not available."

    # Parse severity
    severity_int = _parse_severity(severity)

    # Parse tags
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []

    # Parse observables
    observable_list = []
    if observables:
        for obs in observables.split(","):
            obs = obs.strip()
            if ":" in obs:
                obs_type, obs_value = obs.split(":", 1)
                observable_list.append({
                    "dataType": obs_type.strip(),
                    "data": obs_value.strip(),
                })
            else:
                # Auto-detect type
                obs_type = _detect_observable_type(obs)
                observable_list.append({
                    "dataType": obs_type,
                    "data": obs,
                })

    result = client.create_alert(
        title=title,
        description=description,
        source=source,
        source_ref=source_ref,
        severity=severity_int,
        tags=tag_list,
        observables=observable_list if observable_list else None,
    )

    if "error" in result:
        return f"Error creating alert: {result['error']}"

    alert_id = result.get("_id", "unknown")
    return f"✅ Created TheHive alert:\n- **ID:** {alert_id}\n- **Title:** {title}\n- **Source:** {source}"


@tool
@log_tool_call
def add_task_to_thehive_case(
    case_id: str,
    task_title: str,
    task_description: str = ""
) -> str:
    """Add a task to a TheHive case.

    Use this tool when:
    - Creating investigation tasks
    - Assigning work items within a case
    - Tracking remediation steps

    Args:
        case_id: TheHive case ID (e.g., "~123456")
        task_title: Task title
        task_description: Task description (optional)

    Returns:
        Success message or error
    """
    client = _get_thehive_client()
    if not client:
        return "Error: TheHive service is not available."

    result = client.add_task(
        case_id=case_id.strip(),
        title=task_title,
        description=task_description,
    )

    if "error" in result:
        return f"Error adding task: {result['error']}"

    task_id = result.get("_id", "unknown")
    return f"✅ Added task to case {case_id}:\n- **Task:** {task_title}\n- **ID:** {task_id}"


# =============================================================================
# SAMPLE PROMPTS FOR LLM GUIDANCE
# =============================================================================
# Use these prompts to help users discover TheHive capabilities:
#
# - "Create a new case in TheHive for malware investigation"
# - "Add IP 1.2.3.4 as an observable to TheHive case ~123456"
# - "Search TheHive for open cases"
# - "Update TheHive case ~123456 status to InProgress"
# - "Close TheHive case ~123456 as TruePositive"
# - "Add a comment to TheHive case ~123456"
# - "Create a TheHive alert for suspicious activity"
# - "Add a task to TheHive case ~123456"
# =============================================================================
