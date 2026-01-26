"""
Abnormal Security Tools Module

Provides Abnormal Security integration for email threat detection and case management.
Supports querying threats, cases, and taking remediation actions.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from langchain_core.tools import tool

from my_config import get_config
from services.abnormal_security import AbnormalSecurityClient, AbnormalSecurityError
from src.utils.tool_decorator import log_tool_call

# Initialize Abnormal Security client once
_abnormal_client: Optional[AbnormalSecurityClient] = None

try:
    logging.info("Initializing Abnormal Security client...")
    config = get_config()

    if config.abnormal_security_api_key:
        _abnormal_client = AbnormalSecurityClient(config.abnormal_security_api_key)
        logging.info("Abnormal Security client initialized successfully.")
    else:
        logging.warning("Abnormal Security client not configured (missing API key). Tools will be disabled.")

except Exception as e:
    logging.error(f"Failed to initialize Abnormal Security client: {e}")
    _abnormal_client = None


def _format_threat_list(threats: list) -> str:
    """Format threat results for display."""
    if not threats:
        return "No threats found matching the criteria."

    lines = [f"## Abnormal Security Threats ({len(threats)} found)", ""]

    for threat in threats:
        threat_id = threat.get("threatId", "Unknown")
        attack_type = threat.get("attackType", "Unknown")
        attack_strategy = threat.get("attackStrategy", "Unknown")
        received_time = threat.get("receivedTime", "Unknown")
        subject = threat.get("subject", "N/A")
        sender = threat.get("fromAddress", "Unknown")
        recipient_count = len(threat.get("toAddresses", []))
        is_read = threat.get("isRead", False)
        remediation_status = threat.get("remediationStatus", "Unknown")

        lines.append(f"### Threat: {attack_type}")
        lines.append(f"**ID:** `{threat_id}`")
        lines.append(f"**Strategy:** {attack_strategy}")
        lines.append(f"**Subject:** {subject[:80]}{'...' if len(subject) > 80 else ''}")
        lines.append(f"**From:** {sender}")
        lines.append(f"**Recipients:** {recipient_count}")
        lines.append(f"**Received:** {received_time}")
        lines.append(f"**Status:** {remediation_status} | Read: {'Yes' if is_read else 'No'}")
        lines.append("")

    return "\n".join(lines)


def _format_threat_details(threat: dict) -> str:
    """Format a single threat for detailed display."""
    threat_id = threat.get("threatId", "Unknown")
    attack_type = threat.get("attackType", "Unknown")
    attack_strategy = threat.get("attackStrategy", "Unknown")
    attack_vector = threat.get("attackVector", "Unknown")
    impersonated_party = threat.get("impersonatedParty", "N/A")
    received_time = threat.get("receivedTime", "Unknown")
    subject = threat.get("subject", "N/A")
    sender = threat.get("fromAddress", "Unknown")
    sender_name = threat.get("fromName", "Unknown")
    to_addresses = threat.get("toAddresses", [])
    cc_addresses = threat.get("ccEmails", [])
    remediation_status = threat.get("remediationStatus", "Unknown")
    remediation_timestamp = threat.get("remediationTimestamp", "N/A")
    is_read = threat.get("isRead", False)
    summary_insights = threat.get("summaryInsights", [])

    lines = [
        f"## Abnormal Security Threat Details",
        "",
        f"**Threat ID:** `{threat_id}`",
        f"**Attack Type:** {attack_type}",
        f"**Attack Strategy:** {attack_strategy}",
        f"**Attack Vector:** {attack_vector}",
        f"**Impersonated Party:** {impersonated_party}",
        "",
        "### Email Details",
        f"**Subject:** {subject}",
        f"**From:** {sender_name} <{sender}>",
        f"**To:** {', '.join(to_addresses[:5])}{'...' if len(to_addresses) > 5 else ''}",
    ]

    if cc_addresses:
        lines.append(f"**CC:** {', '.join(cc_addresses[:3])}{'...' if len(cc_addresses) > 3 else ''}")

    lines.extend([
        f"**Received:** {received_time}",
        "",
        "### Status",
        f"**Remediation Status:** {remediation_status}",
        f"**Remediation Time:** {remediation_timestamp}",
        f"**Read:** {'Yes' if is_read else 'No'}",
    ])

    if summary_insights:
        lines.append("")
        lines.append("### Insights")
        for insight in summary_insights[:5]:
            lines.append(f"- {insight}")

    return "\n".join(lines)


def _format_case_list(cases: list) -> str:
    """Format case results for display."""
    if not cases:
        return "No cases found matching the criteria."

    lines = [f"## Abnormal Security Cases ({len(cases)} found)", ""]

    for case in cases:
        case_id = case.get("caseId", "Unknown")
        severity = case.get("severity", "Unknown")
        status = case.get("status", "Unknown")
        case_type = case.get("caseType", "Unknown")
        threat_ids = case.get("threatIds", [])
        created_time = case.get("createdTime", "Unknown")

        # Determine severity indicator
        if severity.lower() in ["high", "critical"]:
            severity_indicator = "**HIGH**"
        elif severity.lower() == "medium":
            severity_indicator = "MEDIUM"
        else:
            severity_indicator = severity

        lines.append(f"### Case #{case_id}")
        lines.append(f"**Type:** {case_type}")
        lines.append(f"**Severity:** {severity_indicator}")
        lines.append(f"**Status:** {status}")
        lines.append(f"**Threats:** {len(threat_ids)}")
        lines.append(f"**Created:** {created_time}")
        lines.append("")

    return "\n".join(lines)


def _format_case_details(case: dict) -> str:
    """Format a single case for detailed display."""
    case_id = case.get("caseId", "Unknown")
    severity = case.get("severity", "Unknown")
    status = case.get("status", "Unknown")
    case_type = case.get("caseType", "Unknown")
    description = case.get("description", "N/A")
    threat_ids = case.get("threatIds", [])
    created_time = case.get("createdTime", "Unknown")
    last_modified = case.get("lastModifiedTime", "Unknown")
    customer_visible_time = case.get("customerVisibleTime", "Unknown")
    affected_employee = case.get("affectedEmployee", "N/A")
    first_observed = case.get("firstObserved", "Unknown")

    lines = [
        f"## Abnormal Security Case Details",
        "",
        f"**Case ID:** `{case_id}`",
        f"**Type:** {case_type}",
        f"**Severity:** {severity}",
        f"**Status:** {status}",
        "",
        "### Description",
        description,
        "",
        "### Timeline",
        f"**First Observed:** {first_observed}",
        f"**Created:** {created_time}",
        f"**Last Modified:** {last_modified}",
        f"**Customer Visible:** {customer_visible_time}",
        "",
        "### Affected",
        f"**Employee:** {affected_employee}",
        f"**Related Threats:** {len(threat_ids)}",
    ]

    if threat_ids:
        lines.append("")
        lines.append("### Threat IDs")
        for tid in threat_ids[:10]:
            lines.append(f"- `{tid}`")
        if len(threat_ids) > 10:
            lines.append(f"- ... and {len(threat_ids) - 10} more")

    return "\n".join(lines)


@tool
@log_tool_call
def get_abnormal_threats(days: int = 7, limit: int = 20, attack_type: str = "") -> str:
    """Get recent email threats from Abnormal Security.

    Use this tool to retrieve email threats detected by Abnormal Security.
    Returns threats including phishing, BEC, malware, and other attack types.

    Args:
        days: Number of days to look back (default 7, max 30)
        limit: Maximum number of threats to return (default 20, max 100)
        attack_type: Optional filter by attack type (e.g., "Phishing: Credential", "Social Engineering (BEC)", "Malware")
    """
    if not _abnormal_client:
        return "Error: Abnormal Security service is not initialized."

    # Validate inputs
    days = min(max(1, days), 30)
    limit = min(max(1, limit), 100)

    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)

        kwargs: Dict[str, Any] = {"page_size": limit}
        if attack_type:
            kwargs["attack_type"] = attack_type

        data = _abnormal_client.get_threats_by_timerange(start_time, end_time, **kwargs)
        threats = data.get("threats", [])
        return _format_threat_list(threats)

    except AbnormalSecurityError as e:
        return f"Error: {e.detail}"
    except Exception as e:
        logging.error(f"Error fetching Abnormal threats: {e}")
        return f"Error fetching threats: {str(e)}"


@tool
@log_tool_call
def get_abnormal_threat_details(threat_id: str) -> str:
    """Get detailed information about a specific Abnormal Security threat.

    Use this tool when you need full details about a particular email threat,
    including sender info, attack analysis, and remediation status.

    Args:
        threat_id: The UUID of the threat to retrieve
    """
    if not _abnormal_client:
        return "Error: Abnormal Security service is not initialized."

    try:
        threat_id = threat_id.strip()
        data = _abnormal_client.get_threat_details(threat_id)
        return _format_threat_details(data)

    except AbnormalSecurityError as e:
        return f"Error: {e.detail}"
    except Exception as e:
        logging.error(f"Error fetching Abnormal threat details: {e}")
        return f"Error fetching threat details: {str(e)}"


@tool
@log_tool_call
def get_abnormal_phishing_threats(days: int = 7, limit: int = 10) -> str:
    """Get recent phishing and credential theft threats from Abnormal Security.

    Use this tool to quickly identify phishing attacks targeting credentials.
    Returns only "Phishing: Credential" type threats.

    Args:
        days: Number of days to look back (default 7, max 30)
        limit: Maximum number of threats to return (default 10, max 50)
    """
    if not _abnormal_client:
        return "Error: Abnormal Security service is not initialized."

    days = min(max(1, days), 30)
    limit = min(max(1, limit), 50)

    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)

        data = _abnormal_client.get_threats_by_timerange(
            start_time, end_time,
            page_size=limit,
            attack_type="Phishing: Credential"
        )
        threats = data.get("threats", [])

        if not threats:
            return f"No phishing threats found in the last {days} days. This is good news!"

        return _format_threat_list(threats)

    except AbnormalSecurityError as e:
        return f"Error: {e.detail}"
    except Exception as e:
        logging.error(f"Error fetching phishing threats: {e}")
        return f"Error fetching phishing threats: {str(e)}"


@tool
@log_tool_call
def get_abnormal_bec_threats(days: int = 7, limit: int = 10) -> str:
    """Get recent Business Email Compromise (BEC) threats from Abnormal Security.

    Use this tool to identify social engineering and invoice fraud attacks.
    Returns BEC-type threats including invoice fraud and social engineering.

    Args:
        days: Number of days to look back (default 7, max 30)
        limit: Maximum number of threats to return (default 10, max 50)
    """
    if not _abnormal_client:
        return "Error: Abnormal Security service is not initialized."

    days = min(max(1, days), 30)
    limit = min(max(1, limit), 50)

    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)

        # Get Social Engineering BEC threats
        data = _abnormal_client.get_threats_by_timerange(
            start_time, end_time,
            page_size=limit,
            attack_type="Social Engineering (BEC)"
        )
        threats = data.get("threats", [])

        if not threats:
            return f"No BEC threats found in the last {days} days. This is good news!"

        return _format_threat_list(threats)

    except AbnormalSecurityError as e:
        return f"Error: {e.detail}"
    except Exception as e:
        logging.error(f"Error fetching BEC threats: {e}")
        return f"Error fetching BEC threats: {str(e)}"


@tool
@log_tool_call
def get_abnormal_cases(days: int = 7, limit: int = 20) -> str:
    """Get recent cases from Abnormal Security.

    Use this tool to retrieve security cases that may require investigation.
    Cases group related threats and provide context for incident response.

    Args:
        days: Number of days to look back (default 7, max 30)
        limit: Maximum number of cases to return (default 20, max 100)
    """
    if not _abnormal_client:
        return "Error: Abnormal Security service is not initialized."

    days = min(max(1, days), 30)
    limit = min(max(1, limit), 100)

    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)

        data = _abnormal_client.get_cases_by_timerange(
            start_time, end_time,
            filter_key="lastModifiedTime",
            page_size=limit
        )
        cases = data.get("cases", [])
        return _format_case_list(cases)

    except AbnormalSecurityError as e:
        return f"Error: {e.detail}"
    except Exception as e:
        logging.error(f"Error fetching Abnormal cases: {e}")
        return f"Error fetching cases: {str(e)}"


@tool
@log_tool_call
def get_abnormal_case_details(case_id: str) -> str:
    """Get detailed information about a specific Abnormal Security case.

    Use this tool when you need full details about a security case,
    including affected employees, related threats, and investigation status.

    Args:
        case_id: The ID of the case to retrieve
    """
    if not _abnormal_client:
        return "Error: Abnormal Security service is not initialized."

    try:
        case_id = case_id.strip()
        data = _abnormal_client.get_case_details(case_id)
        return _format_case_details(data)

    except AbnormalSecurityError as e:
        return f"Error: {e.detail}"
    except Exception as e:
        logging.error(f"Error fetching Abnormal case details: {e}")
        return f"Error fetching case details: {str(e)}"


@tool
@log_tool_call
def search_abnormal_threats_by_sender(sender_email: str, days: int = 30) -> str:
    """Search for threats from a specific sender email address.

    Use this tool to investigate all threats from a particular sender,
    useful for tracking repeat attackers or compromised accounts.

    Args:
        sender_email: Email address of the sender to search for
        days: Number of days to look back (default 30, max 90)
    """
    if not _abnormal_client:
        return "Error: Abnormal Security service is not initialized."

    days = min(max(1, days), 90)

    try:
        sender_email = sender_email.strip().lower()
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)

        data = _abnormal_client.get_threats_by_timerange(
            start_time, end_time,
            page_size=50,
            sender=sender_email
        )
        threats = data.get("threats", [])

        if not threats:
            return f"No threats found from sender '{sender_email}' in the last {days} days."

        return _format_threat_list(threats)

    except AbnormalSecurityError as e:
        return f"Error: {e.detail}"
    except Exception as e:
        logging.error(f"Error searching threats by sender: {e}")
        return f"Error searching threats: {str(e)}"


@tool
@log_tool_call
def search_abnormal_threats_by_recipient(recipient_email: str, days: int = 30) -> str:
    """Search for threats targeting a specific recipient email address.

    Use this tool to investigate threats targeting a particular user,
    useful for understanding if an employee is being specifically targeted.

    Args:
        recipient_email: Email address of the recipient to search for
        days: Number of days to look back (default 30, max 90)
    """
    if not _abnormal_client:
        return "Error: Abnormal Security service is not initialized."

    days = min(max(1, days), 90)

    try:
        recipient_email = recipient_email.strip().lower()
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)

        data = _abnormal_client.get_threats_by_timerange(
            start_time, end_time,
            page_size=50,
            recipient=recipient_email
        )
        threats = data.get("threats", [])

        if not threats:
            return f"No threats found targeting '{recipient_email}' in the last {days} days."

        return _format_threat_list(threats)

    except AbnormalSecurityError as e:
        return f"Error: {e.detail}"
    except Exception as e:
        logging.error(f"Error searching threats by recipient: {e}")
        return f"Error searching threats: {str(e)}"


# =============================================================================
# SAMPLE TEST PROMPTS
# =============================================================================
# Use these prompts to test Abnormal Security tools via the Pokédex bot:
#
# --- Threat Tools ---
#
# get_abnormal_threats:
#   "Show me recent email threats from Abnormal Security"
#   "What email threats were detected in the last 7 days?"
#   "Get me the latest Abnormal Security threats"
#
# get_abnormal_threat_details:
#   "Get details for Abnormal threat abc123-def456"
#   "Show me more info about threat ID xyz789"
#
# get_abnormal_phishing_threats:
#   "What phishing attacks were detected recently?"
#   "Show me credential phishing threats from the last week"
#   "Are there any phishing emails in Abnormal?"
#
# get_abnormal_bec_threats:
#   "What BEC attacks were detected?"
#   "Show me business email compromise threats"
#   "Any invoice fraud attempts in Abnormal?"
#
# --- Case Tools ---
#
# get_abnormal_cases:
#   "Show me Abnormal Security cases"
#   "What security cases need investigation?"
#   "Get recent cases from Abnormal"
#
# get_abnormal_case_details:
#   "Get details for Abnormal case 12345"
#   "Show me case information for case ID abc123"
#
# --- Search Tools ---
#
# search_abnormal_threats_by_sender:
#   "Search Abnormal for threats from attacker@malicious.com"
#   "What threats came from suspicious@domain.com?"
#   "Find all emails from bad-actor@evil.net in Abnormal"
#
# search_abnormal_threats_by_recipient:
#   "Search Abnormal for threats targeting ceo@company.com"
#   "Is john.smith@company.com being targeted by phishing?"
#   "Check if finance@company.com received any threats"
#
# --- Combined/Natural Queries ---
#
#   "What's the email threat situation?"
#   "Are there any urgent email security issues?"
#   "Check Abnormal for threats targeting our executives"
#   "What phishing or BEC attacks happened this week?"
#
# =============================================================================
