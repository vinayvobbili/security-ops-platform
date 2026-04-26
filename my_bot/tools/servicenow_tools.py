# /my_bot/tools/servicenow_tools.py
"""
ServiceNow Integration Tools

Provides ServiceNow CMDB lookup tools for host/device information.
Useful for retrieving asset details, ownership, and lifecycle status.
"""

import logging
from typing import Optional

from langchain_core.tools import tool

from services.service_now import ServiceNowClient
from src.utils.tool_decorator import log_tool_call
from src.utils.llm_decorators import validate_args, llm_cache, HOSTNAME_PATTERN

# Lazy-initialized ServiceNow client
_servicenow_client: Optional[ServiceNowClient] = None


def _get_servicenow_client() -> Optional[ServiceNowClient]:
    """Get ServiceNow client (lazy initialization)."""
    global _servicenow_client
    if _servicenow_client is None:
        try:
            _servicenow_client = ServiceNowClient()
        except Exception as e:
            logging.error(f"Failed to initialize ServiceNow client: {e}")
    return _servicenow_client


def _format_host_details(details: dict, hostname: str) -> str:
    """Format ServiceNow host details for display."""
    if not details:
        return f"No ServiceNow record found for '{hostname}'."

    # Check for errors or not found
    if details.get('status') == 'Not Found':
        return f"Host '{hostname}' was not found in ServiceNow CMDB."

    if details.get('status') == 'ServiceNow API Error':
        error = details.get('error', 'Unknown error')
        return f"Error querying ServiceNow for '{hostname}': {error}"

    info_parts = [f"ServiceNow CMDB Details for '{hostname}':"]

    # Core identity fields
    if details.get('name'):
        info_parts.append(f"  Name: {details.get('name')}")
    if details.get('id'):
        info_parts.append(f"  CI ID: {details.get('id')}")
    if details.get('ciClass'):
        info_parts.append(f"  CI Class: {details.get('ciClass')}")
    if details.get('category'):
        info_parts.append(f"  Category: {details.get('category')}")

    # Network info
    if details.get('ipAddress'):
        info_parts.append(f"  IP Address: {details.get('ipAddress')}")
    if details.get('osDomain'):
        info_parts.append(f"  Domain: {details.get('osDomain')}")

    # System info
    if details.get('operatingSystem'):
        info_parts.append(f"  Operating System: {details.get('operatingSystem')}")

    # Location info
    if details.get('country'):
        info_parts.append(f"  Country: {details.get('country')}")
    if details.get('supportedCountry'):
        info_parts.append(f"  Supported Country: {details.get('supportedCountry')}")

    # Lifecycle info
    if details.get('environment'):
        info_parts.append(f"  Environment: {details.get('environment')}")
    if details.get('lifecycleStatus'):
        info_parts.append(f"  Lifecycle Status: {details.get('lifecycleStatus')}")
    if details.get('state'):
        info_parts.append(f"  State: {details.get('state')}")

    # Owner/assignment info (if available)
    if details.get('assignedTo'):
        info_parts.append(f"  Assigned To: {details.get('assignedTo')}")
    if details.get('ownedBy'):
        info_parts.append(f"  Owned By: {details.get('ownedBy')}")
    if details.get('managedBy'):
        info_parts.append(f"  Managed By: {details.get('managedBy')}")
    if details.get('supportGroup'):
        info_parts.append(f"  Support Group: {details.get('supportGroup')}")

    # Discovery info
    if details.get('mostRecentDiscovery'):
        info_parts.append(f"  Last Discovery: {details.get('mostRecentDiscovery')}")

    return "\n".join(info_parts)


@tool
@validate_args(hostname=HOSTNAME_PATTERN)
@llm_cache(ttl_seconds=86400)
@log_tool_call
def get_host_details_snow(hostname: str) -> str:
    """Get host/device details from ServiceNow CMDB.

    USE THIS TOOL when user asks for ServiceNow, CMDB, or asset management details.
    Do NOT use this for Tanium lookups - use lookup_endpoint_tanium instead.

    Returns CMDB asset info: CI class, operating system, location, environment,
    lifecycle status, and ownership information from ServiceNow.

    Args:
        hostname: The hostname to look up (e.g., "US1Q60TZ3" or "SERVER01.domain.com")
    """
    client = _get_servicenow_client()
    if not client:
        return "Error: ServiceNow service is not available."

    hostname = hostname.strip()
    # Remove domain suffix if present
    hostname_short = hostname.split('.')[0]

    details = client.get_host_details(hostname_short)
    return _format_host_details(details, hostname_short)


@tool
@validate_args(hostname=HOSTNAME_PATTERN)
@log_tool_call
def get_servicenow_changes(hostname: str) -> str:
    """Get active or recently scheduled ServiceNow change tickets for a host.

    An active change window on the affected host can explain an alert as
    expected maintenance activity — use this to rule out false positives
    driven by planned work.

    Args:
        hostname: The hostname to search for (short name, no domain)
    """
    client = _get_servicenow_client()
    if not client:
        return "Error: ServiceNow service is not available."

    short = hostname.strip().split('.')[0]
    try:
        changes = client.search_changes_by_ci(short)
    except Exception as e:
        return f"Error querying ServiceNow changes for {short}: {e}"

    if not changes:
        return f"No active change tickets found for '{short}'."

    lines = [f"ServiceNow changes for '{short}' ({len(changes)} found):"]
    for c in changes[:10]:
        num = c.get('number', c.get('changeNumber', '?'))
        state = c.get('state', c.get('status', ''))
        ctype = c.get('type', c.get('changeType', ''))
        desc = str(c.get('shortDescription', c.get('description', '')))[:150]
        start = c.get('plannedStart', c.get('startDate', ''))
        end = c.get('plannedEnd', c.get('endDate', ''))
        lines.append(f"  - {num} [{state}/{ctype}] {start} → {end}")
        if desc:
            lines.append(f"    {desc}")
    return "\n".join(lines)


@tool
@log_tool_call
def get_servicenow_incidents(search_term: str, hours: int = 72) -> str:
    """Get recent ServiceNow incidents where the affected CI matches a hostname or username.

    Useful for finding existing incident tickets that correlate with the alert
    under triage (e.g. a help-desk ticket opened for the same host around the
    same time can explain benign activity).

    Args:
        search_term: Hostname or username to search for
        hours: How far back to look (default 72 = 3 days)
    """
    client = _get_servicenow_client()
    if not client:
        return "Error: ServiceNow service is not available."

    short = search_term.strip().split('.')[0]
    try:
        incidents = client.search_incidents_by_ci(short, hours=hours)
    except Exception as e:
        return f"Error querying ServiceNow incidents for {short}: {e}"

    if not incidents:
        return f"No ServiceNow incidents found for '{short}' in the last {hours}h."

    lines = [f"ServiceNow incidents for '{short}' (last {hours}h, {len(incidents)} found):"]
    for inc in incidents[:10]:
        num = inc.get('number', inc.get('incidentNumber', '?'))
        state = inc.get('state', '')
        pri = inc.get('priority', '')
        desc = str(inc.get('shortDescription', inc.get('description', '')))[:150]
        opened = inc.get('createdDate', inc.get('openedAt', ''))
        assign = inc.get('assignmentGroup', '')
        lines.append(f"  - {num} [{state} P{pri}] opened {opened} — {assign}")
        if desc:
            lines.append(f"    {desc}")
    return "\n".join(lines)


# =============================================================================
# SAMPLE PROMPTS FOR LLM GUIDANCE
# =============================================================================
# Use these prompts to help users discover ServiceNow capabilities:
#
# - "Get ServiceNow details for HOST123"
# - "Look up HOST123 in ServiceNow CMDB"
# - "What's the CI class for SERVER01 in ServiceNow?"
# - "Who owns WORKSTATION-001 in ServiceNow?"
# - "Get CMDB info for US1Q60TZ3"
# - "Check ServiceNow for asset details on LAPTOP-XYZ"
# =============================================================================
