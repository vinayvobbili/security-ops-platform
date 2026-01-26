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

# Initialize ServiceNow client once
_servicenow_client: Optional[ServiceNowClient] = None

try:
    logging.info("Initializing ServiceNow client...")
    _servicenow_client = ServiceNowClient()
    logging.info("ServiceNow client initialized successfully.")
except Exception as e:
    logging.error(f"Failed to initialize ServiceNow client: {e}")
    _servicenow_client = None


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
    if not _servicenow_client:
        return "Error: ServiceNow service is not initialized."

    hostname = hostname.strip()
    # Remove domain suffix if present
    hostname_short = hostname.split('.')[0]

    details = _servicenow_client.get_host_details(hostname_short)
    return _format_host_details(details, hostname_short)


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
