"""
Tanium Tools Module

Provides Tanium API integration for endpoint visibility and management.
Supports both Cloud and On-Prem Tanium instances.

Useful for:
- Looking up endpoint details by hostname
- Searching for endpoints matching a pattern
- Getting endpoint tags, IP addresses, and last seen times
- Investigating hosts during incident response

Note: Requires Tanium API tokens configured for Cloud and/or On-Prem instances.
"""

import logging
from typing import Optional

from langchain_core.tools import tool

from services.tanium import TaniumClient, TaniumAPIError
from src.utils.tool_decorator import log_tool_call

logger = logging.getLogger(__name__)

# Lazy-initialized Tanium client (only connects when first used)
_tanium_client: Optional[TaniumClient] = None
_tanium_client_initialized: bool = False


def _get_tanium_client() -> Optional[TaniumClient]:
    """Lazily initialize and return the Tanium client."""
    global _tanium_client, _tanium_client_initialized

    if _tanium_client_initialized:
        return _tanium_client

    _tanium_client_initialized = True

    try:
        logger.info("Initializing Tanium client...")
        _tanium_client = TaniumClient()

        available_instances = _tanium_client.list_available_instances()
        if available_instances:
            logger.info(f"Tanium client initialized. Available instances: {', '.join(available_instances)}")
        else:
            logger.warning("Tanium client initialized but no instances are available/configured.")
            _tanium_client = None

    except Exception as e:
        logger.error(f"Failed to initialize Tanium client: {e}")
        _tanium_client = None

    return _tanium_client


def _format_computer_result(computer, instance_name: str) -> str:
    """Format a single computer result for display."""
    tags_str = ", ".join(computer.custom_tags) if computer.custom_tags else "None"

    # Format last seen
    last_seen = computer.eidLastSeen
    if last_seen:
        # Try to format nicely
        try:
            from datetime import datetime
            dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
            last_seen = dt.strftime("%m/%d/%Y %I:%M %p UTC")
        except (ValueError, AttributeError):
            pass

    result = [
        f"### {computer.name}",
        f"- **Tanium ID:** {computer.id}",
        f"- **IP Address:** {computer.ip or 'Unknown'}",
        f"- **OS Platform:** {computer.os_platform or 'Unknown'}",
        f"- **Last Seen:** {last_seen or 'Unknown'}",
        f"- **Instance:** {instance_name}",
        f"- **Tags:** {tags_str}",
    ]

    return "\n".join(result)


def _format_search_results(computers: list, search_term: str, instance_name: str) -> str:
    """Format search results for display."""
    if not computers:
        return (
            f"## Tanium Endpoint Search\n"
            f"**Search Term:** {search_term}\n"
            f"**Instance:** {instance_name}\n"
            f"**Status:** No endpoints found matching '{search_term}'"
        )

    result = [
        f"## Tanium Endpoint Search",
        f"**Search Term:** {search_term}",
        f"**Instance:** {instance_name}",
        f"**Results:** {len(computers)} endpoint(s) found",
        "",
    ]

    for computer in computers[:10]:  # Limit to 10 results
        result.append(_format_computer_result(computer, instance_name))
        result.append("")

    if len(computers) > 10:
        result.append(f"_...and {len(computers) - 10} more results_")

    return "\n".join(result)


@tool
@log_tool_call
def lookup_endpoint_tanium(hostname: str) -> str:
    """Look up an endpoint by hostname in Tanium.

    USE THIS TOOL when user explicitly asks for Tanium lookups or mentions "Tanium".
    Do NOT use this for ServiceNow/CMDB lookups - use get_host_details_snow instead.

    Returns Tanium-specific data: Tanium ID, IP address, OS platform, last seen time,
    custom tags, and agent status from Tanium endpoint management.

    Searches both Cloud and On-Prem Tanium instances if configured.

    Args:
        hostname: The exact hostname to look up (e.g., "WORKSTATION-001")
    """
    client = _get_tanium_client()
    if not client:
        return "Error: Tanium service is not configured or no instances available."

    try:
        hostname = hostname.strip()
        results = []

        # Search all available instances
        for instance in client.instances:
            try:
                computer = instance.find_computer_by_name(hostname)
                if computer:
                    results.append((computer, instance.name))
            except TaniumAPIError as e:
                logger.warning(f"Error searching {instance.name}: {e}")
                continue

        if not results:
            instances_checked = ", ".join(client.list_available_instances())
            return (
                f"## Tanium Endpoint Lookup\n"
                f"**Hostname:** {hostname}\n"
                f"**Status:** ❌ Not found\n\n"
                f"Endpoint '{hostname}' was not found in Tanium.\n"
                f"Instances checked: {instances_checked}\n\n"
                f"_Tip: Try using `search_endpoints_tanium` for partial hostname matches._"
            )

        output = [
            f"## Tanium Endpoint Lookup",
            f"**Hostname:** {hostname}",
            f"**Status:** ✅ Found in {len(results)} instance(s)",
            "",
        ]

        for computer, instance_name in results:
            output.append(_format_computer_result(computer, instance_name))
            output.append("")

        return "\n".join(output)

    except Exception as e:
        logger.error(f"Tanium endpoint lookup failed: {e}")
        return f"Error looking up endpoint in Tanium: {str(e)}"


@tool
@log_tool_call
def search_endpoints_tanium(search_term: str, instance: str = "cloud") -> str:
    """Search for endpoints in Tanium by partial hostname match.

    USE THIS TOOL when user asks to search Tanium or mentions "Tanium" for endpoint searches.
    Do NOT use this for ServiceNow searches.

    Use this tool when you need to find endpoints matching a pattern in Tanium,
    such as searching for all workstations in a department or finding hosts with similar names.

    Args:
        search_term: Partial hostname to search for (e.g., "WORKSTATION", "NYC-PC")
        instance: Which Tanium instance to search - "cloud" or "onprem" (default: "cloud")
    """
    client = _get_tanium_client()
    if not client:
        return "Error: Tanium service is not configured or no instances available."

    try:
        search_term = search_term.strip()
        instance = instance.strip().lower()

        # Normalize instance name
        if instance in ["cloud", "tanium-cloud"]:
            instance_name = "Cloud"
        elif instance in ["onprem", "on-prem", "tanium-onprem"]:
            instance_name = "On-Prem"
        else:
            # Try to find by exact name
            instance_name = instance

        # Check if instance exists
        available = client.list_available_instances()
        matching_instance = None
        for inst in available:
            if inst.lower() == instance_name.lower():
                matching_instance = inst
                break

        if not matching_instance:
            return (
                f"## Tanium Search Error\n"
                f"Instance '{instance}' not found or not available.\n"
                f"Available instances: {', '.join(available)}"
            )

        computers = client.search_computers(search_term, matching_instance, limit=10)
        return _format_search_results(computers, search_term, matching_instance)

    except TaniumAPIError as e:
        logger.error(f"Tanium search failed: {e}")
        return f"Error searching Tanium: {str(e)}"
    except Exception as e:
        logger.error(f"Tanium search failed: {e}")
        return f"Error searching endpoints in Tanium: {str(e)}"


@tool
@log_tool_call
def list_tanium_instances() -> str:
    """List available Tanium instances and their status.

    Use this tool to see which Tanium instances are configured and available
    before performing lookups or searches.
    """
    client = _get_tanium_client()
    if not client:
        return "Error: Tanium service is not configured."

    try:
        instances = client.list_available_instances()

        if not instances:
            return (
                "## Tanium Instances\n"
                "**Status:** ⚠️ No instances available\n\n"
                "No Tanium instances are configured or accessible."
            )

        result = [
            "## Tanium Instances",
            f"**Available:** {len(instances)} instance(s)",
            "",
        ]

        for instance in client.instances:
            is_valid = instance.validate_token()
            status = "✅ Connected" if is_valid else "❌ Connection failed"
            result.append(f"- **{instance.name}**: {status}")
            result.append(f"  URL: {instance.server_url}")

        return "\n".join(result)

    except Exception as e:
        logger.error(f"Error listing Tanium instances: {e}")
        return f"Error listing Tanium instances: {str(e)}"


# =============================================================================
# SAMPLE PROMPTS FOR LLM GUIDANCE
# =============================================================================
# Use these prompts to help users discover Tanium capabilities:
#
# - "Look up WORKSTATION-001 in Tanium"
# - "Search Tanium for endpoints matching NYC-PC"
# - "Find all endpoints with 'SERVER' in the name on Tanium Cloud"
# - "Get Tanium details for hostname ABC123"
# - "What Tanium instances are available?"
# - "Search Tanium On-Prem for LAPTOP"
# - "Look up this host in Tanium: DESKTOP-XYZ"
# =============================================================================
