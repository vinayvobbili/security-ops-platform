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

        tags = details.get('tags', [])
        if tags:
            info_parts.append(f"• Tags: {', '.join(tags)}")
        else:
            info_parts.append("• Tags: None")

        return "\n".join(info_parts)

    return f"Unable to retrieve detailed information for hostname '{hostname}'."