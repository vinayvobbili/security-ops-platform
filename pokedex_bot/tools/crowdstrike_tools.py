# /services/crowdstrike_tools.py
"""
CrowdStrike Integration Tools

This module provides CrowdStrike-specific tools for the security operations bot.
All tools focus on defensive security operations including device monitoring,
containment status checking, and device information retrieval.
"""

import logging
import time
from typing import Optional
from langchain_core.tools import tool

# Import CrowdStrike client
from services.crowdstrike import CrowdStrikeClient
from pokedex_bot.utils.network_logger import log_api_call


class CrowdStrikeToolsManager:
    """Manager for CrowdStrike tools and client lifecycle"""
    
    def __init__(self):
        self.client: Optional[CrowdStrikeClient] = None
        self._initialize_client()
    
    def _initialize_client(self) -> None:
        """Initialize CrowdStrike client with proper error handling"""
        try:
            logging.info("Initializing CrowdStrike client...")
            self.client = CrowdStrikeClient()
            
            # Test the connection
            token = self.client.get_access_token()
            if token:
                logging.info("CrowdStrike client initialized successfully.")
            else:
                logging.warning("CrowdStrike client failed to get access token. Tools will be disabled.")
                self.client = None
                
        except Exception as e:
            logging.error(f"Failed to initialize CrowdStrike client: {e}")
            self.client = None
    
    def is_available(self) -> bool:
        """Check if CrowdStrike client is available"""
        return self.client is not None
    
    def get_tools(self) -> list:
        """Get list of available CrowdStrike tools"""
        if not self.is_available():
            return []
        
        # Return tools with client reference
        return [
            get_device_containment_status_tool(self.client),
            get_device_online_status_tool(self.client),
            get_device_details_tool(self.client)
        ]


def get_device_containment_status_tool(client: CrowdStrikeClient):
    """Factory function to create containment status tool with client reference"""
    @tool
    def get_device_containment_status(hostname: str) -> str:
        """Get device containment status from CrowdStrike. Use for containment status queries."""
        if not client:
            return "Error: CrowdStrike service is not initialized."

        # Tools should receive clean hostnames - agent should do the parsing
        hostname = hostname.strip().upper()
        
        status = client.get_device_containment_status(hostname)

        if status == 'Host not found in CS':
            return f"Hostname '{hostname}' was not found in CrowdStrike."

        if status:
            status_descriptions = {
                'normal': 'Normal - Device is not contained',
                'containment_pending': 'Containment Pending - Containment action initiated',
                'contained': 'Contained - Device is isolated from network',
                'lift_containment_pending': 'Lift Containment Pending - Uncontainment action initiated'
            }
            description = status_descriptions.get(status, f'Unknown status: {status}')
            return f"Containment status for '{hostname}': {description}"

        return f"Unable to retrieve containment status for hostname '{hostname}'."
    
    return get_device_containment_status


def get_device_online_status_tool(client: CrowdStrikeClient):
    """Factory function to create online status tool with client reference"""
    @tool
    def get_device_online_status(hostname: str) -> str:
        """Get device online status from CrowdStrike. Use for online/offline status queries."""
        if not client:
            return "Error: CrowdStrike service is not initialized."

        # Tools should receive clean hostnames - agent should do the parsing
        hostname = hostname.strip().upper()
        
        status = client.get_device_online_state(hostname)

        if status:
            status_descriptions = {
                'online': 'Online - Device is currently connected',
                'offline': 'Offline - Device is not currently connected',
                'unknown': 'Unknown - Connection status unclear'
            }
            description = status_descriptions.get(status, f'Status: {status}')
            return f"Online status for '{hostname}': {description}"

        return f"Unable to retrieve online status for hostname '{hostname}'. Device may not exist in CrowdStrike."
    
    return get_device_online_status


def get_device_details_tool(client: CrowdStrikeClient):
    """Factory function to create device details tool with client reference"""
    @tool
    def get_device_details_cs(hostname: str) -> str:
        """Get detailed device information from CrowdStrike. Use for comprehensive device queries."""
        if not client:
            return "Error: CrowdStrike service is not initialized."

        # Tools should receive clean hostnames - agent should do the parsing
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

            tags = details.get('tags', [])
            if tags:
                info_parts.append(f"• Tags: {', '.join(tags)}")
            else:
                info_parts.append("• Tags: None")

            return "\n".join(info_parts)

        return f"Unable to retrieve detailed information for hostname '{hostname}'."
    
    return get_device_details_cs