# /pokedex_bot/tools/network_monitoring_tools.py
"""
Network Monitoring Tools for SOC Bot

Provides tools to view and analyze the bot's network traffic logs
for security auditing and monitoring purposes.
"""

import logging
from typing import List
from langchain_core.tools import tool
from pokedex_bot.utils.network_logger import get_network_logger, get_network_summary


class NetworkMonitoringToolsManager:
    """Manager for network monitoring tools"""
    
    def __init__(self):
        self.logger = get_network_logger()
    
    def get_tools(self) -> List:
        """Get list of available network monitoring tools"""
        return [
            get_network_activity_tool(),
            get_network_summary_tool()
        ]


@tool
def get_network_activity_tool():
    """Get recent network activity logs from the bot"""
    try:
        logger = get_network_logger()
        recent_logs = logger.get_recent_logs(limit=20)
        
        if not recent_logs:
            return "No network activity logged yet."
        
        # Format the logs for display
        formatted_logs = []
        formatted_logs.append("🌐 **Recent Network Activity:**\n")
        
        for log in recent_logs[-10:]:  # Show last 10 entries
            timestamp = log.get('timestamp', 'Unknown')[:19]  # Remove milliseconds
            domain = log.get('domain', 'Unknown')
            method = log.get('method', 'GET')
            tool_name = log.get('tool_name', 'unknown')
            success = log.get('success', 'Unknown')
            status = log.get('response_status', '')
            duration = log.get('duration_ms', '')
            
            status_emoji = "✅" if success == "True" else "❌" if success == "False" else "❓"
            
            duration_str = f" ({duration}ms)" if duration else ""
            status_str = f" [{status}]" if status else ""
            
            formatted_logs.append(
                f"• `{timestamp}` - {status_emoji} **{domain}** {method} "
                f"via `{tool_name}`{status_str}{duration_str}"
            )
        
        return "\n".join(formatted_logs)
        
    except Exception as e:
        logging.error(f"Error getting network activity: {e}")
        return f"Error retrieving network activity: {str(e)}"


@tool  
def get_network_summary_tool():
    """Get summary of network activity by domain and tool"""
    try:
        summary = get_network_summary()
        
        total_calls = summary.get('total_recent_calls', 0)
        domains = summary.get('domains', {})
        
        if total_calls == 0:
            return "No network activity recorded yet."
        
        # Format summary
        result = []
        result.append(f"📊 **Network Activity Summary** (Last 100 calls: {total_calls})\n")
        
        if domains:
            result.append("**Domains contacted:**")
            for domain, count in sorted(domains.items(), key=lambda x: x[1], reverse=True):
                result.append(f"• **{domain}**: {count} calls")
        
        return "\n".join(result)
        
    except Exception as e:
        logging.error(f"Error getting network summary: {e}")
        return f"Error retrieving network summary: {str(e)}"