# /services/utilities.py
"""
Utilities Module

This module provides utility functions for message preprocessing,
response formatting, and general helper functions used across
the security operations bot.
"""

import re
import logging
from datetime import datetime


def preprocess_message(message: str) -> str:
    """Clean up message formatting (Webex or other chat platforms)"""
    if not message:
        return ""
        
    # Remove @mentions
    message = re.sub(r'<@[^>]+>', '', message).strip()
    
    # Handle common HTML entities
    message = message.replace('&lt;', '<').replace('&gt;', '>')
    message = message.replace('&amp;', '&').replace('&nbsp;', ' ')
    
    return message.strip()


def format_for_chat(response: str) -> str:
    """Format response for Webex Teams chat display with proper markdown"""
    if not response:
        return "No response generated"
        
    # Chat message length limit (Webex is ~7439 chars)
    if len(response) > 7400:
        response = response[:7350] + "\n\n*[Response truncated due to length limits]*"
    
    # Apply specific formatting based on content type
    response = _apply_content_specific_formatting(response)
    
    # Apply general markdown enhancements
    response = _apply_general_formatting(response)
    
    return response


def _apply_content_specific_formatting(response: str) -> str:
    """Apply formatting specific to different types of responses"""
    
    if "Calculation:" in response:
        return _format_calculation_response(response)
    elif "Current weather" in response:
        return _format_weather_response(response)
    elif "Status Code:" in response:
        return _format_api_response(response)
    elif any(keyword in response for keyword in ["Containment status:", "Device ID:", "Online status:"]):
        return _format_crowdstrike_response(response)
    elif "Error:" in response:
        return _format_error_response(response)
    elif "Device Details for" in response:
        return _format_device_details_response(response)
    elif response.startswith(('🟢', '🟡', '🔴')):
        return _format_health_response(response)
    elif "Available Commands:" in response:
        return _format_help_response(response)
    else:
        return _format_general_response(response)


def _format_calculation_response(response: str) -> str:
    """Format calculation responses"""
    calc_match = re.search(r'Calculation:\s*(.+?)\s*=\s*(.+)', response)
    if calc_match:
        expression, result = calc_match.groups()
        return f"## 🧮 Math Result\n\n**Expression:** `{expression}`  \n**Result:** `{result}`"
    else:
        return f"## 🧮 Math Result\n\n{response}"


def _format_weather_response(response: str) -> str:
    """Format weather information responses"""
    response = f"## 🌤️ Weather Information\n\n{response}"
    # Make temperature and conditions stand out
    response = re.sub(r'(\d+°F)', r'**\1**', response)
    response = re.sub(r'(Sunny|Cloudy|Rainy|Clear|Overcast|Partly cloudy)', r'**\1**', response)
    return response


def _format_api_response(response: str) -> str:
    """Format API responses"""
    return f"## 🌐 API Response\n\n```json\n{response}\n```"


def _format_crowdstrike_response(response: str) -> str:
    """Format CrowdStrike information responses"""
    response = f"## 🔒 CrowdStrike Information\n\n{response}"
    # Highlight important status information
    response = re.sub(r'(Contained|Normal|Online|Offline)', r'**\1**', response)
    response = re.sub(r'(Device ID:\s*[A-Za-z0-9-]+)', r'**\1**', response)
    return response


def _format_error_response(response: str) -> str:
    """Format error responses"""
    return f"## ⚠️ Error\n\n{response}"


def _format_device_details_response(response: str) -> str:
    """Format device details responses"""
    lines = response.split('\n')
    formatted_lines = []
    for line in lines:
        if line.startswith('•'):
            # Make property names bold
            line = re.sub(r'•\s*([^:]+):', r'• **\1:**', line)
        formatted_lines.append(line)
    return f"## 💻 Device Details\n\n" + '\n'.join(formatted_lines)


def _format_health_response(response: str) -> str:
    """Format health check responses"""
    return f"## 🏥 System Status\n\n{response}"


def _format_help_response(response: str) -> str:
    """Format help command responses"""
    response = response.replace('🤖 **Available Commands:**', '## 🤖 Available Commands')
    response = re.sub(r'•\s*([^•\n]+)', r'• **\1**', response)
    return response


def _format_general_response(response: str) -> str:
    """Format general responses with appropriate headers"""
    if len(response) > 200 and '\n' in response:
        if any(keyword in response.lower() for keyword in ['search', 'found', 'document', 'policy', 'information']):
            return f"## 📄 Information Found\n\n{response}"
        elif any(keyword in response.lower() for keyword in ['answer', 'result', 'solution']):
            return f"## 💡 Answer\n\n{response}"
    return response


def _apply_general_formatting(response: str) -> str:
    """Apply general markdown enhancements"""
    # Make URLs clickable (if they're not already)
    response = re.sub(r'(?<![\[(])(https?://[^\s)]+)(?![])])', r'[\1](\1)', response)
    
    # Enhance bullet points
    response = re.sub(r'^- ', '• ', response, flags=re.MULTILINE)
    
    # Make key-value pairs more readable
    response = re.sub(r'^([A-Za-z\s]+):\s*([^\n]+)$', r'**\1:** \2', response, flags=re.MULTILINE)
    
    return response


def truncate_text(text: str, max_length: int, suffix: str = "...") -> str:
    """Truncate text to specified length with optional suffix"""
    if not text or len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def sanitize_input(text: str) -> str:
    """Sanitize user input to prevent potential issues"""
    if not text:
        return ""
        
    # Remove control characters except newlines and tabs
    text = ''.join(char for char in text if ord(char) >= 32 or char in '\n\t')
    
    # Limit length
    max_input_length = 5000
    if len(text) > max_input_length:
        text = text[:max_input_length]
        logging.warning(f"Input truncated to {max_input_length} characters")
    
    return text.strip()


def extract_hostname(text: str) -> str:
    """Extract hostname from text input"""
    # Look for hostname patterns
    hostname_patterns = [
        r'\b([A-Z0-9][A-Z0-9-]{0,61}[A-Z0-9])\b',  # Standard hostname
        r'\b([A-Z]+\d+)\b',  # Simple pattern like ABC123
    ]
    
    for pattern in hostname_patterns:
        match = re.search(pattern, text.upper())
        if match:
            return match.group(1)
    
    return text.strip().upper()


def get_query_type(message: str) -> str:
    """Determine query type from message content"""
    if not message:
        return "general"
        
    message_lower = message.lower()
    
    if any(word in message_lower for word in ['weather', 'temperature', 'forecast']):
        return "weather"
    elif any(word in message_lower for word in ['containment', 'device', 'hostname']) and 'crowdstrike' in message_lower:
        return "crowdstrike"
    elif message_lower in ['status', 'health', 'health check', 'help', 'commands', 'what can you do', 'what can you do?', 'metrics', 'performance', 'stats', 'metrics summary', 'quick stats']:
        return "status"
    else:
        return "rag"


def is_special_command(message: str) -> bool:
    """Check if message is a special system command"""
    if not message:
        return False
        
    special_commands = [
        'status', 'health', 'health check',
        'help', 'commands', 'what can you do', 'what can you do?',
        'metrics', 'performance', 'stats', 'metrics summary', 'quick stats'
    ]
    
    return message.lower().strip() in special_commands


def validate_input_length(text: str, max_length: int = 5000) -> bool:
    """Validate input length"""
    return len(text) <= max_length if text else True


def clean_response_for_logging(response: str, max_length: int = 200) -> str:
    """Clean and truncate response for logging purposes"""
    if not response:
        return "Empty response"
        
    # Remove markdown formatting
    cleaned = re.sub(r'[#*`\[\]]', '', response)
    
    # Replace multiple whitespace with single space
    cleaned = re.sub(r'\s+', ' ', cleaned)
    
    # Truncate for logging
    return truncate_text(cleaned.strip(), max_length)


def format_timestamp(dt: datetime = None) -> str:
    """Format datetime for display"""
    if dt is None:
        dt = datetime.now()
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def parse_boolean(value: str) -> bool:
    """Parse string to boolean value"""
    if not value:
        return False
        
    return value.lower() in ('true', '1', 'yes', 'on', 'enabled')


def safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    """Safely divide two numbers, returning default if denominator is zero"""
    if denominator == 0:
        return default
    return numerator / denominator


def format_bytes(bytes_value: int) -> str:
    """Format bytes to human readable format"""
    if bytes_value == 0:
        return "0 B"
        
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    
    return f"{bytes_value:.1f} PB"


def format_duration(seconds: float) -> str:
    """Format seconds to human readable duration"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"