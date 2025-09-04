# /pokedex_bot/utils/network_logger.py
"""
Network Traffic Logger for SOC Bot

Logs all outbound API calls to CSV file for security audit and monitoring.
Tracks endpoint, payload, response status, timing, and other security-relevant data.
"""

import csv
import json
import os
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import hashlib


def _is_network_logging_enabled() -> bool:
    """Check if network logging is enabled via configuration"""
    try:
        # Try to import the configuration from the main pokedex bot
        import sys
        from pathlib import Path
        
        # Add webex_bots to path to access pokedex configuration
        webex_bots_path = Path(__file__).parent.parent.parent / "webex_bots"
        if str(webex_bots_path) not in sys.path:
            sys.path.append(str(webex_bots_path))
        
        # Import the configuration switch
        import pokedex
        return getattr(pokedex, 'SHOULD_LOG_NETWORK_TRAFFIC', True)
        
    except Exception as e:
        # If we can't access the config, default to enabled but log the issue
        logging.debug(f"Could not access network logging configuration: {e}. Defaulting to enabled.")
        return True

class NetworkLogger:
    """CSV logger for network traffic monitoring"""
    
    def __init__(self, log_file: str = "data/logs/pokedex_network_traffic.csv"):
        """Initialize network logger with CSV file"""
        self.log_file = log_file
        self._ensure_log_directory()
        self._initialize_csv_file()
        
    def _ensure_log_directory(self):
        """Ensure log directory exists"""
        log_dir = os.path.dirname(self.log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
    
    def _initialize_csv_file(self):
        """Initialize CSV file with headers if it doesn't exist"""
        if not os.path.exists(self.log_file):
            headers = [
                'timestamp',
                'endpoint_url',
                'domain', 
                'method',
                'payload_hash',  # Hash for privacy
                'payload_size_bytes',
                'response_status',
                'response_size_bytes',
                'duration_ms',
                'tool_name',
                'user_query_hash',  # Hash of user query
                'success',
                'error_message'
            ]
            
            with open(self.log_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
    
    def log_api_call(self, 
                    endpoint_url: str,
                    method: str = "GET",
                    payload: Optional[Dict[str, Any]] = None,
                    response_status: Optional[int] = None,
                    response_size: Optional[int] = None,
                    duration_ms: Optional[float] = None,
                    tool_name: str = "unknown",
                    user_query: str = "",
                    success: bool = True,
                    error_message: str = "") -> None:
        """Log an API call to CSV file"""
        
        # Check if network logging is enabled - early return for performance but still allow file access
        if not _is_network_logging_enabled():
            return
        
        try:
            # Parse URL components
            parsed_url = urlparse(endpoint_url)
            domain = parsed_url.netloc
            
            # Hash sensitive data for privacy
            payload_hash = ""
            payload_size = 0
            if payload:
                payload_json = json.dumps(payload, sort_keys=True)
                payload_hash = hashlib.sha256(payload_json.encode()).hexdigest()[:16]
                payload_size = len(payload_json.encode())
            
            user_query_hash = ""
            if user_query:
                user_query_hash = hashlib.sha256(user_query.encode()).hexdigest()[:16]
            
            # Create log entry
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'endpoint_url': endpoint_url,
                'domain': domain,
                'method': method.upper(),
                'payload_hash': payload_hash,
                'payload_size_bytes': payload_size,
                'response_status': response_status or "",
                'response_size_bytes': response_size or "",
                'duration_ms': round(duration_ms, 2) if duration_ms else "",
                'tool_name': tool_name,
                'user_query_hash': user_query_hash,
                'success': success,
                'error_message': error_message
            }
            
            # Append to CSV file
            with open(self.log_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=log_entry.keys())
                writer.writerow(log_entry)
                
        except Exception as e:
            logging.error(f"Failed to log network traffic: {e}")
    
    def get_recent_logs(self, limit: int = 50) -> list:
        """Get recent network log entries"""
        try:
            if not os.path.exists(self.log_file):
                return []
                
            with open(self.log_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                logs = list(reader)
                return logs[-limit:] if logs else []
                
        except Exception as e:
            logging.error(f"Failed to read network logs: {e}")
            return []
    
    def get_domain_summary(self) -> Dict[str, int]:
        """Get summary of API calls by domain"""
        try:
            logs = self.get_recent_logs(limit=1000)
            domain_counts = {}
            
            for log in logs:
                domain = log.get('domain', 'unknown')
                domain_counts[domain] = domain_counts.get(domain, 0) + 1
                
            return domain_counts
            
        except Exception as e:
            logging.error(f"Failed to generate domain summary: {e}")
            return {}


# Global instance for easy access
_network_logger = None

def get_network_logger() -> NetworkLogger:
    """Get singleton network logger instance"""
    global _network_logger
    if _network_logger is None:
        _network_logger = NetworkLogger()
    return _network_logger


def log_api_call(endpoint_url: str, **kwargs):
    """Convenience function to log API call"""
    # Always create logger (which creates CSV file) but let the logger decide whether to write
    logger = get_network_logger()
    logger.log_api_call(endpoint_url, **kwargs)


def get_network_summary() -> Dict[str, Any]:
    """Get network activity summary"""
    logger = get_network_logger()
    recent_logs = logger.get_recent_logs(limit=100)
    domain_summary = logger.get_domain_summary()
    
    return {
        'total_recent_calls': len(recent_logs),
        'domains': domain_summary,
        'recent_activity': recent_logs[-10:] if recent_logs else []
    }