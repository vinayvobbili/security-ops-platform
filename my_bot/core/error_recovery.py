# /pokedx_bot/core/error_recovery.py
"""
Enhanced Error Recovery System

Provides graceful degradation and fallback responses when tools fail.
Implements retry logic, caching, and intelligent error handling to maintain
bot functionality even when external services are unavailable.
"""

import logging
import time
import json
from typing import Dict, Any, Optional, Callable, Tuple
from functools import wraps
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)


class ErrorRecoveryManager:
    """Manages error recovery, retries, and fallback responses"""
    
    def __init__(self):
        self.retry_config = {
            'crowdstrike': {'max_retries': 2, 'delay': 1.0, 'backoff': 2.0},
            'weather': {'max_retries': 3, 'delay': 0.5, 'backoff': 1.5},
            'document_search': {'max_retries': 1, 'delay': 0.5, 'backoff': 1.0},
            'default': {'max_retries': 2, 'delay': 1.0, 'backoff': 2.0}
        }
        
        self.fallback_responses = {
            'crowdstrike_device_status': "⚠️ Unable to retrieve device status at this time. Please check CrowdStrike Falcon console directly or try again later.",
            'crowdstrike_device_details': "⚠️ Unable to retrieve device details at this time. Please check CrowdStrike Falcon console directly for device information.",
            'weather': "⚠️ Weather information is temporarily unavailable. Please check a reliable weather service directly.",
            'document_search': "⚠️ Document search is temporarily unavailable. Please refer to your local SOC documentation or contact your security team.",
            'general': "⚠️ This service is temporarily unavailable. Please try again later or contact support if the issue persists."
        }
        
        # Simple error tracking
        self.error_counts = {}
        self.last_error_reset = datetime.now()
        self.error_reset_interval = timedelta(hours=1)
        
        logger.info("Error recovery manager initialized")
    
    def with_retry(self, tool_type: str = 'default'):
        """Decorator to add retry logic to tool functions"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                config = self.retry_config.get(tool_type, self.retry_config['default'])
                last_exception = None
                
                for attempt in range(config['max_retries'] + 1):
                    try:
                        result = func(*args, **kwargs)
                        
                        # Reset error count on success
                        if tool_type in self.error_counts:
                            self.error_counts[tool_type] = 0
                        
                        return result
                        
                    except Exception as e:
                        last_exception = e
                        self._track_error(tool_type, str(e))
                        
                        if attempt < config['max_retries']:
                            delay = config['delay'] * (config['backoff'] ** attempt)
                            logger.warning(f"{tool_type} attempt {attempt + 1} failed: {e}. Retrying in {delay:.1f}s...")
                            time.sleep(delay)
                        else:
                            logger.error(f"{tool_type} failed after {config['max_retries'] + 1} attempts: {e}")
                
                # All retries failed
                raise last_exception
            
            return wrapper
        return decorator
    
    def _track_error(self, tool_type: str, error_msg: str):
        """Track error frequency for monitoring"""
        now = datetime.now()
        
        # Reset counters hourly
        if now - self.last_error_reset > self.error_reset_interval:
            self.error_counts = {}
            self.last_error_reset = now
        
        self.error_counts[tool_type] = self.error_counts.get(tool_type, 0) + 1
        
        # Log high error rates
        if self.error_counts[tool_type] > 10:
            logger.warning(f"High error rate for {tool_type}: {self.error_counts[tool_type]} errors in last hour")
    
    def get_fallback_response(self, tool_type: str, context: str = None) -> str:
        """Get appropriate fallback response when tool fails"""
        
        # Check for specific context-based fallbacks
        if tool_type == 'crowdstrike':
            if context and ('status' in context.lower() or 'contain' in context.lower()):
                return self.fallback_responses['crowdstrike_device_status']
            elif context and ('detail' in context.lower() or 'info' in context.lower()):
                return self.fallback_responses['crowdstrike_device_details']
        
        # Return tool-specific fallback or general fallback
        return self.fallback_responses.get(tool_type, self.fallback_responses['general'])
    
    def is_tool_available(self, tool_type: str) -> bool:
        """Check if a tool is currently experiencing issues"""
        error_count = self.error_counts.get(tool_type, 0)
        
        # Consider tool unavailable if too many recent errors
        if tool_type == 'crowdstrike' and error_count > 5:
            return False
        elif tool_type == 'weather' and error_count > 10:
            return False
        elif error_count > 8:
            return False
            
        return True
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get current health status of all tools"""
        now = datetime.now()
        
        # Reset if needed
        if now - self.last_error_reset > self.error_reset_interval:
            self.error_counts = {}
            self.last_error_reset = now
        
        return {
            'timestamp': now.isoformat(),
            'error_counts': self.error_counts.copy(),
            'tool_availability': {
                tool: self.is_tool_available(tool) 
                for tool in ['crowdstrike', 'weather', 'document_search']
            },
            'last_reset': self.last_error_reset.isoformat()
        }


def safe_tool_call(func: Callable, tool_type: str, context: str = None, 
                   recovery_manager: ErrorRecoveryManager = None) -> Tuple[bool, str]:
    """
    Safely call a tool function with error recovery
    
    Returns:
        Tuple[bool, str]: (success, response_or_error_message)
    """
    if recovery_manager is None:
        recovery_manager = ErrorRecoveryManager()
    
    try:
        # Check if tool is available
        if not recovery_manager.is_tool_available(tool_type):
            logger.warning(f"Tool {tool_type} marked as unavailable due to recent errors")
            return False, recovery_manager.get_fallback_response(tool_type, context)
        
        # Apply retry decorator and call function
        wrapped_func = recovery_manager.with_retry(tool_type)(func)
        result = wrapped_func()
        
        return True, result
        
    except Exception as e:
        logger.error(f"Tool {tool_type} failed: {e}")
        fallback = recovery_manager.get_fallback_response(tool_type, context)
        return False, fallback


def enhanced_query_wrapper(state_manager, query: str, recovery_manager: ErrorRecoveryManager = None):
    """
    Wrapper for native tool calling with enhanced error recovery
    """
    if recovery_manager is None:
        recovery_manager = ErrorRecoveryManager()
    
    try:
        # Add error recovery instructions
        enhanced_query = f"""
{query}

IMPORTANT: If any tool calls fail, provide a helpful response explaining the issue and suggest alternatives. Never return empty responses or technical error messages to users.
"""
        
        result = state_manager.execute_query(enhanced_query)
        
        if result:
            return result
        else:
            return "⚠️ I'm experiencing technical difficulties. Please try again or contact support."
            
    except Exception as e:
        logger.error(f"Agent execution failed: {e}")
        
        # Provide context-aware fallback
        if 'status' in query.lower() or 'contain' in query.lower():
            return recovery_manager.get_fallback_response('crowdstrike', query)
        elif 'weather' in query.lower():
            return recovery_manager.get_fallback_response('weather', query)
        elif any(word in query.lower() for word in ['document', 'search', 'how to', 'procedure']):
            return recovery_manager.get_fallback_response('document_search', query)
        else:
            return recovery_manager.get_fallback_response('general', query)


# Global recovery manager instance
_recovery_manager = None


def get_recovery_manager() -> ErrorRecoveryManager:
    """Get global recovery manager instance (singleton)"""
    global _recovery_manager
    if _recovery_manager is None:
        _recovery_manager = ErrorRecoveryManager()
    return _recovery_manager