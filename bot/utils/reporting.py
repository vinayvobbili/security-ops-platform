# /services/reporting.py
"""
Reporting Module

This module provides reporting functions for health checks, performance metrics,
and help information. Extracted from the main module to improve organization.
"""

import logging
from datetime import datetime
from typing import Dict, Optional

from services.performance_monitor import PerformanceMonitor
from services.session_manager import SessionManager


def generate_health_check_report(
    performance_monitor: PerformanceMonitor,
    session_manager: SessionManager,
    component_status: Dict[str, bool]
) -> str:
    """Generate comprehensive health check report"""
    
    # Get performance stats
    perf_stats = performance_monitor.get_stats()
    session_stats = session_manager.get_stats()

    # Check for capacity warnings
    warning = performance_monitor.get_capacity_warning()

    # Build comprehensive status report
    status_icon, status_text = _determine_system_status(component_status, warning)
    
    health_report = f"{status_icon} **{status_text}**\n\n"

    # Performance metrics
    health_report += _format_performance_metrics(perf_stats)
    
    # System resources
    health_report += _format_system_resources(perf_stats)
    
    # Session info
    health_report += _format_session_info(session_stats)

    return health_report


def _determine_system_status(component_status: Dict[str, bool], warning: Optional[str]) -> tuple:
    """Determine overall system status"""
    if all(v for v in component_status.values()):
        status_icon = "🟢"
        status_text = "All systems operational"
    else:
        status_icon = "🟡"
        issues = [k for k, v in component_status.items() if not v]
        status_text = f"Issues detected: {', '.join(issues)}"

    # Add warning if system is under stress
    if warning:
        status_icon = "🟠"
        status_text += f" ⚠️ Capacity warning: {warning}"
    
    return status_icon, status_text


def _format_performance_metrics(perf_stats: Dict) -> str:
    """Format performance metrics section"""
    metrics_section = f"## 📊 Performance Metrics\n"
    metrics_section += f"• **Current Session Uptime:** {perf_stats['uptime_hours']:.1f} hours\n"
    metrics_section += f"• **Total Lifetime Uptime:** {perf_stats['total_uptime_hours']:.1f} hours\n"
    metrics_section += f"• **Current Users:** {perf_stats['concurrent_users']} (Peak Ever: {perf_stats['peak_concurrent_users']})\n"
    metrics_section += f"• **Queries (24h):** {perf_stats['total_queries_24h']}\n"
    metrics_section += f"• **Total Lifetime Queries:** {perf_stats['total_lifetime_queries']}\n"
    metrics_section += f"• **Avg Response Time:** {perf_stats['avg_response_time_seconds']}s\n"
    metrics_section += f"• **Cache Hit Rate:** {perf_stats['cache_hit_rate']}%\n"
    metrics_section += f"• **Session Errors:** {perf_stats['total_errors']} (Lifetime: {perf_stats['total_lifetime_errors']})\n\n"
    return metrics_section


def _format_system_resources(perf_stats: Dict) -> str:
    """Format system resources section"""
    if not perf_stats['system']['memory_percent']:
        return ""
        
    resources_section = f"## 💻 System Resources\n"
    resources_section += f"• **Memory:** {perf_stats['system']['memory_percent']}% used ({perf_stats['system']['memory_available_gb']}GB free)\n"
    resources_section += f"• **CPU:** {perf_stats['system']['cpu_percent']}%\n"
    resources_section += f"• **Disk:** {perf_stats['system']['disk_percent']}% used ({perf_stats['system']['disk_free_gb']}GB free)\n\n"
    return resources_section


def _format_session_info(session_stats: Dict) -> str:
    """Format session information section"""
    session_section = f"## 👥 Session Info\n"
    session_section += f"• **Active Users:** {session_stats['active_users']}\n"
    session_section += f"• **Total Users Ever:** {session_stats['total_users_ever']}\n"
    session_section += f"• **Active Interactions:** {session_stats['total_interactions']}"
    return session_section


def generate_performance_report(performance_monitor: PerformanceMonitor) -> str:
    """Generate detailed performance report"""
    stats = performance_monitor.get_stats()

    report = f"""## 📊 Detailed Performance Report

### 🕐 Uptime & Usage
• **System Uptime:** {stats['uptime_hours']:.1f} hours
• **Current Active Users:** {stats['concurrent_users']}
• **Peak Concurrent Users:** {stats['peak_concurrent_users']}
• **Total Queries (24h):** {stats['total_queries_24h']}

### ⚡ Response Performance
• **Average Response Time:** {stats['avg_response_time_seconds']}s
• **Total Response Samples:** {stats['total_response_samples']}
• **Cache Hit Rate:** {stats['cache_hit_rate']}%
• **Cache Hits:** {stats['cache_hits']}
• **Cache Misses:** {stats['cache_misses']}

### 🚫 Error Tracking
• **Total Errors:** {stats['total_errors']}
• **Last Error:** {stats['last_error_time'] or 'None'}

### 💻 System Resources
• **System Memory:** {stats['system']['memory_percent']}% used
• **Available Memory:** {stats['system']['memory_available_gb']}GB
• **Process Memory:** {stats['system']['process_memory_mb']}MB ({stats['system']['process_memory_percent']}%)
• **CPU Usage:** {stats['system']['cpu_percent']}%
• **Disk Usage:** {stats['system']['disk_percent']}% used
• **Free Disk Space:** {stats['system']['disk_free_gb']}GB

### 📈 Query Types Distribution"""

    # Add query types
    if stats['query_types']:
        for query_type, count in stats['query_types'].items():
            report += f"\n• **{query_type.title()}:** {count} queries"
    else:
        report += "\n• No query data available yet"

    # Add hourly breakdown
    hourly_queries = performance_monitor.get_queries_per_hour()
    if hourly_queries:
        report += f"\n\n### 📅 Hourly Query Volume (Last 24h)"
        recent_hours = sorted(hourly_queries.keys())[-12:]  # Show last 12 hours
        for hour in recent_hours:
            hour_display = datetime.strptime(hour, "%Y-%m-%d-%H").strftime("%m/%d %H:00")
            report += f"\n• **{hour_display}:** {hourly_queries[hour]} queries"

    return report


def generate_metrics_summary_report(performance_monitor: PerformanceMonitor) -> Dict:
    """Generate metrics summary for programmatic access"""
    stats = performance_monitor.get_stats()

    return {
        'concurrent_users': stats['concurrent_users'],
        'peak_concurrent_users': stats['peak_concurrent_users'],
        'avg_response_time_seconds': stats['avg_response_time_seconds'],
        'total_queries_24h': stats['total_queries_24h'],
        'memory_usage_percent': stats['system']['memory_percent'],
        'cpu_usage_percent': stats['system']['cpu_percent'],
        'cache_hit_rate': stats['cache_hit_rate'],
        'total_errors': stats['total_errors'],
        'uptime_hours': stats['uptime_hours'],
        'capacity_warning': performance_monitor.get_capacity_warning()
    }


def format_metrics_summary_for_chat(summary: Dict) -> str:
    """Format metrics summary for chat display"""
    response = f"""## 📊 Quick Metrics Summary

• **Concurrent Users:** {summary['concurrent_users']} (Peak: {summary['peak_concurrent_users']})
• **Avg Response Time:** {summary['avg_response_time_seconds']}s
• **24h Queries:** {summary['total_queries_24h']}
• **Memory Usage:** {summary['memory_usage_percent']}%
• **CPU Usage:** {summary['cpu_usage_percent']}%
• **Cache Hit Rate:** {summary['cache_hit_rate']}%
• **Total Errors:** {summary['total_errors']}
• **Uptime:** {summary['uptime_hours']:.1f} hours
{f"⚠️ **Warning:** {summary['capacity_warning']}" if summary['capacity_warning'] else "✅ **Status:** All systems normal"}"""
    
    return response


def generate_help_message() -> str:
    """Generate help message with available commands"""
    help_text = """🤖 **Available Commands:**

• **Weather**: Ask about weather in various cities
  - "What's the weather in Tokyo?"
  - "Weather in San Francisco"

• **Document Search**: Search local documents and policies
  - "Search for information about security policies"
  - "Find documentation about procedures"

• **CrowdStrike**: Check device status (if available)
  - "Check containment status for HOSTNAME"
  - "Is HOSTNAME online?"
  - "Get device details for HOSTNAME"

• **System Status**: Check bot health and performance
  - "status" or "health check"

• **General Questions**: Ask me anything else!
  - I can help with general information and conversation

💡 **Tips:**
- You can ask follow-up questions - I remember our recent conversation
- Be specific in your questions for better results
- Use "status" to check my current performance and health"""

    return help_text


def generate_component_status_report(
    llm_available: bool = False,
    embeddings_available: bool = False,
    agent_available: bool = False,
    rag_available: bool = False,
    crowdstrike_available: bool = False
) -> Dict[str, bool]:
    """Generate component status dictionary"""
    return {
        'llm': llm_available,
        'embeddings': embeddings_available,
        'agent': agent_available,
        'rag': rag_available,
        'crowdstrike': crowdstrike_available
    }


def log_performance_summary(performance_monitor: PerformanceMonitor):
    """Log performance summary for monitoring purposes"""
    try:
        summary = generate_metrics_summary_report(performance_monitor)
        logging.info(
            f"Performance Summary - "
            f"Users: {summary['concurrent_users']}, "
            f"Avg Response: {summary['avg_response_time_seconds']}s, "
            f"24h Queries: {summary['total_queries_24h']}, "
            f"Memory: {summary['memory_usage_percent']}%, "
            f"CPU: {summary['cpu_usage_percent']}%, "
            f"Errors: {summary['total_errors']}"
        )
        
        if summary['capacity_warning']:
            logging.warning(f"Capacity Warning: {summary['capacity_warning']}")
            
    except Exception as e:
        logging.error(f"Failed to log performance summary: {e}")


def create_debug_report(state_manager) -> str:
    """Create debug report for troubleshooting"""
    try:
        health = state_manager.health_check()
        config_summary = "Configuration loaded" if state_manager.config else "Configuration not loaded"
        
        debug_info = f"""## 🔧 Debug Report

### System Status
• **Initialization Status:** {'Initialized' if state_manager.is_initialized else 'Not Initialized'}
• **Configuration:** {config_summary}

### Component Status"""
        
        for component, status in health['components'].items():
            status_icon = "✅" if status else "❌"
            debug_info += f"\n• **{component.title()}:** {status_icon}"
        
        if state_manager.performance_monitor:
            stats = state_manager.performance_monitor.get_stats()
            debug_info += f"\n\n### Recent Activity"
            debug_info += f"\n• **Total Queries:** {stats['total_lifetime_queries']}"
            debug_info += f"\n• **Current Users:** {stats['concurrent_users']}"
            debug_info += f"\n• **Errors:** {stats['total_errors']}"
        
        return debug_info
        
    except Exception as e:
        return f"Error generating debug report: {str(e)}"