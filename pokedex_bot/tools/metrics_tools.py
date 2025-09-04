# /pokedex_bot/tools/metrics_tools.py
"""
Metrics Tools

This module provides bot performance and system metrics tools for the security operations bot.
Integrates with the existing metrics functionality from src/pokedx/get_metrics.py
"""

import logging
import json
from datetime import datetime
from langchain_core.tools import tool
from typing import Dict, Any


class MetricsToolsManager:
    """Manager for metrics and performance monitoring tools"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def get_tools(self) -> list:
        """Get list of available metrics tools"""
        return [
            get_bot_metrics_tool(),
            get_bot_metrics_summary_tool()
        ]
    
    def is_available(self) -> bool:
        """Check if metrics tools are available"""
        try:
            # Test if we can import the required modules
            from pokedex_bot.core.my_model import performance_monitor, session_manager
            return True
        except ImportError:
            return False


def get_bot_metrics_tool():
    """Factory function to create detailed bot metrics tool"""
    @tool
    def get_bot_metrics() -> str:
        """Get comprehensive bot performance metrics including system resources, response times, user sessions, and capacity warnings. Use this when asked for 'metrics', 'performance', 'status', or 'system stats'."""
        try:
            from pokedex_bot.core.my_model import performance_monitor, session_manager
            
            # Get comprehensive stats
            perf_stats = performance_monitor.get_stats()
            session_stats = session_manager.get_stats()
            capacity_warning = performance_monitor.get_capacity_warning()
            
            # Format as readable table for Webex
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            result = [
                "📊 **BOT PERFORMANCE METRICS**",
                f"🕐 **Timestamp:** {timestamp}",
                "",
                "**📈 Core Metrics:**",
                f"• Concurrent Users: **{perf_stats['concurrent_users']}** (Peak: **{perf_stats['peak_concurrent_users']}**)",
                f"• Avg Response Time: **{perf_stats['avg_response_time_seconds']}s**",
                f"• 24h Query Volume: **{perf_stats['total_queries_24h']}**",
                f"• Total Lifetime Queries: **{perf_stats['total_lifetime_queries']}**",
                "",
                "**💻 System Resources:**",
                f"• Memory Usage: **{perf_stats['system']['memory_percent']}%** ({perf_stats['system']['memory_available_gb']}GB free)",
                f"• CPU Usage: **{perf_stats['system']['cpu_percent']}%**",
                f"• Process Memory: **{perf_stats['system']['process_memory_mb']}MB**",
                "",
                "**⚡ Performance:**",
                f"• Cache Hit Rate: **{perf_stats['cache_hit_rate']}%**",
                f"• Total Errors: **{perf_stats['total_errors']}** (Lifetime: **{perf_stats['total_lifetime_errors']}**)",
                f"• Session Uptime: **{perf_stats['uptime_hours']:.1f}h**",
                f"• Total Uptime: **{perf_stats['total_uptime_hours']:.1f}h**",
                "",
                "**👥 User Sessions:**",
                f"• Active Users: **{session_stats['active_users']}**",
                f"• Total Users Ever: **{session_stats['total_users_ever']}**",
                f"• Active Interactions: **{session_stats['total_interactions']}**",
                ""
            ]
            
            # Add query types breakdown if available
            if perf_stats.get('query_types'):
                result.append("**📊 Query Types:**")
                for query_type, count in perf_stats['query_types'].items():
                    result.append(f"• {query_type.title()}: **{count}**")
                result.append("")
            
            # Add capacity warnings if any
            if capacity_warning:
                result.extend([
                    "**⚠️ Capacity Warnings:**",
                    f"• {capacity_warning}",
                    ""
                ])
            else:
                result.extend([
                    "**✅ System Status:**",
                    "• No capacity warnings - all systems operating normally",
                    ""
                ])
            
            return "\n".join(result)
            
        except ImportError as e:
            logging.error(f"Could not import performance monitor: {e}")
            return f"❌ **Metrics unavailable:** Performance monitoring not initialized - {str(e)}"
        except Exception as e:
            logging.error(f"Error getting bot metrics: {e}")
            return f"❌ **Error retrieving metrics:** {str(e)}"
    
    return get_bot_metrics


def get_bot_metrics_summary_tool():
    """Factory function to create bot metrics summary tool"""
    @tool  
    def get_bot_metrics_summary() -> str:
        """Get a brief summary of bot metrics including key performance indicators. Use this for quick status checks or when asked for a 'summary' or 'quick status'."""
        try:
            from pokedx_bot.core.my_model import performance_monitor, session_manager
            
            perf_stats = performance_monitor.get_stats()
            capacity_warning = performance_monitor.get_capacity_warning()
            
            warning_emoji = " ⚠️" if capacity_warning else " ✅"
            warning_text = f" - {capacity_warning}" if capacity_warning else ""
            
            summary = (
                f"🤖 **Bot Status Summary** ({datetime.now().strftime('%H:%M:%S')})\n"
                f"👥 Users: **{perf_stats['concurrent_users']}** | "
                f"⏱️ Response: **{perf_stats['avg_response_time_seconds']}s** | "
                f"📊 24h Queries: **{perf_stats['total_queries_24h']}** | "
                f"💾 Memory: **{perf_stats['system']['memory_percent']}%**{warning_emoji}{warning_text}"
            )
            
            return summary
            
        except ImportError as e:
            logging.error(f"Could not import performance monitor: {e}")
            return f"❌ **Metrics summary unavailable:** {str(e)}"
        except Exception as e:
            logging.error(f"Error getting metrics summary: {e}")
            return f"❌ **Error:** {str(e)}"
    
    return get_bot_metrics_summary


def _fetch_raw_metrics() -> Dict[str, Any]:
    """Helper function to fetch raw metrics data (used internally)"""
    try:
        from pokedx_bot.core.my_model import performance_monitor, session_manager

        # Get comprehensive stats
        perf_stats = performance_monitor.get_stats()
        session_stats = session_manager.get_stats()

        # Combine all metrics
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'performance': perf_stats,
            'sessions': session_stats,
            'capacity_warning': performance_monitor.get_capacity_warning()
        }

        return metrics

    except ImportError as e:
        return {'error': f'Could not import performance monitor: {e}'}
    except Exception as e:
        return {'error': f'Error fetching metrics: {e}'}