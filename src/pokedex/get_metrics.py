#!/usr/bin/env python3
"""
Standalone script to fetch bot performance metrics
Usage: python get_metrics.py [--format json|table|summary]
"""

import sys
import json
import argparse
from datetime import datetime
from typing import Dict, Any

# Add the project root to Python path
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

def fetch_metrics() -> Dict[str, Any]:
    """Fetch metrics from the performance monitor"""
    try:
        from pokedex_bot.core.my_model import performance_monitor, session_manager

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

def format_metrics_table(metrics: Dict[str, Any]) -> str:
    """Format metrics as a readable table"""
    if 'error' in metrics:
        return f"❌ Error: {metrics['error']}"

    perf = metrics['performance']
    sessions = metrics['sessions']

    output = ["=" * 60, "🤖 BOT PERFORMANCE METRICS", "=" * 60, f"📅 Timestamp: {metrics['timestamp']}", "", "📊 CORE METRICS", "-" * 30, f"  Concurrent Users: {perf['concurrent_users']} (Peak: {perf['peak_concurrent_users']})",
              f"  Avg Response Time: {perf['avg_response_time_seconds']}s", f"  24h Query Volume: {perf['total_queries_24h']}", f"  Total Lifetime Queries: {perf['total_lifetime_queries']}", "", "💻 SYSTEM RESOURCES", "-" * 30]

    # Core metrics

    # System resources
    system = perf['system']
    output.append(f"  Memory Usage: {system['memory_percent']}% ({system['memory_available_gb']}GB free)")
    output.append(f"  CPU Usage: {system['cpu_percent']}%")
    output.append(f"  Process Memory: {system['process_memory_mb']}MB")
    output.append("")

    # Performance
    output.append("⚡ PERFORMANCE")
    output.append("-" * 30)
    output.append(f"  Cache Hit Rate: {perf['cache_hit_rate']}%")
    output.append(f"  Total Errors: {perf['total_errors']} (Lifetime: {perf['total_lifetime_errors']})")
    output.append(f"  Session Uptime: {perf['uptime_hours']:.1f}h")
    output.append(f"  Total Uptime: {perf['total_uptime_hours']:.1f}h")
    output.append("")

    # Sessions
    output.append("👥 USER SESSIONS")
    output.append("-" * 30)
    output.append(f"  Active Users: {sessions['active_users']}")
    output.append(f"  Total Users Ever: {sessions['total_users_ever']}")
    output.append(f"  Active Interactions: {sessions['total_interactions']}")
    output.append("")

    # Query types
    if perf['query_types']:
        output.append("📈 QUERY TYPES")
        output.append("-" * 30)
        for query_type, count in perf['query_types'].items():
            output.append(f"  {query_type.title()}: {count}")
        output.append("")

    # Warnings
    if metrics['capacity_warning']:
        output.append("⚠️ CAPACITY WARNINGS")
        output.append("-" * 30)
        output.append(f"  {metrics['capacity_warning']}")
        output.append("")
    else:
        output.append("✅ NO CAPACITY WARNINGS")
        output.append("")

    output.append("=" * 60)

    return "\n".join(output)

def format_metrics_summary(metrics: Dict[str, Any]) -> str:
    """Format metrics as a brief summary"""
    if 'error' in metrics:
        return f"❌ Error: {metrics['error']}"

    perf = metrics['performance']
    warning_text = f" ⚠️ {metrics['capacity_warning']}" if metrics['capacity_warning'] else " ✅"

    return f"""🤖 Bot Metrics Summary ({datetime.now().strftime('%H:%M:%S')})
Users: {perf['concurrent_users']}⏱️ Resp: {perf['avg_response_time_seconds']}s 📊 24h: {perf['total_queries_24h']} 💾 Mem: {perf['system']['memory_percent']}%{warning_text}"""

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Fetch bot performance metrics')
    parser.add_argument('--format', choices=['json', 'table', 'summary'],
                       default='table', help='Output format')
    parser.add_argument('--save', help='Save output to file')

    args = parser.parse_args()

    # Fetch metrics
    metrics = fetch_metrics()

    # Format output
    if args.format == 'json':
        output = json.dumps(metrics, indent=2)
    elif args.format == 'summary':
        output = format_metrics_summary(metrics)
    else:  # table
        output = format_metrics_table(metrics)

    # Output or save
    if args.save:
        with open(args.save, 'w') as f:
            f.write(output)
        print(f"Metrics saved to {args.save}")
    else:
        print(output)

if __name__ == '__main__':
    main()
