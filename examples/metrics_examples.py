"""
Example of how to access metrics programmatically in Python
"""

# Import the performance monitoring functions
from services.my_model import (
    performance_monitor,
    session_manager,
    get_performance_report,
    get_metrics_summary,
    health_check
)


def example_usage():
    """Examples of different ways to fetch metrics"""

    # Method 1: Get raw comprehensive data
    raw_stats = performance_monitor.get_stats()
    print(f"Current concurrent users: {raw_stats['concurrent_users']}")
    print(f"Average response time: {raw_stats['avg_response_time_seconds']}s")

    # Method 2: Get formatted performance report (same as bot command)
    detailed_report = get_performance_report()
    print(detailed_report)

    # Method 3: Get summary for dashboards/APIs
    summary = get_metrics_summary()
    print(f"Quick status: {summary['concurrent_users']} users, {summary['avg_response_time_seconds']}s avg")

    # Method 4: Get health check (same as bot status command)
    health = health_check()
    print(health)

    # Method 5: Get specific metrics
    concurrent_users = performance_monitor.get_concurrent_users()
    memory_usage = performance_monitor.get_memory_usage()
    query_volume = performance_monitor.get_queries_per_hour(24)

    print(f"Memory: {memory_usage['system_memory_percent']}%")
    print(f"24h queries: {sum(query_volume.values())}")

    # Method 6: Check for capacity warnings
    warning = performance_monitor.get_capacity_warning()
    if warning:
        print(f"⚠️ Warning: {warning}")
    else:
        print("✅ All systems normal")


if __name__ == "__main__":
    example_usage()
