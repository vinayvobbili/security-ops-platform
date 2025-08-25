#!/usr/bin/env python3
"""
Demo Metrics Display Script

This script generates realistic demo metrics to showcase the SOC bot's usage analytics.
Perfect for management presentations and demos.
"""

import sys
import os
import json
from datetime import datetime, timedelta

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from bot.core.state_manager import get_state_manager
from bot.utils.reporting import generate_metrics_summary_report, format_metrics_summary_for_chat


def add_demo_metrics():
    """Add realistic demo metrics to performance data"""
    
    # Use direct path to performance data file
    project_root = os.path.join(os.path.dirname(__file__), '..', '..')
    data_file = os.path.join(project_root, "performance_data.json")
    
    print(f"📊 Adding demo metrics to {data_file}")
    
    # Generate realistic demo data
    demo_data = {
        'peak_concurrent_users': 8,
        'total_errors': 2,
        'cache_hits': 147,
        'cache_misses': 23,
        'total_lifetime_queries': 342,
        'total_lifetime_errors': 3,
        'query_types': {
            'rag': 198,  # Document searches
            'weather': 45,
            'status': 67,
            'crowdstrike': 32
        },
        'hourly_queries': generate_hourly_demo_data(),
        'response_times': [1.2, 2.1, 1.8, 3.4, 1.9, 2.7, 1.5, 2.2, 1.7, 2.9, 1.4, 2.1],
        'last_error_time': (datetime.now() - timedelta(hours=6)).isoformat(),
        'initial_start_time': (datetime.now() - timedelta(days=3, hours=4)).isoformat(),
        'last_save_time': datetime.now().isoformat()
    }
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(data_file), exist_ok=True)
    
    # Save demo data
    with open(data_file, 'w') as f:
        json.dump(demo_data, f, indent=2)
    
    print("✅ Demo metrics added successfully!")
    print(f"📈 Total queries: {demo_data['total_lifetime_queries']}")
    print(f"👥 Peak concurrent users: {demo_data['peak_concurrent_users']}")
    print(f"🎯 Cache hit rate: {demo_data['cache_hits']/(demo_data['cache_hits']+demo_data['cache_misses'])*100:.1f}%")
    
    return demo_data


def generate_hourly_demo_data():
    """Generate realistic hourly query data for last 24 hours"""
    hourly_data = {}
    current_time = datetime.now()
    
    # Generate data for last 24 hours
    for i in range(24):
        hour_time = current_time - timedelta(hours=i)
        hour_key = hour_time.strftime("%Y-%m-%d-%H")
        
        # Simulate realistic SOC patterns
        hour_of_day = hour_time.hour
        
        if 6 <= hour_of_day <= 22:  # Business hours - higher activity
            queries = 8 + (i % 7)  # Vary between 8-15 queries
        else:  # Off hours - lower activity
            queries = 1 + (i % 4)  # Vary between 1-5 queries
            
        hourly_data[hour_key] = queries
    
    return hourly_data


def display_current_metrics():
    """Display current metrics in formatted way"""
    print("\n" + "="*60)
    print("📊 CURRENT SOC BOT METRICS")
    print("="*60)
    
    try:
        # Read directly from performance data file
        project_root = os.path.join(os.path.dirname(__file__), '..', '..')
        data_file = os.path.join(project_root, "performance_data.json")
        
        if os.path.exists(data_file):
            with open(data_file, 'r') as f:
                data = json.load(f)
            
            # Format metrics for console display
            total_cache = data.get('cache_hits', 0) + data.get('cache_misses', 0)
            hit_rate = (data.get('cache_hits', 0) / total_cache * 100) if total_cache > 0 else 0
            
            print(f"\n🔍 Quick Metrics Summary")
            print(f"  • Concurrent Users: {data.get('peak_concurrent_users', 0)} (Peak)")
            print(f"  • Lifetime Queries: {data.get('total_lifetime_queries', 0)}")
            print(f"  • Cache Hit Rate: {hit_rate:.1f}%")
            print(f"  • Total Errors: {data.get('total_errors', 0)}")
            
            if 'query_types' in data:
                print(f"\n📈 Query Types:")
                for query_type, count in data['query_types'].items():
                    print(f"  • {query_type.title()}: {count} queries")
            
            print(f"\n⏱️ Last Updated: {data.get('last_save_time', 'Unknown')}")
        else:
            print("❌ No performance data file found")
            print(f"Expected location: {data_file}")
            
    except Exception as e:
        print(f"❌ Error displaying metrics: {e}")


def main():
    """Main function"""
    print("🎯 SOC Bot Demo Metrics Generator")
    print("-" * 40)
    
    if len(sys.argv) > 1 and sys.argv[1] == "add":
        add_demo_metrics()
    else:
        display_current_metrics()
        
    print("\n💡 Usage:")
    print("  python demo_metrics.py add    # Add realistic demo data")
    print("  python demo_metrics.py        # Display current metrics")
    print("\n🚀 In Webex, type 'metrics' to see the formatted version!")


if __name__ == "__main__":
    main()