#!/usr/bin/env python3
"""View historical enrichment metrics and performance trends.

Usage:
    python src/view_enrichment_metrics.py
    python src/view_enrichment_metrics.py --last 10  # Show last 10 runs
"""
import argparse
import json
import sys
from datetime import datetime
from pathlib import Path


def format_timestamp(ts_str: str) -> str:
    """Format ISO timestamp to readable format."""
    try:
        dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return ts_str


def print_metrics_table(metrics_list: list, limit: int = None):
    """Print metrics in a formatted table."""
    if not metrics_list:
        print("No metrics found.")
        return

    # Apply limit if specified
    if limit:
        metrics_list = metrics_list[-limit:]

    print("\n" + "=" * 140)
    print("TICKET ENRICHMENT METRICS HISTORY")
    print("=" * 140)
    print(f"{'Date':<20} {'Workers':<8} {'Total':<8} {'Success':<8} {'Failed':<8} "
          f"{'Rate Lmt':<10} {'RL %':<8} {'Time (m)':<10} {'TPS':<8}")
    print("-" * 140)

    for m in metrics_list:
        timestamp = format_timestamp(m.get('timestamp', 'N/A'))
        workers = m.get('max_workers', 'N/A')
        total = m.get('total_requests', 0)
        success = m.get('successful', 0)
        failed = m.get('failed', 0)
        rate_limited = m.get('rate_limited', 0)
        rl_pct = m.get('rate_limit_percentage', 0)
        elapsed = m.get('elapsed_time', 0) / 60  # Convert to minutes
        tps = m.get('throughput_per_sec', 0)

        print(f"{timestamp:<20} {workers:<8} {total:<8} {success:<8} {failed:<8} "
              f"{rate_limited:<10} {rl_pct:<8.2f} {elapsed:<10.1f} {tps:<8.2f}")

    print("=" * 140)


def print_detailed_metrics(metrics: dict):
    """Print detailed metrics for a single run."""
    print("\n" + "=" * 80)
    print("DETAILED METRICS")
    print("=" * 80)
    print(f"Timestamp:         {format_timestamp(metrics.get('timestamp', 'N/A'))}")
    print(f"Workers:           {metrics.get('max_workers', 'N/A')}")
    print(f"Total Requests:    {metrics.get('total_requests', 0)}")
    print(f"Successful:        {metrics.get('successful', 0)} ({metrics.get('success_rate', 0):.1f}%)")
    print(f"Failed:            {metrics.get('failed', 0)}")
    print(f"Rate Limited:      {metrics.get('rate_limited', 0)} ({metrics.get('rate_limit_percentage', 0):.2f}%)")
    print(f"Elapsed Time:      {metrics.get('elapsed_time', 0):.1f}s ({metrics.get('elapsed_time', 0)/60:.1f}m)")
    print(f"Throughput:        {metrics.get('throughput_per_sec', 0):.2f} tickets/sec")

    retry_breakdown = metrics.get('retry_breakdown', {})
    if retry_breakdown:
        print("\nRetry Breakdown:")
        for attempt, count in sorted(retry_breakdown.items(), key=lambda x: int(x[0])):
            print(f"  Attempt {attempt}: {count} retries")

    if metrics.get('total_retry_wait_time', 0) > 0:
        total_wait = metrics.get('total_retry_wait_time', 0)
        avg_wait = total_wait / metrics.get('rate_limited', 1)
        print(f"\nTotal Wait Time:   {total_wait:.1f}s ({total_wait/60:.1f}m)")
        print(f"Avg Wait/Retry:    {avg_wait:.1f}s")

    print("=" * 80)


def analyze_trends(metrics_list: list):
    """Analyze and print performance trends."""
    if len(metrics_list) < 2:
        return

    print("\n" + "=" * 80)
    print("TREND ANALYSIS (Last 5 runs)")
    print("=" * 80)

    recent = metrics_list[-5:]

    # Average metrics
    avg_workers = sum(m.get('max_workers', 0) for m in recent) / len(recent)
    avg_rl_pct = sum(m.get('rate_limit_percentage', 0) for m in recent) / len(recent)
    avg_tps = sum(m.get('throughput_per_sec', 0) for m in recent) / len(recent)
    avg_time = sum(m.get('elapsed_time', 0) for m in recent) / len(recent) / 60

    print(f"Average Workers:       {avg_workers:.0f}")
    print(f"Average Rate Limit %:  {avg_rl_pct:.2f}%")
    print(f"Average Throughput:    {avg_tps:.2f} tickets/sec")
    print(f"Average Time:          {avg_time:.1f} minutes")

    # Recommendations
    print("\nRecommendations:")
    if avg_rl_pct > 15:
        print("  ⚠️  High rate limiting detected - consider reducing TICKET_ENRICHMENT_WORKERS")
        print(f"     Current avg: {avg_workers:.0f}, Try: {max(10, int(avg_workers * 0.7))}")
    elif avg_rl_pct < 3 and avg_workers < 150:
        print("  ✅ Low rate limiting - you can safely increase TICKET_ENRICHMENT_WORKERS")
        print(f"     Current avg: {avg_workers:.0f}, Try: {min(200, int(avg_workers * 1.3))}")
    else:
        print("  ✅ Rate limiting within acceptable range")

    print("=" * 80)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='View ticket enrichment metrics history')
    parser.add_argument('--last', type=int, help='Show only the last N runs')
    parser.add_argument('--detailed', action='store_true', help='Show detailed metrics for last run')
    parser.add_argument('--trends', action='store_true', help='Show trend analysis')
    args = parser.parse_args()

    # Find most recent metrics file
    root_dir = Path(__file__).parent.parent
    data_dir = root_dir / 'data' / 'transient' / 'secOps'

    if not data_dir.exists():
        print(f"Error: Data directory not found: {data_dir}")
        sys.exit(1)

    # Find all date directories and get the most recent one
    date_dirs = sorted([d for d in data_dir.iterdir() if d.is_dir()], reverse=True)
    if not date_dirs:
        print("No data directories found.")
        sys.exit(1)

    metrics_file = None
    for date_dir in date_dirs:
        potential_file = date_dir / 'enrichment_metrics.json'
        if potential_file.exists():
            metrics_file = potential_file
            break

    if not metrics_file:
        print("No enrichment_metrics.json found in any date directory.")
        sys.exit(1)

    print(f"Reading metrics from: {metrics_file}")

    # Load metrics
    try:
        with open(metrics_file, 'r') as f:
            metrics_data = json.load(f)

        # Handle both list and single object formats
        if isinstance(metrics_data, dict):
            metrics_data = [metrics_data]

        if not metrics_data:
            print("No metrics data found.")
            sys.exit(1)

        # Print table
        print_metrics_table(metrics_data, limit=args.last)

        # Detailed view
        if args.detailed and metrics_data:
            print_detailed_metrics(metrics_data[-1])

        # Trend analysis
        if args.trends:
            analyze_trends(metrics_data)

    except json.JSONDecodeError as e:
        print(f"Error reading metrics file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
