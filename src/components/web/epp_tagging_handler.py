"""
EPP Device Tagging Metrics Handler

Provides API endpoints for querying EPP (CrowdStrike/Tanium) device tagging metrics
from the SQLite database.
"""

import logging
from datetime import date, datetime, timedelta
from typing import Optional

from services.epp_tagging_db import (
    get_all_metrics_for_dashboard,
    get_summary_stats,
    get_monthly_stats,
    get_country_stats,
    get_daily_stats,
    get_region_stats,
    get_category_stats,
    get_ring_tag_stats,
    get_filter_options,
)

logger = logging.getLogger(__name__)


def get_dashboard_data(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    platform: Optional[str] = None
) -> dict:
    """
    Get all metrics needed for the dashboard.

    Args:
        start_date: Optional start date filter (YYYY-MM-DD)
        end_date: Optional end date filter (YYYY-MM-DD)
        platform: Optional platform filter ('CrowdStrike' or 'Tanium')

    Returns:
        Dictionary with all dashboard metrics
    """
    try:
        # Get base metrics
        metrics = get_all_metrics_for_dashboard()

        # Parse dates if provided
        start = datetime.strptime(start_date, '%Y-%m-%d').date() if start_date else None
        end = datetime.strptime(end_date, '%Y-%m-%d').date() if end_date else None

        # If date filters provided, get filtered daily stats
        if start or end:
            metrics['daily'] = get_daily_stats(start, end)

        # Add formatted summary for display
        summary = metrics['summary']
        by_platform = summary['by_platform']

        # Calculate Tanium totals (combine legacy 'Tanium', 'Tanium Cloud', and 'Tanium On-Prem')
        tanium_cloud_devices = by_platform.get('Tanium Cloud', {}).get('devices', 0)
        tanium_onprem_devices = by_platform.get('Tanium On-Prem', {}).get('devices', 0)
        tanium_legacy_devices = by_platform.get('Tanium', {}).get('devices', 0)
        tanium_total_devices = tanium_cloud_devices + tanium_onprem_devices + tanium_legacy_devices

        metrics['formatted_summary'] = {
            'total_devices': f"{summary['total_devices']:,}",
            'total_tagged': f"{summary['total_tagged']:,}",
            'success_rate': f"{(summary['total_tagged'] / summary['total_devices'] * 100):.1f}%" if summary['total_devices'] > 0 else "0%",
            'total_runs': summary['total_runs'],
            'date_range': f"{summary['earliest_date']} to {summary['latest_date']}",
            'crowdstrike_devices': f"{by_platform.get('CrowdStrike', {}).get('devices', 0):,}",
            'tanium_devices': f"{tanium_total_devices:,}",
            'tanium_cloud_devices': f"{tanium_cloud_devices:,}",
            'tanium_onprem_devices': f"{tanium_onprem_devices:,}",
        }

        # Add trend data for sparklines
        metrics['trends'] = calculate_trends(metrics['daily'])

        # Add filter options for client-side filtering
        metrics['filter_options'] = get_filter_options()

        return {
            'success': True,
            **metrics
        }

    except Exception as e:
        logger.error(f"Error fetching dashboard data: {e}", exc_info=True)
        return {
            'success': False,
            'error': str(e)
        }


def calculate_trends(daily_stats: list[dict]) -> dict:
    """
    Calculate trend data for dashboard KPI sparklines.

    Returns recent 30-day trend and week-over-week comparison.
    """
    if not daily_stats:
        return {'weekly': [], 'trend': 'stable', 'change_pct': 0}

    # Group by date (combine platforms)
    by_date = {}
    for row in daily_stats:
        d = row['run_date']
        if d not in by_date:
            by_date[d] = 0
        by_date[d] += row['successfully_tagged']

    # Sort by date
    sorted_dates = sorted(by_date.keys())

    # Get last 30 days
    recent_30 = sorted_dates[-30:] if len(sorted_dates) >= 30 else sorted_dates
    weekly_totals = [by_date[d] for d in recent_30]

    # Calculate week-over-week change
    if len(sorted_dates) >= 14:
        this_week = sum(by_date.get(d, 0) for d in sorted_dates[-7:])
        last_week = sum(by_date.get(d, 0) for d in sorted_dates[-14:-7])
        change_pct = ((this_week - last_week) / last_week * 100) if last_week > 0 else 0
        trend = 'up' if change_pct > 5 else 'down' if change_pct < -5 else 'stable'
    else:
        change_pct = 0
        trend = 'stable'

    return {
        'weekly': weekly_totals,
        'trend': trend,
        'change_pct': round(change_pct, 1)
    }


def get_chart_data_by_country(limit: int = 20) -> dict:
    """Get country breakdown for bar chart."""
    try:
        countries = get_country_stats()[:limit]
        return {
            'success': True,
            'labels': [c['country'] for c in countries],
            'values': [c['successfully_tagged'] for c in countries],
            'guessed': [c['country_guessed'] for c in countries]
        }
    except Exception as e:
        logger.error(f"Error fetching country chart data: {e}")
        return {'success': False, 'error': str(e)}


def get_chart_data_by_month() -> dict:
    """Get monthly breakdown for timeline chart."""
    try:
        monthly = get_monthly_stats()

        # Pivot data for stacked bar chart
        months = sorted(set(m['month'] for m in monthly))
        cs_data = []
        tanium_data = []

        for month in months:
            cs = next((m['successfully_tagged'] for m in monthly if m['month'] == month and m['platform'] == 'CrowdStrike'), 0)
            tn = next((m['successfully_tagged'] for m in monthly if m['month'] == month and m['platform'] == 'Tanium'), 0)
            cs_data.append(cs)
            tanium_data.append(tn)

        return {
            'success': True,
            'months': months,
            'crowdstrike': cs_data,
            'tanium': tanium_data
        }
    except Exception as e:
        logger.error(f"Error fetching monthly chart data: {e}")
        return {'success': False, 'error': str(e)}


def get_chart_data_by_platform() -> dict:
    """Get platform breakdown for pie chart."""
    try:
        summary = get_summary_stats()
        platforms = summary.get('by_platform', {})

        return {
            'success': True,
            'labels': list(platforms.keys()),
            'values': [p['tagged'] for p in platforms.values()],
            'runs': [p['runs'] for p in platforms.values()]
        }
    except Exception as e:
        logger.error(f"Error fetching platform chart data: {e}")
        return {'success': False, 'error': str(e)}


def get_chart_data_daily(days: int = 90) -> dict:
    """Get daily breakdown for timeline chart."""
    try:
        # Calculate date range
        end = date.today()
        start = end - timedelta(days=days)

        daily = get_daily_stats(start, end)

        # Pivot data for multi-line chart
        dates = sorted(set(d['run_date'] for d in daily))

        cs_data = []
        tanium_data = []

        for dt in dates:
            cs = sum(d['successfully_tagged'] for d in daily if d['run_date'] == dt and d['platform'] == 'CrowdStrike')
            tn = sum(d['successfully_tagged'] for d in daily if d['run_date'] == dt and d['platform'] == 'Tanium')
            cs_data.append(cs)
            tanium_data.append(tn)

        return {
            'success': True,
            'dates': dates,
            'crowdstrike': cs_data,
            'tanium': tanium_data
        }
    except Exception as e:
        logger.error(f"Error fetching daily chart data: {e}")
        return {'success': False, 'error': str(e)}


def get_ring_tag_distribution() -> dict:
    """Get ring tag distribution for chart."""
    try:
        tags = get_ring_tag_stats()

        # Group by ring number (Ring1, Ring2, Ring3, Ring4)
        ring_groups = {'Ring1': 0, 'Ring2': 0, 'Ring3': 0, 'Ring4': 0, 'Other': 0}
        for tag in tags:
            ring_tag = tag.get('ring_tag', '') or ''
            matched = False
            for ring in ['Ring1', 'Ring2', 'Ring3', 'Ring4']:
                if ring in ring_tag:
                    ring_groups[ring] += tag['successfully_tagged']
                    matched = True
                    break
            if not matched:
                ring_groups['Other'] += tag['successfully_tagged']

        # Remove empty groups
        ring_groups = {k: v for k, v in ring_groups.items() if v > 0}

        return {
            'success': True,
            'labels': list(ring_groups.keys()),
            'values': list(ring_groups.values())
        }
    except Exception as e:
        logger.error(f"Error fetching ring tag chart data: {e}")
        return {'success': False, 'error': str(e)}
