"""
XSOAR Timeline Handler

Thin wrapper over services.xsoar_timeline_db for the web layer.
Provides timeline data and sync status for the animated bar chart race.
"""

import logging

logger = logging.getLogger(__name__)


def get_timeline_data(start_date=None, end_date=None, granularity='monthly') -> dict:
    """Get timeline aggregation data for all 5 dimensions."""
    try:
        from services.xsoar_timeline_db import get_timeline_data as db_get_timeline_data, has_data, get_sync_metadata, get_date_range, get_ticket_count

        if not has_data():
            return {
                'success': True,
                'has_data': False,
                'data': None,
                'meta': None,
            }

        data = db_get_timeline_data(granularity=granularity, start_date=start_date, end_date=end_date)
        date_range = get_date_range()
        ticket_count = get_ticket_count()

        return {
            'success': True,
            'has_data': True,
            'data': data,
            'meta': {
                'ticket_count': ticket_count,
                'date_range': date_range,
                'last_synced_at': get_sync_metadata('last_sync_at'),
            },
        }

    except Exception as e:
        logger.error(f"Error reading timeline data: {e}", exc_info=True)
        return {'success': False, 'error': str(e)}


def get_sync_status() -> dict:
    """Return sync status for the UI."""
    try:
        from services.xsoar_timeline_db import has_data, get_ticket_count, get_sync_metadata

        return {
            'success': True,
            'has_data': has_data(),
            'ticket_count': get_ticket_count() if has_data() else 0,
            'last_synced_at': get_sync_metadata('last_sync_at'),
        }

    except Exception as e:
        logger.error(f"Error reading sync status: {e}", exc_info=True)
        return {'success': False, 'error': str(e)}
