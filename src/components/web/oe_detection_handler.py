"""Web handler for OE Detection dashboard.

Follows existing handler pattern: lazy imports, {success, data} responses,
thread-locking for concurrent operation prevention.
"""

import logging
import threading

logger = logging.getLogger(__name__)

_scan_lock = threading.Lock()
_scan_in_progress = False


def get_dashboard_data(start_date=None, end_date=None) -> dict:
    """Read dashboard data: summary stats + latest scores table."""
    try:
        from services.oe_detection_db import get_summary_stats, get_latest_scores

        stats = get_summary_stats(start_date=start_date, end_date=end_date)
        scores = get_latest_scores(start_date=start_date, end_date=end_date)

        return {
            'success': True,
            'has_data': stats['total_scanned'] > 0,
            'stats': stats,
            'scores': scores,
        }
    except Exception as e:
        logger.error(f"Error reading OE dashboard data: {e}", exc_info=True)
        return {'success': False, 'error': str(e)}


def get_employee_detail(employee_id: str) -> dict:
    """Get score history + signal breakdown for an employee."""
    try:
        from services.oe_detection_db import get_employee_history, get_signal_details

        history = get_employee_history(employee_id)
        if not history:
            return {'success': True, 'has_data': False, 'history': [], 'signals': []}

        # Get signals for the most recent score
        latest_score_id = history[0]['score_id']
        signals = get_signal_details(latest_score_id)

        return {
            'success': True,
            'has_data': True,
            'history': history,
            'signals': signals,
        }
    except Exception as e:
        logger.error(f"Error reading employee detail {employee_id}: {e}", exc_info=True)
        return {'success': False, 'error': str(e)}


def get_scan_history() -> dict:
    """Get recent scan runs."""
    try:
        from services.oe_detection_db import get_scan_history as db_get_scans

        scans = db_get_scans(limit=20)
        return {'success': True, 'scans': scans}
    except Exception as e:
        logger.error(f"Error reading scan history: {e}", exc_info=True)
        return {'success': False, 'error': str(e)}


def trigger_scan(employee_id=None, dry_run=False) -> dict:
    """Trigger a manual OE detection scan in a background thread."""
    global _scan_in_progress

    if not _scan_lock.acquire(blocking=False):
        return {'success': False, 'error': 'A scan is already in progress'}

    try:
        _scan_in_progress = True

        def _run():
            global _scan_in_progress
            try:
                from src.components.oe_detection.config.loader import load_oe_config
                from src.components.oe_detection.scanner import run_scan

                config = load_oe_config()
                run_scan(config, dry_run=dry_run, employee_id=employee_id)
            except Exception as e:
                logger.error(f"Manual scan failed: {e}", exc_info=True)
            finally:
                _scan_in_progress = False
                _scan_lock.release()

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()

        return {
            'success': True,
            'message': f'Scan started {"(dry run)" if dry_run else ""}',
            'employee_id': employee_id,
        }
    except Exception as e:
        _scan_in_progress = False
        _scan_lock.release()
        logger.error(f"Failed to start scan: {e}", exc_info=True)
        return {'success': False, 'error': str(e)}


def is_scan_in_progress() -> bool:
    return _scan_in_progress
