"""Domain monitoring routes."""

import json
import logging
from datetime import datetime
from pathlib import Path

from flask import Blueprint, jsonify, render_template

from src.utils.logging_utils import log_web_activity

logger = logging.getLogger(__name__)
monitoring_bp = Blueprint('monitoring', __name__)

# Domain Monitoring Results Directory
MONITORING_RESULTS_DIR = Path(__file__).parent.parent.parent / "data" / "transient" / "domain_monitoring"


@monitoring_bp.route('/domain-monitoring')
@monitoring_bp.route('/domain-monitoring/<filename>')
@log_web_activity
def domain_monitoring_report(filename=None):
    """Display domain monitoring report page."""
    return render_template('domain_monitoring_report.html', filename=filename)


@monitoring_bp.route('/api/domain-monitoring/results')
@monitoring_bp.route('/api/domain-monitoring/results/<date_str>')
@log_web_activity
def api_domain_monitoring_results(date_str=None):
    """API endpoint to get monitoring results.

    Args:
        date_str: Optional date string (YYYY-MM-DD) for historical results.
                  Defaults to latest.json.
    """
    try:
        import re

        if date_str is None:
            # Load latest results
            filepath = MONITORING_RESULTS_DIR / 'latest.json'
        else:
            # Validate date format to prevent directory traversal
            if not re.match(r'^\d{4}-\d{2}-\d{2}$', date_str):
                return jsonify({'success': False, 'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400

            # Load from date subdirectory
            filepath = MONITORING_RESULTS_DIR / date_str / 'results.json'

        if not filepath.exists():
            return jsonify({
                'success': False,
                'error': 'No monitoring results found. Run the daily monitoring job first.'
            }), 404

        with open(filepath, 'r') as f:
            results = json.load(f)

        return jsonify({'success': True, 'results': results, 'date': date_str})

    except Exception as exc:
        logger.error(f"Error fetching monitoring results: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': str(exc)}), 500


@monitoring_bp.route('/api/domain-monitoring/history')
@log_web_activity
def api_domain_monitoring_history():
    """API endpoint to list available monitoring result files."""
    try:
        if not MONITORING_RESULTS_DIR.exists():
            return jsonify({'success': True, 'files': []})

        files = []
        # Look for date subdirectories (YYYY-MM-DD format) containing results.json
        for date_dir in sorted(MONITORING_RESULTS_DIR.iterdir(), reverse=True):
            if date_dir.is_dir() and len(date_dir.name) == 10:  # YYYY-MM-DD is 10 chars
                results_file = date_dir / 'results.json'
                if results_file.exists():
                    stat = results_file.stat()
                    files.append({
                        'filename': date_dir.name,  # The date string
                        'date': date_dir.name,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                    })

        return jsonify({'success': True, 'files': files})

    except Exception as exc:
        logger.error(f"Error listing monitoring history: {exc}", exc_info=True)
        return jsonify({'success': False, 'error': str(exc)}), 500
