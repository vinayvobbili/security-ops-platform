"""Connectors dashboard routes: overview of all external integrations."""

import logging

from flask import Blueprint, jsonify, render_template

from src.utils.logging_utils import log_web_activity

logger = logging.getLogger(__name__)
connectors_bp = Blueprint('connectors', __name__)


@connectors_bp.route('/connectors')
@log_web_activity
def connectors_page():
    """Render the connectors dashboard page."""
    from src.components.web import connectors_handler
    statuses = connectors_handler.get_all_connector_statuses(run_probes=False)
    categories = connectors_handler.get_connector_categories()
    return render_template(
        'connectors.html',
        connectors=statuses['connectors'],
        summary=statuses['summary'],
        categories=categories,
    )


@connectors_bp.route('/api/connectors/status')
@log_web_activity
def connectors_status_api():
    """Return live health-check results for all connectors (JSON)."""
    try:
        from src.components.web import connectors_handler
        statuses = connectors_handler.get_all_connector_statuses(run_probes=True)
        return jsonify({'success': True, **statuses})
    except Exception as exc:
        logger.error("Error checking connector statuses: %s", exc, exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500
