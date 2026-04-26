"""Traffic Logs routes — admin-only activity log viewer.

Uses the same LOG_VIEWER_USERNAME / LOG_VIEWER_PASSWORD credentials
as the bot status API (Mission Control restart buttons).
"""

import os
import secrets

from flask import Blueprint, jsonify, make_response, render_template, request

from src.utils.logging_utils import log_web_activity

traffic_logs_bp = Blueprint('traffic_logs', __name__)


def _check_admin(req) -> bool:
    """Check admin credentials from JSON body or query params."""
    expected_user = os.environ.get('LOG_VIEWER_USERNAME', '').strip()
    expected_pass = os.environ.get('LOG_VIEWER_PASSWORD', '').strip()
    if not expected_user or not expected_pass:
        return True
    data = req.get_json(silent=True) or {}
    provided_user = data.get('username', '') or req.args.get('username', '')
    provided_pass = data.get('password', '') or req.args.get('password', '')
    return (secrets.compare_digest(provided_user, expected_user)
            and secrets.compare_digest(provided_pass, expected_pass))


@traffic_logs_bp.route('/traffic-logs')


def traffic_logs_page():
    return render_template('traffic_logs.html')


@traffic_logs_bp.route('/api/traffic-logs/exclude-me', methods=['POST'])
def traffic_logs_exclude_me():
    """Set a cookie to exclude the current user from traffic logging."""
    if not _check_admin(request):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    resp = make_response(jsonify({'success': True, 'message': 'You are now excluded from traffic logs'}))
    resp.set_cookie('traffic_log_exclude', 'true', max_age=365 * 24 * 3600, httponly=False, samesite='Lax')
    return resp


@traffic_logs_bp.route('/api/traffic-logs/auth', methods=['POST'])
def traffic_logs_auth():
    if not _check_admin(request):
        return jsonify({'success': False, 'error': 'Invalid password'}), 403
    return jsonify({'success': True})


@traffic_logs_bp.route('/api/traffic-logs/web-activity')


def api_web_activity():
    if not _check_admin(request):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    from src.utils.bot_logs_db import get_web_activity
    limit = request.args.get('limit', 200, type=int)
    offset = request.args.get('offset', 0, type=int)
    path_filter = request.args.get('path', '').strip()
    rows = get_web_activity(limit=limit, offset=offset, path_filter=path_filter)
    return jsonify({'success': True, 'rows': rows})


@traffic_logs_bp.route('/api/traffic-logs/stats')


def api_web_stats():
    if not _check_admin(request):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    from src.utils.bot_logs_db import get_web_activity_stats
    stats = get_web_activity_stats()
    return jsonify({'success': True, **stats})


@traffic_logs_bp.route('/api/traffic-logs/bot-activity')


def api_bot_activity():
    if not _check_admin(request):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    from src.utils.bot_logs_db import get_bot_activity
    limit = request.args.get('limit', 200, type=int)
    offset = request.args.get('offset', 0, type=int)
    rows = get_bot_activity(limit=limit, offset=offset)
    return jsonify({'success': True, 'rows': rows})


@traffic_logs_bp.route('/api/traffic-logs/conversations')


def api_conversations():
    if not _check_admin(request):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    from src.utils.bot_logs_db import get_conversations
    limit = request.args.get('limit', 200, type=int)
    offset = request.args.get('offset', 0, type=int)
    rows = get_conversations(limit=limit, offset=offset)
    return jsonify({'success': True, 'rows': rows})
