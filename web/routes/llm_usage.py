"""LLM Usage dashboard — admin-only cost, token, and prompt analytics.

Gated on the signed-in user's role (``admin``) via the session cookie.
The old hardcoded page password is gone — admins use the same session
cookie they use for everything else.
"""

from flask import Blueprint, jsonify, render_template, request
from web.auth import helpers

llm_usage_bp = Blueprint('llm_usage', __name__)


def _check_admin(req) -> bool:
    """Admin = signed-in user with role=admin (req kept for callsite compat)."""
    return helpers.is_admin()


@llm_usage_bp.route('/llm-usage')
@helpers.admin_required
def llm_usage_page():
    return render_template('llm_usage.html')


@llm_usage_bp.route('/api/llm-usage/stats')
def api_llm_stats():
    if not _check_admin(request):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    from src.utils.bot_logs_db import get_llm_usage_stats
    bot_filter = request.args.get('bot', '').strip()
    stats = get_llm_usage_stats(bot_filter=bot_filter)
    return jsonify({'success': True, **stats})


@llm_usage_bp.route('/api/llm-usage/logs')
def api_llm_logs():
    if not _check_admin(request):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    from src.utils.bot_logs_db import get_llm_usage
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    bot_filter = request.args.get('bot', '').strip()
    rows = get_llm_usage(limit=limit, offset=offset, bot_filter=bot_filter)
    return jsonify({'success': True, 'rows': rows})
