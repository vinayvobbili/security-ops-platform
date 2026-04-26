"""LLM Usage dashboard — tracks cost, tokens, and prompts across all bots."""

import secrets

from flask import Blueprint, jsonify, render_template, request

llm_usage_bp = Blueprint('llm_usage', __name__)

LLM_USAGE_PASSWORD = "qwerty123"


def _check_auth(req) -> bool:
    data = req.get_json(silent=True) or {}
    provided = data.get('password', '') or req.args.get('password', '')
    return secrets.compare_digest(provided, LLM_USAGE_PASSWORD)


@llm_usage_bp.route('/llm-usage')
def llm_usage_page():
    return render_template('llm_usage.html')


@llm_usage_bp.route('/api/llm-usage/auth', methods=['POST'])
def api_llm_auth():
    if not _check_auth(request):
        return jsonify({'success': False, 'error': 'Invalid password'}), 403
    return jsonify({'success': True})


@llm_usage_bp.route('/api/llm-usage/stats')
def api_llm_stats():
    if not _check_auth(request):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    from src.utils.bot_logs_db import get_llm_usage_stats
    bot_filter = request.args.get('bot', '').strip()
    stats = get_llm_usage_stats(bot_filter=bot_filter)
    return jsonify({'success': True, **stats})


@llm_usage_bp.route('/api/llm-usage/logs')
def api_llm_logs():
    if not _check_auth(request):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    from src.utils.bot_logs_db import get_llm_usage
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    bot_filter = request.args.get('bot', '').strip()
    rows = get_llm_usage(limit=limit, offset=offset, bot_filter=bot_filter)
    return jsonify({'success': True, 'rows': rows})
