"""Traffic Logs routes — admin-only activity log viewer.

Gated on the signed-in user's role (``admin``). The old shared
LOG_VIEWER_USERNAME/PASSWORD gate is gone — admins use the same
session cookie they use for everything else.
"""

import json
import os
import re
from datetime import datetime
from zoneinfo import ZoneInfo

from flask import Blueprint, jsonify, make_response, render_template, request

from src.utils.logging_utils import log_web_activity
from web.auth import helpers

# Default resolves relative to this worktree's root (web/routes/ -> repo root)
# so the dev instance reads its own captures, not prod's.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CCR_CAPTURE_DIR = os.environ.get(
    'CCR_SHIM_CAPTURE_DIR',
    os.path.join(_REPO_ROOT, 'data', 'transient', 'shim_captures'),
)
_EASTERN = ZoneInfo('America/New_York')
_CAPTURE_FNAME_RE = re.compile(r'^\d+-[A-Za-z0-9._-]+\.json$')

traffic_logs_bp = Blueprint('traffic_logs', __name__)


def _check_admin(req) -> bool:
    """Admin = signed-in user with role=admin (req kept for callsite compat)."""
    return helpers.is_admin()


@traffic_logs_bp.route('/traffic-logs')
@helpers.admin_required
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


@traffic_logs_bp.route('/api/traffic-logs/web-activity')


def api_web_activity():
    if not _check_admin(request):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    from src.utils.bot_logs_db import get_web_activity
    limit = request.args.get('limit', 200, type=int)
    offset = request.args.get('offset', 0, type=int)
    path_filter = request.args.get('path', '').strip()
    user_filter = request.args.get('user', '').strip()
    rows = get_web_activity(limit=limit, offset=offset, path_filter=path_filter,
                            user_filter=user_filter)
    return jsonify({'success': True, 'rows': rows})


@traffic_logs_bp.route('/api/traffic-logs/url-users')
def api_url_users():
    """Per-URL user breakdown: each URL with its top users + hit counts."""
    if not _check_admin(request):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    from src.utils.bot_logs_db import get_url_user_breakdown
    limit_urls = request.args.get('limit_urls', 50, type=int)
    users_per_url = request.args.get('users_per_url', 20, type=int)
    days = request.args.get('days', 30, type=int)
    path_prefix = request.args.get('path_prefix', '/').strip() or '/'
    rows = get_url_user_breakdown(
        limit_urls=limit_urls,
        users_per_url=users_per_url,
        path_prefix=path_prefix,
        days=days,
    )
    return jsonify({'success': True, 'rows': rows, 'days': days})


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


def _summarize_ccr_capture(path: str) -> dict | None:
    try:
        st = os.stat(path)
        with open(path, 'rb') as f:
            env = json.load(f)
    except Exception:
        return None
    if not isinstance(env, dict):
        return None
    # New shim writes an envelope; older shim wrote the raw request payload
    # directly. Detect by presence of a nested "request" object.
    if isinstance(env.get('request'), dict):
        req = env['request']
        envelope_ts = env.get('ts_ms')
        envelope_alias = env.get('alias') or ''
        envelope_ip = env.get('client_ip') or ''
        envelope_user = env.get('client_user') or ''
    else:
        req = env
        envelope_ts = None
        envelope_alias = ''
        envelope_ip = ''
        envelope_user = ''
    messages = req.get('messages') or []
    system = req.get('system') or ''
    tools = req.get('tools') or []
    last_user_preview = ''
    for msg in reversed(messages):
        if msg.get('role') != 'user':
            continue
        content = msg.get('content')
        if isinstance(content, str):
            last_user_preview = content
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get('type') == 'text':
                    last_user_preview = block.get('text', '')
                    break
        if last_user_preview:
            break
    # Fall back to filename prefix (the shim's int(time.time()*1000) at write
    # time) before mtime, since mtime can drift if the file is later touched.
    fname = os.path.basename(path)
    fname_ts = None
    prefix = fname.split('-', 1)[0]
    if prefix.isdigit():
        try:
            fname_ts = int(prefix)
        except ValueError:
            fname_ts = None
    ts_ms = envelope_ts or fname_ts or int(st.st_mtime * 1000)
    ts_eastern = datetime.fromtimestamp(ts_ms / 1000, tz=_EASTERN).strftime('%Y-%m-%d %H:%M:%S')
    return {
        'id': fname,
        'ts_ms': ts_ms,
        'timestamp_eastern': ts_eastern,
        'alias': envelope_alias or req.get('model') or '',
        'client_ip': envelope_ip,
        'client_user': envelope_user,
        'num_messages': len(messages),
        'num_tools': len(tools) if isinstance(tools, list) else 0,
        'system_chars': len(system) if isinstance(system, str) else 0,
        'prompt_preview': last_user_preview[:200],
        'size_bytes': st.st_size,
    }


@traffic_logs_bp.route('/api/traffic-logs/ccr-captures')
def api_ccr_captures():
    if not _check_admin(request):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    limit = request.args.get('limit', 200, type=int)
    offset = request.args.get('offset', 0, type=int)
    ip_filter = request.args.get('ip', '').strip()
    alias_filter = request.args.get('alias', '').strip()
    user_filter = request.args.get('user', '').strip().lower()

    if not os.path.isdir(CCR_CAPTURE_DIR):
        return jsonify({'success': True, 'rows': [], 'total': 0})

    try:
        files = [
            f for f in os.listdir(CCR_CAPTURE_DIR)
            if _CAPTURE_FNAME_RE.match(f)
        ]
    except OSError:
        return jsonify({'success': True, 'rows': [], 'total': 0})
    files.sort(reverse=True)

    rows: list[dict] = []
    scanned = 0
    matched = 0
    for fname in files:
        scanned += 1
        summary = _summarize_ccr_capture(os.path.join(CCR_CAPTURE_DIR, fname))
        if not summary:
            continue
        if ip_filter and ip_filter not in summary['client_ip']:
            continue
        if alias_filter and alias_filter not in summary['alias']:
            continue
        if user_filter and user_filter not in (summary['client_user'] or '').lower():
            continue
        if matched >= offset and len(rows) < limit:
            rows.append(summary)
        matched += 1
        if len(rows) >= limit and matched > offset + limit + 50:
            break
    return jsonify({'success': True, 'rows': rows, 'total': matched, 'scanned': scanned})


@traffic_logs_bp.route('/api/traffic-logs/pat-usage')
def api_pat_usage():
    """Per-PAT IP fingerprint table — sharing-signal view for admins.

    One row per active PAT (active = exists in pats table, including
    expired/revoked so the admin can see the historical pattern). A row
    is 'shared' when distinct_ip_count > 1; the UI highlights those.
    """
    if not _check_admin(request):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    from web.auth import db as auth_db
    rows = auth_db.list_pat_usage_admin()
    for r in rows:
        for key in ('created_at', 'expires_at', 'last_used_at'):
            ts = r.get(key)
            r[f'{key}_eastern'] = (
                datetime.fromtimestamp(ts, tz=_EASTERN).strftime('%Y-%m-%d %H:%M')
                if ts else ''
            )
        for ip in r['ips']:
            for key in ('first_seen_at', 'last_seen_at'):
                ip[f'{key}_eastern'] = datetime.fromtimestamp(
                    ip[key], tz=_EASTERN).strftime('%Y-%m-%d %H:%M')
    return jsonify({'success': True, 'rows': rows})


@traffic_logs_bp.route('/api/traffic-logs/ccr-capture/<path:capture_id>')
def api_ccr_capture_detail(capture_id: str):
    if not _check_admin(request):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    if not _CAPTURE_FNAME_RE.match(capture_id):
        return jsonify({'success': False, 'error': 'Invalid id'}), 400
    full_path = os.path.join(CCR_CAPTURE_DIR, capture_id)
    if not os.path.isfile(full_path):
        return jsonify({'success': False, 'error': 'Not found'}), 404
    try:
        with open(full_path, 'rb') as f:
            env = json.load(f)
    except Exception as exc:
        return jsonify({'success': False, 'error': f'Read failed: {exc}'}), 500
    return jsonify({'success': True, 'capture': env})
