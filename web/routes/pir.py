"""PIR Management Platform routes.

Exposes Alex's PIR (Priority Intelligence Requirements) app as a Flask
blueprint under /pir.  The database layer lives in services/pir_app/db.py
and is used unchanged.
"""

import csv
import io
import urllib.parse

from flask import Blueprint, jsonify, redirect, render_template, request, make_response

from src.utils.logging_utils import log_web_activity

# Lazy-import db so the module path is resolved at call time, not import time.
_db = None


def _get_db():
    global _db
    if _db is None:
        from services.pir_app import db as pir_db
        pir_db.init_db()
        pir_db.start_cleanup_thread()
        _db = pir_db
    return _db


pir_bp = Blueprint('pir', __name__, url_prefix='/pir')

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_session():
    """Return the PIR session dict or None."""
    db = _get_db()
    session_id = request.cookies.get('pir_session')
    if not session_id:
        return None
    if len(session_id) > 100 or not all(c.isalnum() or c in '-_' for c in session_id):
        return None
    return db.get_session(session_id)


def _require_auth(role=None):
    """Return session dict or (error_response, status_code)."""
    session = _get_session()
    if not session:
        return jsonify({'error': 'Not authenticated'}), 401
    if role and session['role'] != role:
        return jsonify({'error': 'Insufficient permissions'}), 403
    return session


def _require_admin():
    session = _get_session()
    if not session:
        return jsonify({'error': 'Not authenticated'}), 401
    if session['role'] != 'admin':
        return jsonify({'error': 'Admin role required'}), 403
    return session


def _is_error(result):
    """True if result is a Flask error tuple rather than a session dict."""
    return isinstance(result, tuple)


def _validate_csrf(session):
    """Validate CSRF token from X-CSRF-Token header."""
    db = _get_db()
    token = request.headers.get('X-CSRF-Token')
    if not token:
        return False
    session_id = request.cookies.get('pir_session')
    if not session_id:
        return False
    return db.validate_csrf_token(session_id, token)


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------

@pir_bp.route('/')
@log_web_activity
def pir_root():
    session = _get_session()
    if session:
        return render_template('pir_app.html')
    return render_template('pir_login.html')


# ---------------------------------------------------------------------------
# Auth API
# ---------------------------------------------------------------------------

@pir_bp.route('/api/auth/login', methods=['POST'])
def pir_api_login():
    db = _get_db()
    body = request.get_json(silent=True) or {}
    username = (body.get('username') or '').strip()
    password = body.get('password') or ''

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if len(username) > 100 or len(password) > 200:
        return jsonify({'error': 'Invalid credentials'}), 400

    client_ip = request.remote_addr
    user = db.login(username, password, client_ip)

    if not user:
        return jsonify({'error': 'Invalid credentials or account locked'}), 401

    session_id, csrf_token = db.create_session(user['id'], user['username'], user['role'])
    resp = make_response(jsonify({
        'username': user['username'],
        'role': user['role'],
        'full_name': user.get('full_name', ''),
        'csrf_token': csrf_token,
    }))
    resp.set_cookie('pir_session', session_id, path='/pir',
                     httponly=True, samesite='Strict', max_age=28800)
    return resp


@pir_bp.route('/api/auth/logout', methods=['POST'])
def pir_api_logout():
    db = _get_db()
    session_id = request.cookies.get('pir_session')
    if session_id:
        db.delete_session(session_id)
    resp = make_response(jsonify({}))
    resp.set_cookie('pir_session', '', path='/pir', max_age=0,
                     httponly=True, samesite='Strict')
    return resp


@pir_bp.route('/api/auth/me')
def pir_api_me():
    session = _require_auth()
    if _is_error(session):
        return session
    return jsonify({
        'username': session['username'],
        'role': session['role'],
        'csrf_token': session.get('csrf_token', ''),
    })


@pir_bp.route('/api/auth/change-password', methods=['POST'])
def pir_api_change_password():
    db = _get_db()
    session = _require_auth()
    if _is_error(session):
        return session

    body = request.get_json(silent=True) or {}
    old_password = body.get('old_password', '')
    new_password = body.get('new_password', '')

    if not old_password or not new_password:
        return jsonify({'error': 'Old and new passwords required'}), 400
    if len(new_password) < 8:
        return jsonify({'error': 'New password must be at least 8 characters'}), 400
    if len(new_password) > 200:
        return jsonify({'error': 'Password too long'}), 400

    try:
        success = db.change_password(session['username'], old_password, new_password)
        if success:
            return jsonify({'ok': True, 'message': 'Password changed successfully'})
        return jsonify({'error': 'Current password is incorrect'}), 400
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


# ---------------------------------------------------------------------------
# Requirements API
# ---------------------------------------------------------------------------

@pir_bp.route('/api/requirements')
def pir_api_list_requirements():
    db = _get_db()
    session = _require_auth()
    if _is_error(session):
        return session
    reqs = db.get_requirements(
        req_type=request.args.get('type'),
        status=request.args.get('status'),
        priority=request.args.get('priority'),
        owner=request.args.get('owner'),
        search=request.args.get('q'),
    )
    return jsonify(reqs)


@pir_bp.route('/api/requirements/next-id')
def pir_api_next_req_id():
    db = _get_db()
    session = _require_auth()
    if _is_error(session):
        return session
    req_type = request.args.get('type', 'PIR')
    parent_id = request.args.get('parent_id')
    return jsonify({'req_id': db.next_req_id(req_type, parent_id)})


@pir_bp.route('/api/requirements', methods=['POST'])
def pir_api_create_requirement():
    db = _get_db()
    session = _require_auth()
    if _is_error(session):
        return session
    if session['role'] == 'viewer':
        return jsonify({'error': 'Viewer role cannot create requirements'}), 403
    if not _validate_csrf(session):
        return jsonify({'error': 'Invalid security token'}), 403

    data = request.get_json(silent=True) or {}
    req_id = (data.get('req_id') or '').strip()
    req_type = (data.get('req_type') or '').strip().upper()
    req_text = (data.get('req_text') or '').strip()
    parent_id = (data.get('parent_id') or '').strip() or None
    status = data.get('status', 'Active')

    if not req_id or not req_type or not req_text:
        return jsonify({'error': 'req_id, req_type, and req_text are required'}), 400

    try:
        db.validate_input_length(req_id, 'req_id', 100)
        db.validate_input_length(req_text, 'req_text')
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    if req_type not in ('PIR', 'EEI', 'SIR'):
        return jsonify({'error': 'req_type must be PIR, EEI, or SIR'}), 400
    if db.get_requirement(req_id):
        return jsonify({'error': f'{req_id} already exists'}), 409

    result = db.create_requirement(req_id, req_type, req_text,
                                    parent_id, status, session['username'])
    return jsonify(result), 201


@pir_bp.route('/api/requirements/<path:req_id>', methods=['DELETE'])
def pir_api_delete_requirement(req_id):
    db = _get_db()
    session = _require_auth()
    if _is_error(session):
        return session
    if session['role'] != 'admin':
        return jsonify({'error': 'Only admins can delete requirements'}), 403
    if not _validate_csrf(session):
        return jsonify({'error': 'Invalid security token'}), 403

    req_id = urllib.parse.unquote(req_id)[:100]
    if not db.get_requirement(req_id):
        return jsonify({'error': 'Not found'}), 404

    result = db.delete_requirement(req_id, session['username'])
    return jsonify({'ok': True, 'deleted': result['deleted'], 'ids': result['ids']})


@pir_bp.route('/api/requirements/<path:req_id>')
def pir_api_get_requirement(req_id):
    db = _get_db()
    session = _require_auth()
    if _is_error(session):
        return session
    req_id = urllib.parse.unquote(req_id)[:100]
    req = db.get_requirement(req_id)
    if not req:
        return jsonify({'error': 'Not found'}), 404
    req['coverage'] = db.get_source_coverage(req_id)
    return jsonify(req)


@pir_bp.route('/api/requirements/<path:req_id>', methods=['PUT'])
def pir_api_update_requirement(req_id):
    db = _get_db()
    session = _require_auth()
    if _is_error(session):
        return session
    if session['role'] == 'viewer':
        return jsonify({'error': 'Viewer role cannot edit'}), 403
    if not _validate_csrf(session):
        return jsonify({'error': 'Invalid security token'}), 403

    req_id = urllib.parse.unquote(req_id)[:100]
    data = request.get_json(silent=True) or {}
    req = db.get_requirement(req_id)
    if not req:
        return jsonify({'error': 'Not found'}), 404

    if session['role'] == 'analyst':
        if req.get('primary_owner') and req['primary_owner'] != session['username']:
            return jsonify({'error': 'You can only edit requirements assigned to you'}), 403

    try:
        if 'req_text' in data:
            db.validate_input_length(data['req_text'], 'req_text')
        if 'notes' in data:
            db.validate_input_length(data['notes'], 'notes')
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    db.update_requirement(req_id, data, session['username'])
    if 'coverage' in data and isinstance(data['coverage'], dict):
        db.upsert_many_sources(req_id, data['coverage'], session['username'])
    updated = db.get_requirement(req_id)
    updated['coverage'] = db.get_source_coverage(req_id)
    return jsonify(updated)


# ---------------------------------------------------------------------------
# Matrix / Stats / Gaps
# ---------------------------------------------------------------------------

@pir_bp.route('/api/matrix')
def pir_api_matrix():
    db = _get_db()
    session = _require_auth()
    if _is_error(session):
        return session
    data = db.get_matrix_data()
    return jsonify({'requirements': data, 'sources': db.get_sources()})


@pir_bp.route('/api/stats')
def pir_api_stats():
    db = _get_db()
    session = _require_auth()
    if _is_error(session):
        return session
    return jsonify(db.get_stats())


@pir_bp.route('/api/gaps')
def pir_api_gaps():
    db = _get_db()
    session = _require_auth()
    if _is_error(session):
        return session
    return jsonify(db.get_coverage_gaps())


# ---------------------------------------------------------------------------
# Users (admin)
# ---------------------------------------------------------------------------

@pir_bp.route('/api/users')
def pir_api_list_users():
    db = _get_db()
    session = _require_admin()
    if _is_error(session):
        return session
    return jsonify(db.get_users())


@pir_bp.route('/api/users', methods=['POST'])
def pir_api_create_user():
    db = _get_db()
    session = _require_admin()
    if _is_error(session):
        return session
    if not _validate_csrf(session):
        return jsonify({'error': 'Invalid security token'}), 403

    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    role = data.get('role', 'analyst')
    full_name = (data.get('full_name') or '').strip()

    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400
    if len(username) > 100 or len(password) > 200 or len(full_name) > 200:
        return jsonify({'error': 'Input too long'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    if role not in ('admin', 'analyst', 'viewer'):
        return jsonify({'error': 'role must be admin, analyst, or viewer'}), 400

    try:
        db.create_user(username, password, role, full_name)
        return jsonify({'ok': True}), 201
    except Exception:
        return jsonify({'error': 'Username already exists'}), 409


@pir_bp.route('/api/users/<int:user_id>', methods=['PUT'])
def pir_api_update_user(user_id):
    db = _get_db()
    session = _require_admin()
    if _is_error(session):
        return session
    if not _validate_csrf(session):
        return jsonify({'error': 'Invalid security token'}), 403

    data = request.get_json(silent=True) or {}
    if 'password' in data and data['password']:
        if len(data['password']) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        if len(data['password']) > 200:
            return jsonify({'error': 'Password too long'}), 400
    db.update_user(user_id, data)
    return jsonify({'ok': True})


@pir_bp.route('/api/users/<int:user_id>', methods=['DELETE'])
def pir_api_delete_user(user_id):
    db = _get_db()
    session = _require_admin()
    if _is_error(session):
        return session
    if not _validate_csrf(session):
        return jsonify({'error': 'Invalid security token'}), 403
    db.delete_user(user_id)
    return jsonify({'ok': True})


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

@pir_bp.route('/api/audit')
def pir_api_audit():
    db = _get_db()
    session = _require_admin()
    if _is_error(session):
        return session
    limit = min(int(request.args.get('limit', 200)), 1000)
    return jsonify(db.get_audit_log(limit))


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

@pir_bp.route('/api/sources')
def pir_api_sources():
    db = _get_db()
    session = _require_auth()
    if _is_error(session):
        return session
    return jsonify({'sources': db.get_sources()})


@pir_bp.route('/api/sources', methods=['POST'])
def pir_api_add_source():
    db = _get_db()
    session = _require_admin()
    if _is_error(session):
        return session
    if not _validate_csrf(session):
        return jsonify({'error': 'Invalid security token'}), 403
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Source name required'}), 400
    if len(name) > 200:
        return jsonify({'error': 'Source name too long'}), 400
    try:
        db.add_source(name)
        return jsonify({'ok': True}), 201
    except Exception:
        return jsonify({'error': 'Source already exists'}), 409


@pir_bp.route('/api/sources/<path:name>', methods=['DELETE'])
def pir_api_delete_source(name):
    db = _get_db()
    session = _require_admin()
    if _is_error(session):
        return session
    if not _validate_csrf(session):
        return jsonify({'error': 'Invalid security token'}), 403
    name = urllib.parse.unquote(name)[:200]
    db.delete_source(name)
    return jsonify({'ok': True})


# ---------------------------------------------------------------------------
# CSV Export
# ---------------------------------------------------------------------------

@pir_bp.route('/api/export/requirements')
def pir_api_export_requirements():
    db = _get_db()
    session = _require_auth()
    if _is_error(session):
        return session

    data = db.get_export_data()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(['req_id', 'req_type', 'parent_id', 'req_text',
                'priority', 'status', 'primary_owner',
                'collection_frequency', 'notes', 'covered_sources'])
    for r in data['requirements']:
        cov = data['coverage'].get(r['req_id'], {})
        covered = [s for s, v in cov.items() if v and v.get('coverage_value')]
        w.writerow([
            r['req_id'], r['req_type'], r.get('parent_id', ''),
            r['req_text'], r.get('priority', ''), r.get('status', ''),
            r.get('primary_owner', ''), r.get('collection_frequency', ''),
            r.get('notes', ''), '; '.join(covered),
        ])

    resp = make_response(out.getvalue().encode('utf-8-sig'))
    resp.headers['Content-Type'] = 'text/csv; charset=utf-8'
    resp.headers['Content-Disposition'] = 'attachment; filename="requirements.csv"'
    return resp


@pir_bp.route('/api/export/matrix')
def pir_api_export_matrix():
    db = _get_db()
    session = _require_auth()
    if _is_error(session):
        return session

    data = db.get_export_data()
    sources = data['sources']
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(['req_id', 'req_type', 'parent_id', 'req_text',
                'priority', 'status'] + sources)
    for r in data['requirements']:
        cov = data['coverage'].get(r['req_id'], {})
        src_vals = [((cov.get(s) or {}).get('coverage_value') or '') for s in sources]
        w.writerow([
            r['req_id'], r['req_type'], r.get('parent_id', ''),
            r['req_text'], r.get('priority', ''), r.get('status', ''),
        ] + src_vals)

    resp = make_response(out.getvalue().encode('utf-8-sig'))
    resp.headers['Content-Type'] = 'text/csv; charset=utf-8'
    resp.headers['Content-Disposition'] = 'attachment; filename="coverage_matrix.csv"'
    return resp
