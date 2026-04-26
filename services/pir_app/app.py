"""
app.py  –  PIR Management Platform  (Python stdlib only, no pip required)

Start:   python app.py
Default: http://localhost:8080
         python app.py 9000   (custom port)
"""

import json
import mimetypes
import os
import re
import sys
import ssl
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from collections import defaultdict
from datetime import datetime, timedelta

import db

BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
DEFAULT_PORT  = 8080

# Set to True when SSL is enabled; used to add the Secure flag to cookies
_use_ssl = False

# Security: Rate limiting for API endpoints (IP-based)
_rate_limits = defaultdict(list)  # {ip: [timestamp,...]}
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 100  # max requests per window
LOGIN_RATE_LIMIT = 5  # max login attempts per window

# Whitelist of allowed template files to prevent path traversal
ALLOWED_TEMPLATES = {'index.html', 'login.html'}

# ---------------------------------------------------------------------------
# Small routing helper
# ---------------------------------------------------------------------------

ROUTES = []   # [(method, regex, handler_name)]

def route(method, pattern):
    def decorator(fn):
        ROUTES.append((method.upper(), re.compile('^' + pattern + '$'), fn))
        return fn
    return decorator

# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):

    # ------------------------------------------------------------------ util

    def _add_security_headers(self):
        """Add security headers to all responses."""
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
        self.send_header('Content-Security-Policy', "default-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
        # Remove Server header by not setting it (Python's http.server sets it by default)

    def _check_rate_limit(self, limit=RATE_LIMIT_MAX_REQUESTS) -> bool:
        """Check if client has exceeded rate limit. Returns True if under limit."""
        client_ip = self.client_address[0]
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=RATE_LIMIT_WINDOW)
        
        # Clean old timestamps
        _rate_limits[client_ip] = [t for t in _rate_limits[client_ip] if t > cutoff]
        
        # Check limit
        if len(_rate_limits[client_ip]) >= limit:
            return False
        
        # Record this request
        _rate_limits[client_ip].append(now)
        return True

    def _get_csrf_token(self):
        """Extract CSRF token from request headers or body."""
        # Try header first
        token = self.headers.get('X-CSRF-Token')
        if token:
            return token
        # For POST/PUT, might be in body (but we want it in headers)
        return None

    def _validate_csrf(self):
        """Validate CSRF token for state-changing operations."""
        session = self._get_session()
        if not session:
            return False
        
        token = self._get_csrf_token()
        if not token:
            return False
        
        cookie_header = self.headers.get('Cookie', '')
        session_id = None
        for part in cookie_header.split(';'):
            part = part.strip()
            if part.startswith('session='):
                session_id = part[len('session='):]
                break
        
        if not session_id:
            return False
        
        return db.validate_csrf_token(session_id, token)

    def _send(self, code: int, body, content_type='application/json'):
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode('utf-8')
            content_type = 'application/json'
        elif isinstance(body, str):
            data = body.encode('utf-8')
        else:
            data = body
        self.send_response(code)
        self._add_security_headers()
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_error_safe(self, code: int, message: str = None):
        """Send error response without exposing internal details."""
        safe_messages = {
            400: 'Bad Request',
            401: 'Unauthorized',
            403: 'Forbidden',
            404: 'Not Found',
            409: 'Conflict',
            429: 'Too Many Requests',
            500: 'Internal Server Error',
        }
        public_message = message if code in (400, 401, 403, 404, 429) else safe_messages.get(code, 'Error')
        self._send(code, {'error': public_message})

    def _redirect(self, location: str):
        self.send_response(302)
        self._add_security_headers()
        self.send_header('Location', location)
        self.end_headers()

    def _read_json(self):
        length = int(self.headers.get('Content-Length', 0))
        if length == 0:
            return {}
        if length > 1048576:  # 1MB max
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def _get_session(self):
        cookie_header = self.headers.get('Cookie', '')
        for part in cookie_header.split(';'):
            part = part.strip()
            if part.startswith('session='):
                session_id = part[len('session='):]
                # Validate session ID format to prevent injection
                if len(session_id) > 100 or not all(c.isalnum() or c in '-_' for c in session_id):
                    return None
                return db.get_session(session_id)
        return None

    def _require_auth(self, role=None):
        """Returns session dict or sends 401 and returns None."""
        session = self._get_session()
        if not session:
            self._send(401, {'error': 'Not authenticated'})
            return None
        if role and session['role'] != role:
            self._send(403, {'error': 'Insufficient permissions'})
            return None
        return session

    def _require_admin(self):
        session = self._get_session()
        if not session:
            self._send(401, {'error': 'Not authenticated'})
            return None
        if session['role'] != 'admin':
            self._send(403, {'error': 'Admin role required'})
            return None
        return session

    def _not_found(self):
        self._send(404, {'error': 'Not found'})

    # ------------------------------------------------------------------ serve static files

    def _serve_file(self, filepath: str):
        # Security: Validate that file is in templates directory and is allowed
        filename = os.path.basename(filepath)
        if filename not in ALLOWED_TEMPLATES:
            self._send(404, 'Not found', 'text/plain')
            return
        
        # Ensure file is actually in templates directory (prevent path traversal)
        real_path = os.path.realpath(filepath)
        real_templates = os.path.realpath(TEMPLATES_DIR)
        if not real_path.startswith(real_templates):
            self._send(404, 'Not found', 'text/plain')
            return
        
        if not os.path.isfile(filepath):
            self._send(404, 'Not found', 'text/plain')
            return
        
        try:
            mime, _ = mimetypes.guess_type(filepath)
            with open(filepath, 'rb') as f:
                data = f.read()
            self.send_response(200)
            self._add_security_headers()
            self.send_header('Content-Type', mime or 'application/octet-stream')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            print(f"[app] Error serving file {filepath}: {e}")
            self._send(500, 'Internal server error', 'text/plain')

    # ------------------------------------------------------------------ routing

    def _dispatch(self, method: str):
        parsed = urllib.parse.urlparse(self.path)
        path   = parsed.path
        qs     = urllib.parse.parse_qs(parsed.query)

        # Flatten single-value query params
        params = {k: v[0] if len(v) == 1 else v for k, v in qs.items()}

        for meth, pattern, handler in ROUTES:
            if meth != method:
                continue
            m = pattern.match(path)
            if m:
                handler(self, params, m.groups())
                return

        # Fallback: try to serve a template file (only allowed templates)
        safe_path = os.path.basename(path.lstrip('/'))  # Get just filename, no directory traversal
        if safe_path in ALLOWED_TEMPLATES:
            full_path = os.path.join(TEMPLATES_DIR, safe_path)
            self._serve_file(full_path)
        else:
            self._not_found()

    def do_GET(self):
        self._dispatch('GET')

    def do_POST(self):
        self._dispatch('POST')

    def do_PUT(self):
        self._dispatch('PUT')

    def do_DELETE(self):
        self._dispatch('DELETE')

    def do_OPTIONS(self):
        # No cross-origin access permitted for this internal application
        self.send_response(204)
        self.end_headers()

    def log_message(self, fmt, *args):
        # Quiet down the default stderr logging (still shows errors)
        if args and str(args[1]) not in ('200', '302', '304'):
            super().log_message(fmt, *args)


# ===========================================================================
# Route handlers
# ===========================================================================

# ---- Page routes -----------------------------------------------------------

@route('GET', '/')
def page_root(self, params, groups):
    session = self._get_session()
    if session:
        self._redirect('/app')
    else:
        self._redirect('/login')

@route('GET', '/login')
def page_login(self, params, groups):
    self._serve_file(os.path.join(TEMPLATES_DIR, 'login.html'))

@route('GET', '/app')
def page_app(self, params, groups):
    session = self._get_session()
    if not session:
        self._redirect('/login')
        return
    self._serve_file(os.path.join(TEMPLATES_DIR, 'index.html'))

# ---- Auth API --------------------------------------------------------------

@route('POST', '/api/auth/login')
def api_login(self, params, groups):
    # Rate limiting for login attempts
    if not self._check_rate_limit(LOGIN_RATE_LIMIT):
        self._send(429, {'error': 'Too many login attempts. Please try again later.'})
        return
    
    body = self._read_json()
    username = (body.get('username') or '').strip()
    password = (body.get('password') or '')
    
    if not username or not password:
        self._send(400, {'error': 'Username and password required'})
        return
    
    if len(username) > 100 or len(password) > 200:
        self._send(400, {'error': 'Invalid credentials'})
        return
    
    client_ip = self.client_address[0]
    user = db.login(username, password, client_ip)
    
    if not user:
        # Generic error message to prevent user enumeration
        self._send(401, {'error': 'Invalid credentials or account locked'})
        return
    
    try:
        session_id, csrf_token = db.create_session(user['id'], user['username'], user['role'])
        self.send_response(200)
        self._add_security_headers()
        self.send_header('Content-Type', 'application/json')
        # 8-hour session cookie with security flags
        cookie = f'session={session_id}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800'
        if _use_ssl:
            cookie += '; Secure'
        self.send_header('Set-Cookie', cookie)
        body_bytes = json.dumps({
            'username': user['username'],
            'role': user['role'],
            'full_name': user.get('full_name', ''),
            'csrf_token': csrf_token
        }).encode('utf-8')
        self.send_header('Content-Length', str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)
    except Exception as e:
        print(f"[app] Login error: {e}")
        self._send_error_safe(500)

@route('POST', '/api/auth/logout')
def api_logout(self, params, groups):
    cookie_header = self.headers.get('Cookie', '')
    for part in cookie_header.split(';'):
        part = part.strip()
        if part.startswith('session='):
            db.delete_session(part[len('session='):])
    self.send_response(200)
    self._add_security_headers()
    self.send_header('Content-Type', 'application/json')
    self.send_header('Set-Cookie', 'session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict')
    self.send_header('Content-Length', '2')
    self.end_headers()
    self.wfile.write(b'{}')

@route('GET', '/api/auth/me')
def api_me(self, params, groups):
    session = self._require_auth()
    if not session:
        return
    self._send(200, {
        'username':  session['username'],
        'role':      session['role'],
        'csrf_token': session.get('csrf_token', ''),
    })

@route('POST', '/api/auth/change-password')
def api_change_password(self, params, groups):
    session = self._require_auth()
    if not session:
        return
    
    # No CSRF check here - we verify old password instead
    
    body = self._read_json()
    old_password = body.get('old_password', '')
    new_password = body.get('new_password', '')
    
    if not old_password or not new_password:
        self._send(400, {'error': 'Old and new passwords required'})
        return
    
    if len(new_password) < 8:
        self._send(400, {'error': 'New password must be at least 8 characters'})
        return
    
    if len(new_password) > 200:
        self._send(400, {'error': 'Password too long'})
        return
    
    try:
        success = db.change_password(session['username'], old_password, new_password)
        if success:
            self._send(200, {'ok': True, 'message': 'Password changed successfully'})
        else:
            self._send(400, {'error': 'Current password is incorrect'})
    except ValueError as e:
        self._send(400, {'error': str(e)})
    except Exception as e:
        print(f"[app] Password change error: {e}")
        self._send_error_safe(500)

# ---- Requirements API ------------------------------------------------------

@route('GET', '/api/requirements')
def api_list_requirements(self, params, groups):
    session = self._require_auth()
    if not session:
        return
    reqs = db.get_requirements(
        req_type = params.get('type'),
        status   = params.get('status'),
        priority = params.get('priority'),
        owner    = params.get('owner'),
        search   = params.get('q'),
    )
    self._send(200, reqs)

@route('GET', '/api/requirements/next-id')
def api_next_req_id(self, params, groups):
    session = self._require_auth()
    if not session:
        return
    req_type  = params.get('type', 'PIR')
    parent_id = params.get('parent_id')
    self._send(200, {'req_id': db.next_req_id(req_type, parent_id)})

@route('POST', '/api/requirements')
def api_create_requirement(self, params, groups):
    session = self._require_auth()
    if not session:
        return
    if session['role'] == 'viewer':
        self._send(403, {'error': 'Viewer role cannot create requirements'})
        return
    
    # CSRF protection
    if not self._validate_csrf():
        self._send(403, {'error': 'Invalid security token'})
        return
    
    data      = self._read_json()
    req_id    = (data.get('req_id') or '').strip()
    req_type  = (data.get('req_type') or '').strip().upper()
    req_text  = (data.get('req_text') or '').strip()
    parent_id = (data.get('parent_id') or '').strip() or None
    status    = data.get('status', 'Active')
    
    # Input validation
    if not req_id or not req_type or not req_text:
        self._send(400, {'error': 'req_id, req_type, and req_text are required'})
        return
    
    try:
        db.validate_input_length(req_id, 'req_id', 100)
        db.validate_input_length(req_text, 'req_text')
    except ValueError as e:
        self._send(400, {'error': str(e)})
        return
    
    if req_type not in ('PIR', 'EEI', 'SIR'):
        self._send(400, {'error': 'req_type must be PIR, EEI, or SIR'})
        return
    
    if db.get_requirement(req_id):
        self._send(409, {'error': f'{req_id} already exists'})
        return
    
    try:
        result = db.create_requirement(req_id, req_type, req_text,
                                       parent_id, status, session['username'])
        self._send(201, result)
    except Exception as e:
        print(f"[app] Create requirement error: {e}")
        self._send_error_safe(500)

@route('DELETE', r'/api/requirements/([^/]+)')
def api_delete_requirement(self, params, groups):
    session = self._require_auth()
    if not session:
        return
    if session['role'] != 'admin':
        self._send(403, {'error': 'Only admins can delete requirements'})
        return
    
    # CSRF protection
    if not self._validate_csrf():
        self._send(403, {'error': 'Invalid security token'})
        return
    
    req_id = urllib.parse.unquote(groups[0])[:100]  # Limit length
    if not db.get_requirement(req_id):
        self._not_found()
        return
    
    try:
        result = db.delete_requirement(req_id, session['username'])
        self._send(200, {'ok': True, 'deleted': result['deleted'], 'ids': result['ids']})
    except Exception as e:
        print(f"[app] Delete requirement error: {e}")
        self._send_error_safe(500)

@route('GET', r'/api/requirements/([^/]+)')
def api_get_requirement(self, params, groups):
    session = self._require_auth()
    if not session:
        return
    req_id = urllib.parse.unquote(groups[0])[:100]
    req = db.get_requirement(req_id)
    if not req:
        self._not_found()
        return
    req['coverage'] = db.get_source_coverage(req_id)
    self._send(200, req)

@route('PUT', r'/api/requirements/([^/]+)')
def api_update_requirement(self, params, groups):
    session = self._require_auth()
    if not session:
        return
    if session['role'] == 'viewer':
        self._send(403, {'error': 'Viewer role cannot edit'})
        return
    
    # CSRF protection
    if not self._validate_csrf():
        self._send(403, {'error': 'Invalid security token'})
        return
    
    req_id = urllib.parse.unquote(groups[0])[:100]  # Limit length
    data   = self._read_json()
    req    = db.get_requirement(req_id)
    if not req:
        self._not_found()
        return
    
    # Analysts may only update requirements assigned to them
    if session['role'] == 'analyst':
        if req.get('primary_owner') and req['primary_owner'] != session['username']:
            self._send(403, {'error': 'You can only edit requirements assigned to you'})
            return
    
    # Validate input lengths
    try:
        if 'req_text' in data:
            db.validate_input_length(data['req_text'], 'req_text')
        if 'notes' in data:
            db.validate_input_length(data['notes'], 'notes')
    except ValueError as e:
        self._send(400, {'error': str(e)})
        return
    
    try:
        db.update_requirement(req_id, data, session['username'])
        # Handle inlined coverage updates (values may be plain strings or {coverage_value, detection_logic} dicts)
        if 'coverage' in data and isinstance(data['coverage'], dict):
            db.upsert_many_sources(req_id, data['coverage'], session['username'])
        updated = db.get_requirement(req_id)
        updated['coverage'] = db.get_source_coverage(req_id)
        self._send(200, updated)
    except Exception as e:
        print(f"[app] Update requirement error: {e}")
        self._send_error_safe(500)

# ---- Matrix API ------------------------------------------------------------

@route('GET', '/api/matrix')
def api_matrix(self, params, groups):
    session = self._require_auth()
    if not session:
        return
    data = db.get_matrix_data()
    self._send(200, {
        'requirements': data,
        'sources':      db.get_sources(),
    })

# ---- Stats API -------------------------------------------------------------

@route('GET', '/api/stats')
def api_stats(self, params, groups):
    session = self._require_auth()
    if not session:
        return
    self._send(200, db.get_stats())

# ---- Users API (admin only) ------------------------------------------------

@route('GET', '/api/users')
def api_list_users(self, params, groups):
    session = self._require_admin()
    if not session:
        return
    self._send(200, db.get_users())

@route('POST', '/api/users')
def api_create_user(self, params, groups):
    session = self._require_admin()
    if not session:
        return
    
    # CSRF protection
    if not self._validate_csrf():
        self._send(403, {'error': 'Invalid security token'})
        return
    
    data = self._read_json()
    username  = (data.get('username') or '').strip()
    password  = (data.get('password') or '')
    role      = data.get('role', 'analyst')
    full_name = (data.get('full_name') or '').strip()
    
    if not username or not password:
        self._send(400, {'error': 'username and password required'})
        return
    
    if len(username) > 100 or len(password) > 200 or len(full_name) > 200:
        self._send(400, {'error': 'Input too long'})
        return
    
    if len(password) < 8:
        self._send(400, {'error': 'Password must be at least 8 characters'})
        return
    
    if role not in ('admin', 'analyst', 'viewer'):
        self._send(400, {'error': 'role must be admin, analyst, or viewer'})
        return
    
    try:
        db.create_user(username, password, role, full_name)
        self._send(201, {'ok': True})
    except Exception as e:
        print(f"[app] Create user error: {e}")
        self._send(409, {'error': 'Username already exists'})

@route('PUT', r'/api/users/(\d+)')
def api_update_user(self, params, groups):
    session = self._require_admin()
    if not session:
        return
    
    # CSRF protection
    if not self._validate_csrf():
        self._send(403, {'error': 'Invalid security token'})
        return
    
    try:
        user_id = int(groups[0])
        data    = self._read_json()
        
        # Validate input lengths
        if 'password' in data and data['password']:
            if len(data['password']) < 8:
                self._send(400, {'error': 'Password must be at least 8 characters'})
                return
            if len(data['password']) > 200:
                self._send(400, {'error': 'Password too long'})
                return
        
        db.update_user(user_id, data)
        self._send(200, {'ok': True})
    except Exception as e:
        print(f"[app] Update user error: {e}")
        self._send_error_safe(500)

@route('DELETE', r'/api/users/(\d+)')
def api_delete_user(self, params, groups):
    session = self._require_admin()
    if not session:
        return
    
    # CSRF protection
    if not self._validate_csrf():
        self._send(403, {'error': 'Invalid security token'})
        return
    
    try:
        user_id = int(groups[0])
        db.delete_user(user_id)
        self._send(200, {'ok': True})
    except Exception as e:
        print(f"[app] Delete user error: {e}")
        self._send_error_safe(500)

# ---- Audit log -------------------------------------------------------------

@route('GET', '/api/audit')
def api_audit(self, params, groups):
    session = self._require_admin()
    if not session:
        return
    limit = min(int(params.get('limit', 200)), 1000)
    self._send(200, db.get_audit_log(limit))

# ---- Gap analysis ----------------------------------------------------------

@route('GET', '/api/gaps')
def api_gaps(self, params, groups):
    session = self._require_auth()
    if not session:
        return
    self._send(200, db.get_coverage_gaps())

# ---- CSV Export ------------------------------------------------------------

@route('GET', '/api/export/requirements')
def api_export_requirements(self, params, groups):
    session = self._require_auth()
    if not session:
        return
    import csv, io
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
    body = out.getvalue().encode('utf-8-sig')
    self.send_response(200)
    self._add_security_headers()
    self.send_header('Content-Type', 'text/csv; charset=utf-8')
    self.send_header('Content-Disposition', 'attachment; filename="requirements.csv"')
    self.send_header('Content-Length', str(len(body)))
    self.end_headers()
    self.wfile.write(body)

@route('GET', '/api/export/matrix')
def api_export_matrix(self, params, groups):
    session = self._require_auth()
    if not session:
        return
    import csv, io
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
    body = out.getvalue().encode('utf-8-sig')
    self.send_response(200)
    self._add_security_headers()
    self.send_header('Content-Type', 'text/csv; charset=utf-8')
    self.send_header('Content-Disposition', 'attachment; filename="coverage_matrix.csv"')
    self.send_header('Content-Length', str(len(body)))
    self.end_headers()
    self.wfile.write(body)

# ---- Source metadata -------------------------------------------------------

@route('GET', '/api/sources')
def api_sources(self, params, groups):
    session = self._require_auth()
    if not session:
        return
    self._send(200, {'sources': db.get_sources()})

@route('POST', '/api/sources')
def api_add_source(self, params, groups):
    session = self._require_admin()
    if not session:
        return
    if not self._validate_csrf():
        self._send(403, {'error': 'Invalid security token'})
        return
    data = self._read_json()
    name = (data.get('name') or '').strip()
    if not name:
        self._send(400, {'error': 'Source name required'})
        return
    if len(name) > 200:
        self._send(400, {'error': 'Source name too long'})
        return
    try:
        db.add_source(name)
        self._send(201, {'ok': True})
    except Exception:
        self._send(409, {'error': 'Source already exists'})

@route('DELETE', r'/api/sources/([^/]+)')
def api_delete_source(self, params, groups):
    session = self._require_admin()
    if not session:
        return
    if not self._validate_csrf():
        self._send(403, {'error': 'Invalid security token'})
        return
    name = urllib.parse.unquote(groups[0])[:200]
    try:
        db.delete_source(name)
        self._send(200, {'ok': True})
    except Exception:
        self._send_error_safe(500)

# ===========================================================================
# Entry point
# ===========================================================================

def run(port: int = DEFAULT_PORT, host: str = '0.0.0.0', use_ssl: bool = False, certfile: str = None, keyfile: str = None):
    """Start the PIR Management Platform server.
    
    Args:
        port: Port to listen on (default: 8080)
        host: Interface address to bind to (default: 0.0.0.0 = all interfaces)
        use_ssl: Enable HTTPS (requires certfile and keyfile)
        certfile: Path to SSL certificate file
        keyfile: Path to SSL private key file
    """
    global _use_ssl
    _use_ssl = use_ssl
    db.init_db()
    db.cleanup_sessions()  # Initial cleanup
    db.start_cleanup_thread()  # Start background cleanup
    
    protocol = 'https' if use_ssl else 'http'
    print(f"[app] PIR Management Platform")
    print(f"[app] Listening on {protocol}://{host}:{port}")
    print(f"[app] Press Ctrl+C to stop")
    
    server = ThreadingHTTPServer((host, port), Handler)
    
    if use_ssl:
        if not certfile or not keyfile:
            print("[app] ERROR: SSL enabled but certfile/keyfile not provided")
            return
        try:
            import ssl
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile, keyfile)
            # Modern SSL/TLS settings
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            server.socket = context.wrap_socket(server.socket, server_side=True)
            print(f"[app] SSL/TLS enabled (cert: {certfile})")
        except Exception as e:
            print(f"[app] ERROR: Failed to enable SSL: {e}")
            return
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[app] Shutting down.")
        db.stop_cleanup_thread()
        server.shutdown()


if __name__ == '__main__':
    # Parse command line arguments
    port = DEFAULT_PORT
    host = '0.0.0.0'
    use_ssl = False
    certfile = None
    keyfile = None
    
    args = sys.argv[1:]
    if args and not args[0].startswith('--'):
        port = int(args[0])
    if '--host' in args:
        try:
            host = args[args.index('--host') + 1]
        except IndexError:
            print("Usage: python app.py [port] [--host address] [--ssl certfile keyfile]")
            sys.exit(1)
    if '--ssl' in args:
        use_ssl = True
        try:
            ssl_idx = args.index('--ssl')
            if len(args) > ssl_idx + 2:
                certfile = args[ssl_idx + 1]
                keyfile = args[ssl_idx + 2]
        except (ValueError, IndexError):
            print("Usage: python app.py [port] [--host address] [--ssl certfile keyfile]")
            sys.exit(1)
    
    run(port, host, use_ssl, certfile, keyfile)
