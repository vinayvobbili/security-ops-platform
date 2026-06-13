"""Decorators and helpers that the rest of the web app uses."""
from __future__ import annotations

import os
from functools import wraps
from typing import Callable, Optional
from urllib.parse import quote

from flask import abort, jsonify, redirect, request, session

from . import db, security


def allowed_domains() -> list[str]:
    raw = os.environ.get('COMPANY_DOMAINS', 'the-company.com')
    return [d.strip().lower().lstrip('@') for d in raw.split(',') if d.strip()]


def is_company_email(email: str) -> bool:
    email = (email or '').strip().lower()
    if '@' not in email:
        return False
    domain = email.rsplit('@', 1)[-1]
    return domain in allowed_domains()


# Roles exposed to anyone signing up via /register. The admin role is
# intentionally not in this list — it's granted server-side based on
# AUTH_ADMIN_EMAILS, never picked from the form.
PUBLIC_ROLES: list[tuple[str, str]] = [
    ('secops_analyst',       'SecOps Analyst'),
    ('response_engineer',    'Response Engineer'),
    ('detection_engineer',   'Detection Engineer'),
    ('ai_project_submitter', 'AI Project Submitter'),
]
ADMIN_ROLE = 'admin'

# Dropdown sentinel: when the preset roles don't fit, the user picks this and
# types their own role in the revealed text box. Stored verbatim (capped),
# never matched against PUBLIC_ROLES.
CUSTOM_ROLE_KEY = '__other__'
MAX_CUSTOM_ROLE_LEN = 60

# Mandatory free-text justification collected at signup.
MIN_ACCESS_REASON_LEN = 20
MAX_ACCESS_REASON_LEN = 1000


def public_role_keys() -> set[str]:
    return {k for k, _ in PUBLIC_ROLES}


def is_valid_public_role(role: str) -> bool:
    return role in public_role_keys()


def custom_signup_roles() -> list[tuple[str, str]]:
    """Roles a previous registrant entered via "Other", surfaced on the
    dropdown so the next person can pick one instead of re-typing it.

    Derived from stored user roles (verified accounts only) minus the
    presets and the server-only admin role. Custom roles are stored
    verbatim, so key == label. Deduped case-insensitively to avoid near
    duplicates like "Threat Intel Lead" / "threat intel lead"."""
    from . import rbac  # lazy: rbac imports helpers, avoid a circular import at load
    reserved = public_role_keys() | {ADMIN_ROLE}
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for role in db.distinct_assigned_roles():
        if role in reserved or role.lower() in seen:
            continue
        # A capability-bearing role (e.g. "Customer Assurance Analyst") is
        # admin-assign-only — never advertise it as a self-select signup option,
        # even though picking it would only set a non-binding requested_role.
        if rbac.capabilities_for_role(role):
            continue
        seen.add(role.lower())
        out.append((role, role))
    return out


def signup_role_choices() -> list[tuple[str, str]]:
    """Full (key, label) list for the signup dropdown: the fixed presets
    followed by any custom roles earlier registrants contributed."""
    return PUBLIC_ROLES + custom_signup_roles()


def resolve_signup_role(role: str, custom_role: str) -> Optional[str]:
    """Map the submitted (role, custom_role) pair to the value to store, or
    None if the selection is invalid.

    A preset selection must be one of PUBLIC_ROLES; a previously
    contributed custom role (now offered in the dropdown) is accepted as
    well. The CUSTOM_ROLE_KEY sentinel requires a non-empty custom_role,
    which is stripped, capped, and returned verbatim — and, being stored
    on the new user, becomes a dropdown option for the next registrant."""
    role = (role or '').strip()
    if role == CUSTOM_ROLE_KEY:
        return (custom_role or '').strip()[:MAX_CUSTOM_ROLE_LEN] or None
    if is_valid_public_role(role):
        return role
    if role and role in {k for k, _ in custom_signup_roles()}:
        return role
    return None


def admin_emails() -> set[str]:
    raw = os.environ.get('AUTH_ADMIN_EMAILS', '')
    return {e.strip().lower() for e in raw.split(',') if e.strip()}


def is_admin_email(email: str) -> bool:
    return (email or '').strip().lower() in admin_emails()


def current_user():
    """Return the dict {id, email, role, exclude_from_traffic_log} for the
    logged-in browser user, or None. `role` may be None for legacy accounts
    that pre-date the role column."""
    user_id = session.get('user_id')
    if not user_id:
        return None
    row = db.get_user_by_id(user_id)
    if not row or row['email_verified_at'] is None:
        session.pop('user_id', None)
        return None
    return {
        'id': row['id'],
        'email': row['email'],
        'role': _row_role(row),
        'extra_capabilities': _row_extra_caps(row),
        'exclude_from_traffic_log': _row_traffic_exclude(row),
    }


def _row_extra_caps(row) -> Optional[str]:
    """Per-user capability grants (comma-separated). Absent on DBs that
    pre-date the migration → None (no extra grants)."""
    try:
        return row['extra_capabilities']
    except (IndexError, KeyError):
        return None


def _row_role(row) -> Optional[str]:
    try:
        return row['role']
    except (IndexError, KeyError):
        return None


def _row_traffic_exclude(row) -> bool:
    """Defensive read — the column is absent on DBs that pre-date the
    migration, in which case the user is treated as logged (False)."""
    try:
        return bool(row['exclude_from_traffic_log'])
    except (IndexError, KeyError):
        return False


def current_pat_user():
    """Return the dict {id, email, pat_name} for a valid Authorization
    bearer token, or None."""
    auth = request.headers.get('Authorization', '')
    if not auth.lower().startswith('bearer '):
        return None
    token = auth.split(None, 1)[1].strip()
    if not token:
        return None
    row = db.lookup_pat(security.hash_token(token))
    if not row:
        return None
    if row['email_verified_at'] is None:
        return None
    return {'id': row['user_id'], 'email': row['email'], 'pat_name': row['name']}


def is_admin() -> bool:
    """True iff the current request is from a signed-in user with role=admin.
    Returns False for anonymous users — callers decide whether to 401 or 403."""
    user = current_user()
    return bool(user and user.get('role') == ADMIN_ROLE)


def login_required(view: Callable):
    """Gate the /account PAT-management pages. Scoped to CCR PAT issuance;
    do not slap this onto unrelated edit paths.
    JSON requests get a 401; everything else gets a redirect to /login."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = current_user()
        if user:
            request.user = user  # type: ignore[attr-defined]
            return view(*args, **kwargs)
        if request.is_json or request.accept_mimetypes.best == 'application/json':
            return jsonify({'success': False, 'error': 'login_required'}), 401
        return redirect(f'/login?next={quote(request.full_path)}')
    return wrapper


def admin_required(view: Callable):
    """Gate admin-only pages. Same redirect-to-login behavior as
    login_required for anonymous users; a logged-in non-admin gets a
    flat 403 so it's clear the page exists but is off-limits."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            if request.is_json or request.accept_mimetypes.best == 'application/json':
                return jsonify({'success': False, 'error': 'login_required'}), 401
            return redirect(f'/login?next={quote(request.full_path)}')
        if user.get('role') != ADMIN_ROLE:
            abort(403)
        request.user = user  # type: ignore[attr-defined]
        return view(*args, **kwargs)
    return wrapper


def pat_required(view: Callable):
    """Reserved for the CCR shim's Bearer-PAT path.
    Not currently used as a decorator — the shim consumes PATs directly
    against `web.auth.db` / `security` rather than going through Flask."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = current_pat_user()
        if not user:
            return jsonify({'success': False, 'error': 'pat_required'}), 401
        request.pat_user = user  # type: ignore[attr-defined]
        return view(*args, **kwargs)
    return wrapper


def verify_email_url(token: str) -> str:
    base = (os.environ.get('WEB_SERVER_BASE_URL') or 'http://gdnr.the-company.com').rstrip('/')
    return f'{base}/verify-email?token={quote(token)}'


def password_reset_url(token: str) -> str:
    base = (os.environ.get('WEB_SERVER_BASE_URL') or 'http://gdnr.the-company.com').rstrip('/')
    return f'{base}/reset-password?token={quote(token)}'


def pat_ttl_days() -> int:
    try:
        return int(os.environ.get('AUTH_PAT_TTL_DAYS', '30'))
    except ValueError:
        return 30


def email_verify_ttl_hours() -> int:
    try:
        return int(os.environ.get('AUTH_EMAIL_VERIFY_TTL_HOURS', '24'))
    except ValueError:
        return 24


def password_reset_ttl_hours() -> int:
    try:
        return int(os.environ.get('AUTH_PASSWORD_RESET_TTL_HOURS', '1'))
    except ValueError:
        return 1
