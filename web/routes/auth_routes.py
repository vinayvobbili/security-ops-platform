"""Authentication routes: register, verify email, login, password reset,
PAT management.

Scope: this auth system exists solely to gate CCR PAT issuance for the
`claude` CLI users. Other web edit paths keep whatever guard they already
had (e.g. the LOG_VIEWER_USERNAME/PASSWORD admin check) — don't reach for
@login_required to protect them.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from flask import (
    Blueprint, abort, flash, jsonify, redirect, render_template, request, session,
)

from web.auth import db, helpers, notifications, rbac, security
from web.extensions import limiter

log = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)


def _render_register(**overrides):
    """Render the signup page with a complete context.

    The template references signup form vars (``custom_role_key`` etc.) in an
    always-rendered <script>, so every render — including the ``ok=True``
    success page — must supply them or Jinja blows up on ``Undefined``. Funnel
    all four return paths through here so a partial context can't 500 again.
    """
    ctx = dict(
        error=None, ok=False, email='',
        selected_role='', custom_role='', access_reason='',
        public_roles=helpers.signup_role_choices(),
        custom_role_key=helpers.CUSTOM_ROLE_KEY,
        min_access_reason=helpers.MIN_ACCESS_REASON_LEN,
        min_password_len=security.MIN_PASSWORD_LEN,
        password_policy=security.PASSWORD_POLICY_TEXT,
    )
    ctx.update(overrides)
    return render_template('auth/register.html', **ctx)


def _send_email(to: str, subject: str, body: str, html_body: str | None = None) -> bool:
    """Wrapper around the project's XSOAR-routed sender. Returns False
    silently on failure so registration/reset paths don't surface SMTP
    internals to the user — they get a generic 'check your inbox' message."""
    try:
        from services.xsoar_email import send_email as _send
        _send(to=to, subject=subject, body=body, html_body=html_body)
        return True
    except Exception:
        log.exception('Failed to send auth email to %s', to)
        return False


def _verify_email_message(email: str, link: str) -> tuple[str, str]:
    text = (
        f'Hi,\n\nClick the link below to verify your account '
        f'({email}):\n\n{link}\n\n'
        f'This link expires in {helpers.email_verify_ttl_hours()} hours.\n\n'
        f'If you did not request this, you can ignore this email.\n'
    )
    html = f'''<html><body style="font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif; color:#222;">
<p>Hi,</p>
<p>Click the button below to verify your account (<b>{email}</b>):</p>
<p><a href="{link}" style="display:inline-block; padding:10px 18px; background:#2563eb; color:#fff; text-decoration:none; border-radius:6px;">Verify email</a></p>
<p style="color:#666; font-size:12px;">Or paste this URL: <a href="{link}">{link}</a></p>
<p style="color:#666; font-size:12px;">This link expires in {helpers.email_verify_ttl_hours()} hours. If you did not request this, ignore this email.</p>
</body></html>'''
    return text, html


def _reset_email_message(email: str, link: str) -> tuple[str, str]:
    text = (
        f'Hi,\n\nA password reset was requested for {email}. Click the link '
        f'below to choose a new password:\n\n{link}\n\n'
        f'This link expires in {helpers.password_reset_ttl_hours()} hour(s).\n\n'
        f'If you did not request this, you can ignore this email.\n'
    )
    html = f'''<html><body style="font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif; color:#222;">
<p>Hi,</p>
<p>A password reset was requested for <b>{email}</b>. Click the button below to choose a new password:</p>
<p><a href="{link}" style="display:inline-block; padding:10px 18px; background:#2563eb; color:#fff; text-decoration:none; border-radius:6px;">Reset password</a></p>
<p style="color:#666; font-size:12px;">Or paste this URL: <a href="{link}">{link}</a></p>
<p style="color:#666; font-size:12px;">Expires in {helpers.password_reset_ttl_hours()} hour(s). If you did not request this, ignore this email.</p>
</body></html>'''
    return text, html


# --- registration + email verification -------------------------------------

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return _render_register()

    email = (request.form.get('email') or '').strip().lower()
    password = request.form.get('password') or ''
    password2 = request.form.get('password2') or ''
    role = (request.form.get('role') or '').strip()
    custom_role = (request.form.get('custom_role') or '').strip()
    access_reason = (request.form.get('access_reason') or '').strip()
    effective_role = helpers.resolve_signup_role(role, custom_role)
    err = None
    if not helpers.is_company_email(email):
        err = 'Please use your the company email address.'
    elif effective_role is None:
        err = ('Please describe your role.' if role == helpers.CUSTOM_ROLE_KEY
               else 'Please choose a role.')
    elif len(access_reason) < helpers.MIN_ACCESS_REASON_LEN:
        err = (f'Please explain what you need access for '
               f'(at least {helpers.MIN_ACCESS_REASON_LEN} characters).')
    elif security.validate_password(password):
        err = security.validate_password(password)
    elif password != password2:
        err = 'Passwords do not match.'

    # Directory check: the address must resolve to a real AD account. This is
    # the authoritative gate (the live field check is just early UX). Fail
    # OPEN — if AD/XSOAR can't answer ("unknown"), let signup proceed (email
    # verification still gates sign-in) but flag it on the operator alert.
    ad_status = 'skipped'
    if not err:
        from services.active_directory import email_exists_in_ad
        ad_status = email_exists_in_ad(email)
        if ad_status == 'not_found':
            err = ("We couldn't find that address in the the company directory — "
                   "please double-check for typos.")

    if err:
        return _render_register(error=err, email=email, selected_role=role,
                                custom_role=custom_role, access_reason=access_reason)

    access_reason = access_reason[:helpers.MAX_ACCESS_REASON_LEN]

    existing = db.get_user_by_email(email)
    if existing:
        # Re-send the verification link instead of leaking that the account exists.
        if existing['email_verified_at'] is None:
            _issue_verify_link(existing['id'], email)
        return _render_register(ok=True, email=email)

    # Role assignment at signup:
    #  * admin (AUTH_ADMIN_EMAILS) — straight in as admin, overrides everything.
    #  * MANAGED role (capability-bearing) — needs operator approval. Grant the
    #    open default (`viewer`) now, keep the requested role as a pending hint,
    #    and ping the operator with a promote link. A user can never self-grant
    #    a capability, no matter how the role is submitted (dropdown or "Other").
    #  * OPEN role (zero-capability title) — self-serve, granted directly.
    is_admin_grant = helpers.is_admin_email(email)
    managed_request = (not is_admin_grant) and rbac.is_managed_role(effective_role)
    if is_admin_grant:
        stored_role = helpers.ADMIN_ROLE
    elif managed_request:
        stored_role = rbac.VIEWER_ROLE
    else:
        stored_role = effective_role
    user_id = db.create_user(
        email, security.hash_password(password), stored_role, access_reason,
        requested_role=effective_role,
    )
    _issue_verify_link(user_id, email)
    if managed_request:
        notifications.notify_managed_role_request(
            user_email=email, requested_role=effective_role,
            access_reason=access_reason, client_ip=_client_ip(), ad_status=ad_status,
        )
    else:
        role_label = 'Admin' if is_admin_grant else next(
            (lbl for k, lbl in helpers.PUBLIC_ROLES if k == effective_role), effective_role)
        notifications.notify_new_signup(
            user_email=email, role_label=role_label, access_reason=access_reason,
            client_ip=_client_ip(), is_admin=is_admin_grant, ad_status=ad_status,
        )
    return _render_register(ok=True, email=email)


@auth_bp.route('/register/check-email', methods=['POST'])
@limiter.limit('12 per minute; 60 per hour')
def check_email():
    """Live directory check for the signup form — lets the user catch a
    fat-fingered address before submitting. Rate-limited (and company-domain
    gated) to blunt AD enumeration; it only ever reveals found/not-found, no
    account details. The authoritative check still runs server-side in
    register(); this is UX only.
    """
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    if not helpers.is_company_email(email):
        return jsonify({'status': 'invalid',
                        'message': 'Use your the company email address.'})

    from services.active_directory import email_exists_in_ad
    status = email_exists_in_ad(email)
    if status == 'found':
        msg = ''
    elif status == 'not_found':
        msg = "We couldn't find that address in the the company directory — check for typos."
    else:  # unknown — directory unreachable; don't block, don't alarm
        msg = ''
    return jsonify({'status': status, 'message': msg})


def _client_ip() -> str:
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or ''


def _issue_verify_link(user_id: int, email: str) -> None:
    token = security.new_token(security.EMAIL_VERIFY_PREFIX)
    expires_at = int(time.time()) + helpers.email_verify_ttl_hours() * 3600
    db.insert_email_verify_token(user_id, security.hash_token(token), expires_at)
    link = helpers.verify_email_url(token)
    text, html = _verify_email_message(email, link)
    _send_email(email, 'Verify your account', text, html_body=html)


@auth_bp.route('/verify-email')
def verify_email():
    token = (request.args.get('token') or '').strip()
    if not token:
        return render_template('auth/verify_email.html', ok=False, message='Missing token.'), 400
    user_id = db.consume_email_verify_token(security.hash_token(token))
    if not user_id:
        return render_template('auth/verify_email.html', ok=False,
                               message='This link is invalid or has expired.'), 400
    db.mark_email_verified(user_id)
    session.clear()
    session['user_id'] = user_id
    session.permanent = True
    return render_template('auth/verify_email.html', ok=True,
                           message='Your email is verified. You are now signed in.')


# --- login / logout --------------------------------------------------------

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    next_url = request.args.get('next') or request.form.get('next') or '/all-pages'
    if request.method == 'GET':
        return render_template('auth/login.html', error=None, next=next_url)

    email = (request.form.get('email') or '').strip().lower()
    password = request.form.get('password') or ''
    user = db.get_user_by_email(email)
    if (not user or not security.verify_password(password, user['password_hash'])
            or user['email_verified_at'] is None):
        return render_template('auth/login.html',
                               error='Invalid email/password or email not verified.',
                               next=next_url), 401
    session.clear()
    session['user_id'] = user['id']
    session.permanent = True
    return redirect(next_url)


@auth_bp.route('/logout', methods=['POST', 'GET'])
def logout():
    session.clear()
    return redirect('/login')


# --- password reset --------------------------------------------------------

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        return render_template('auth/forgot_password.html', ok=False, error=None)
    email = (request.form.get('email') or '').strip().lower()
    if not helpers.is_company_email(email):
        return render_template('auth/forgot_password.html', ok=False,
                               error='Please use your the company email address.')
    user = db.get_user_by_email(email)
    if user and user['email_verified_at'] is not None:
        token = security.new_token(security.PASSWORD_RESET_PREFIX)
        expires_at = int(time.time()) + helpers.password_reset_ttl_hours() * 3600
        db.insert_password_reset_token(user['id'], security.hash_token(token), expires_at)
        link = helpers.password_reset_url(token)
        text, html = _reset_email_message(email, link)
        _send_email(email, 'Reset your password', text, html_body=html)
    # Always show the same message — don't leak whether the email exists.
    return render_template('auth/forgot_password.html', ok=True, error=None)


@auth_bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    token = (request.args.get('token') or request.form.get('token') or '').strip()

    def _render(**kw):
        ctx = dict(token=token, error=None, ok=False,
                   min_password_len=security.MIN_PASSWORD_LEN,
                   password_policy=security.PASSWORD_POLICY_TEXT)
        ctx.update(kw)
        return render_template('auth/reset_password.html', **ctx)

    if request.method == 'GET':
        return _render()
    password = request.form.get('password') or ''
    password2 = request.form.get('password2') or ''
    pw_err = security.validate_password(password)
    if pw_err:
        return _render(error=pw_err)
    if password != password2:
        return _render(error='Passwords do not match.')
    user_id = db.consume_password_reset_token(security.hash_token(token))
    if not user_id:
        return _render(error='Reset link is invalid or has expired.'), 400
    db.update_password_hash(user_id, security.hash_password(password))
    session.clear()
    session['user_id'] = user_id
    session.permanent = True
    return _render(ok=True)


# --- account / PATs --------------------------------------------------------

def _pat_to_view(row) -> dict:
    return {
        'id': row['id'],
        'name': row['name'],
        'token': row['token_plaintext'] or '',  # NULL for legacy rows minted before plaintext column
        'created_at': datetime.fromtimestamp(row['created_at'], tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
        'expires_at': datetime.fromtimestamp(row['expires_at'], tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
        'last_used_at': (datetime.fromtimestamp(row['last_used_at'], tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
                         if row['last_used_at'] else ''),
        'revoked': row['revoked_at'] is not None,
        'expired': row['expires_at'] < int(time.time()),
    }


@auth_bp.route('/account')
@helpers.login_required
def account():
    user = request.user  # type: ignore[attr-defined]
    pats = [_pat_to_view(r) for r in db.list_pats(user['id'])]
    return render_template('auth/account.html', user=user, pats=pats,
                           pat_ttl_days=helpers.pat_ttl_days(),
                           public_roles=helpers.signup_role_choices(),
                           custom_role_key=helpers.CUSTOM_ROLE_KEY,
                           min_password_len=security.MIN_PASSWORD_LEN,
                           password_policy=security.PASSWORD_POLICY_TEXT,
                           role_saved=request.args.get('saved') == 'role')


@auth_bp.route('/account/role', methods=['POST'])
@helpers.login_required
def update_role():
    """Let a signed-in user update their *requested* role.

    This is a non-binding hint only — it does NOT change the user's
    effective (capability-bearing) role, which is admin-assigned on
    /admin-users. Capabilities can never be self-granted. Admins are
    excluded entirely (their grant is server-side via AUTH_ADMIN_EMAILS and
    editing it here would be meaningless). A brand-new role typed into the
    "Other" box is stored verbatim and, like at signup, becomes a dropdown
    option for everyone else."""
    user = request.user  # type: ignore[attr-defined]
    if user.get('role') == helpers.ADMIN_ROLE:
        abort(403)
    role = (request.form.get('role') or '').strip()
    custom_role = (request.form.get('custom_role') or '').strip()
    new_role = helpers.resolve_signup_role(role, custom_role)
    if new_role:
        db.set_user_requested_role(user['id'], new_role)
    return redirect('/account?saved=role')


@auth_bp.route('/account/pats', methods=['POST'])
@helpers.login_required
def create_pat():
    user = request.user  # type: ignore[attr-defined]
    name = (request.form.get('name') or '').strip()[:80]
    if not name:
        # Auto-name when the user just clicks "Generate PAT" with no label.
        from zoneinfo import ZoneInfo
        name = datetime.now(tz=ZoneInfo('America/New_York')).strftime(
            'Token %m/%d/%Y %I:%M %p %Z')
    token = security.new_token(security.PAT_PREFIX)
    expires_at = int(time.time()) + helpers.pat_ttl_days() * 86400
    db.insert_pat(user['id'], name, security.hash_token(token), token, expires_at)
    notifications.notify_pat_created(
        user_email=user['email'], pat_name=name, client_ip=_client_ip(),
    )
    return redirect('/account')


@auth_bp.route('/account/pats/<int:pat_id>/revoke', methods=['POST'])
@helpers.login_required
def revoke_pat(pat_id: int):
    user = request.user  # type: ignore[attr-defined]
    db.revoke_pat(user['id'], pat_id)
    return redirect('/account')


@auth_bp.route('/account/password', methods=['POST'])
@helpers.login_required
def change_password():
    """Self-service password change for the signed-in user. Re-authenticates
    with the current password before setting the new one (so a walk-up on an
    unlocked session can't silently take over the account). The existing
    /forgot-password email flow stays the path for users who've forgotten it."""
    user = request.user  # type: ignore[attr-defined]
    row = db.get_user_by_id(user['id'])
    current = request.form.get('current_password') or ''
    new = request.form.get('new_password') or ''
    new2 = request.form.get('new_password2') or ''

    pw_err = security.validate_password(new)
    if not row or not security.verify_password(current, row['password_hash']):
        flash('Current password is incorrect.', 'pw_error')
    elif pw_err:
        flash(pw_err, 'pw_error')
    elif new != new2:
        flash('New passwords do not match.', 'pw_error')
    elif security.verify_password(new, row['password_hash']):
        flash('New password must be different from your current one.', 'pw_error')
    else:
        db.update_password_hash(user['id'], security.hash_password(new))
        log.info('Password changed for user %s', user['email'])
        flash('Password changed.', 'pw_ok')
    return redirect('/account#password')


# --- admin -----------------------------------------------------------------

@auth_bp.route('/admin-users')
@helpers.admin_required
def admin_users():
    """List every registered user with their PAT status. Admin-only."""
    from zoneinfo import ZoneInfo
    eastern = ZoneInfo('America/New_York')
    fmt = '%m/%d/%Y %I:%M %p %Z'

    def _eastern(ts):
        if not ts:
            return ''
        return datetime.fromtimestamp(ts, tz=eastern).strftime(fmt)

    rows = db.list_users_with_pat_summary()
    role_labels = dict(helpers.PUBLIC_ROLES)
    role_labels[helpers.ADMIN_ROLE] = 'Admin'
    role_labels[rbac.VIEWER_ROLE] = 'Viewer (no actions)'

    def _label(role):
        return role_labels.get(role, role or '—')

    view = []
    pending_count = 0
    for r in rows:
        env_admin = helpers.is_admin_email(r['email'])
        role_caps = rbac.capabilities_for_role(r['role'])
        extra_caps = rbac.parse_capabilities(r['extra_capabilities'])
        caps = rbac.user_capabilities(
            {'email': r['email'], 'role': r['role'],
             'extra_capabilities': r['extra_capabilities']})
        # A "pending approval" is a signup that asked for a MANAGED (capability-
        # bearing) role but was parked at the open default — it's waiting for an
        # admin to promote it. role_differs (any mismatch) is broader; this is
        # the subset that actually needs an approval decision.
        req_role = r['requested_role']
        pending_managed = (not env_admin and bool(req_role)
                           and req_role != r['role']
                           and rbac.is_managed_role(req_role))
        if pending_managed:
            pending_count += 1
        view.append({
            'id': r['id'],
            'email': r['email'],
            'role': r['role'] or '',
            'role_label': _label(r['role']),
            'requested_role': req_role or '',
            'requested_role_label': _label(req_role) if req_role else '',
            'role_differs': bool(req_role) and req_role != r['role'],
            'pending_managed': pending_managed,
            'capabilities': sorted(caps),
            'role_caps': sorted(role_caps),
            'extra_caps': sorted(extra_caps),
            'access_reason': r['access_reason'],
            'exclude_from_traffic_log': r['exclude_from_traffic_log'],
            'is_admin': r['role'] == helpers.ADMIN_ROLE,
            'env_admin': env_admin,  # locked: role driven by AUTH_ADMIN_EMAILS
            'email_verified': r['email_verified'],
            'created_at': _eastern(r['created_at']),
            'total_pats': r['total_pats'],
            'active_pats': r['active_pats'],
            'last_pat_used_at': _eastern(r['last_pat_used_at']),
            'last_pat_created_at': _eastern(r['last_pat_created_at']),
        })
    # Roles an admin can assign, in order of increasing privilege. Custom
    # free-text roles already in use are appended so they can be re-assigned;
    # they carry no capabilities until added to the rbac matrix.
    assignable = [(rbac.VIEWER_ROLE, _label(rbac.VIEWER_ROLE))]
    assignable += list(helpers.PUBLIC_ROLES)
    assignable += helpers.custom_signup_roles()
    assignable += [(helpers.ADMIN_ROLE, 'Admin (all capabilities)')]
    # Float pending managed-role approvals to the top so they can't be missed.
    view.sort(key=lambda u: (not u['pending_managed'], u['email'].lower()))
    return render_template(
        'auth/admin_users.html', users=view,
        pending_count=pending_count,
        assignable_roles=assignable,
        capability_descriptions=rbac.CAPABILITIES,
        all_capabilities=sorted(rbac.ALL_CAPABILITIES),
        role_capabilities={k: sorted(v) for k, v in rbac.ROLE_CAPABILITIES.items()},
    )


@auth_bp.route('/admin-users/<int:user_id>/capability', methods=['POST'])
@helpers.admin_required
def set_user_capability(user_id: int):
    """Grant or revoke a single per-user capability (on top of the role).
    Admin-only. The grant path for sensitive caps (e.g. data.destructive)
    that no default role confers — give one person access on request without
    a role change or admin promotion. Env-admins already have everything."""
    target = db.get_user_by_id(user_id)
    if not target:
        abort(404)
    if helpers.is_admin_email(target['email']):
        flash('That account already has every capability (permanent admin).')
        return redirect('/admin-users')

    cap = (request.form.get('capability') or '').strip()
    action = (request.form.get('action') or '').strip()
    if cap not in rbac.ALL_CAPABILITIES:
        flash('Unknown capability.')
        return redirect('/admin-users')

    current = set(rbac.parse_capabilities(target['extra_capabilities']))
    if action == 'grant':
        current.add(cap)
    elif action == 'revoke':
        current.discard(cap)
    else:
        flash('Unknown action.')
        return redirect('/admin-users')

    db.set_user_extra_capabilities(user_id, ','.join(sorted(current)))
    acting = request.user  # type: ignore[attr-defined]
    log.info('[RBAC] capability %s by %s: user=%s cap=%s (extra now: %s)',
             action, acting['email'], target['email'], cap,
             ', '.join(sorted(current)) or 'none')
    flash(f"{action.capitalize()}ed {cap} for {target['email']}.")
    return redirect('/admin-users')


@auth_bp.route('/admin-users/<int:user_id>/role', methods=['POST'])
@helpers.admin_required
def set_user_role(user_id: int):
    """Assign a user's effective (capability-bearing) role. Admin-only.

    Roles tied to AUTH_ADMIN_EMAILS are immutable from here — their
    admin grant is environment-driven, so a DB edit would be overridden on
    their next signup/login path and only causes confusion. An admin also
    cannot change their *own* role (no self-demotion footgun)."""
    target = db.get_user_by_id(user_id)
    if not target:
        abort(404)
    if helpers.is_admin_email(target['email']):
        flash('That account is a permanent admin (set via AUTH_ADMIN_EMAILS) — its role is locked.')
        return redirect('/admin-users')
    acting = request.user  # type: ignore[attr-defined]
    if acting['id'] == user_id:
        flash("You can't change your own role.")
        return redirect('/admin-users')

    new_role = (request.form.get('role') or '').strip()
    valid = ({rbac.VIEWER_ROLE, helpers.ADMIN_ROLE}
             | helpers.public_role_keys()
             | {k for k, _ in helpers.custom_signup_roles()})
    if new_role not in valid:
        flash('Unknown role.')
        return redirect('/admin-users')

    db.set_user_role(user_id, new_role)
    caps = sorted(rbac.capabilities_for_role(new_role))
    log.info('[RBAC] role change by %s: user=%s -> %s (caps: %s)',
             acting['email'], target['email'], new_role, ', '.join(caps) or 'none')
    flash(f"Set {target['email']} to {new_role}.")
    return redirect('/admin-users')


@auth_bp.route('/admin-users/<int:user_id>/traffic-log', methods=['POST'])
@helpers.admin_required
def set_traffic_log_exclude(user_id: int):
    """Toggle whether a user's web traffic is recorded in the activity log.
    Excluded users generate no activity rows on any network (auth-identity
    based, not IP)."""
    exclude = request.form.get('exclude') == '1'
    db.set_user_traffic_log_exclude(user_id, exclude)
    return redirect('/admin-users')
