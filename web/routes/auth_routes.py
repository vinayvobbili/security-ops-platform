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
    Blueprint, flash, jsonify, redirect, render_template, request, session, url_for,
)

from web.auth import db, helpers, notifications, security

log = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)


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
        return render_template('auth/register.html', error=None, ok=False,
                               public_roles=helpers.PUBLIC_ROLES, selected_role='')

    email = (request.form.get('email') or '').strip().lower()
    password = request.form.get('password') or ''
    password2 = request.form.get('password2') or ''
    role = (request.form.get('role') or '').strip()
    err = None
    if not helpers.is_company_email(email):
        err = 'Please use your the company email address.'
    elif not helpers.is_valid_public_role(role):
        err = 'Please choose a role.'
    elif len(password) < security.MIN_PASSWORD_LEN:
        err = f'Password must be at least {security.MIN_PASSWORD_LEN} characters.'
    elif password != password2:
        err = 'Passwords do not match.'

    if err:
        return render_template('auth/register.html', error=err, ok=False,
                               email=email, selected_role=role, public_roles=helpers.PUBLIC_ROLES)

    existing = db.get_user_by_email(email)
    if existing:
        # Re-send the verification link instead of leaking that the account exists.
        if existing['email_verified_at'] is None:
            _issue_verify_link(existing['id'], email)
        return render_template('auth/register.html', error=None, ok=True, email=email)

    # AUTH_ADMIN_EMAILS overrides the form choice — operators can't grant
    # themselves admin by changing the dropdown, and the dropdown itself
    # never offers admin.
    is_admin_grant = helpers.is_admin_email(email)
    effective_role = helpers.ADMIN_ROLE if is_admin_grant else role
    user_id = db.create_user(email, security.hash_password(password), effective_role)
    _issue_verify_link(user_id, email)
    role_label = 'Admin' if is_admin_grant else next(
        (lbl for k, lbl in helpers.PUBLIC_ROLES if k == role), role)
    notifications.notify_new_signup(
        user_email=email, role_label=role_label,
        client_ip=_client_ip(), is_admin=is_admin_grant,
    )
    return render_template('auth/register.html', error=None, ok=True, email=email)


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
    next_url = request.args.get('next') or request.form.get('next') or '/account'
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
    if request.method == 'GET':
        return render_template('auth/reset_password.html', token=token, error=None, ok=False)
    password = request.form.get('password') or ''
    password2 = request.form.get('password2') or ''
    if len(password) < security.MIN_PASSWORD_LEN:
        return render_template('auth/reset_password.html', token=token, ok=False,
                               error=f'Password must be at least {security.MIN_PASSWORD_LEN} characters.')
    if password != password2:
        return render_template('auth/reset_password.html', token=token, ok=False,
                               error='Passwords do not match.')
    user_id = db.consume_password_reset_token(security.hash_token(token))
    if not user_id:
        return render_template('auth/reset_password.html', token=token, ok=False,
                               error='Reset link is invalid or has expired.'), 400
    db.update_password_hash(user_id, security.hash_password(password))
    session.clear()
    session['user_id'] = user_id
    session.permanent = True
    return render_template('auth/reset_password.html', token=token, ok=True, error=None)


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
                           pat_ttl_days=helpers.pat_ttl_days())


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
    view = []
    for r in rows:
        view.append({
            'id': r['id'],
            'email': r['email'],
            'role_label': role_labels.get(r['role'], r['role'] or '—'),
            'is_admin': r['role'] == helpers.ADMIN_ROLE,
            'email_verified': r['email_verified'],
            'created_at': _eastern(r['created_at']),
            'total_pats': r['total_pats'],
            'active_pats': r['active_pats'],
            'last_pat_used_at': _eastern(r['last_pat_used_at']),
            'last_pat_created_at': _eastern(r['last_pat_created_at']),
        })
    return render_template('auth/admin_users.html', users=view)
