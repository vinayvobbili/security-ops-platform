"""Role-based capability gating for sensitive web actions.

The threat model here is the *authenticated insider*: every account is a
verified employee, so plain `@login_required` does nothing to stop someone
from deploying a sidecar, firing an external notification, or deleting
data. This module maps roles to a small set of **capabilities** and gives
us a decorator that gates the dangerous endpoints on them.

Design (see the RBAC decisions doc / commit message):
  * **Views stay open.** Any logged-in user can read any dashboard. Only
    state-changing, high-blast-radius *actions* are gated — the three
    surfaces in CAPABILITIES below.
  * **Capabilities attach to roles; roles are admin-assigned.** `admin`
    comes from AUTH_ADMIN_EMAILS; every other role is set by an admin on
    the /admin-users page. The role a user picks at signup is only a
    non-binding *requested* hint — a user can never self-grant a capability.
  * **The env-var admin is unlockable-outable.** Anyone in AUTH_ADMIN_EMAILS
    always resolves to every capability even if their stored DB role drifts,
    so the operator can never accidentally fence themselves out.

To change who can do what, edit ROLE_CAPABILITIES — it is the single source
of truth.
"""
from __future__ import annotations

import logging
from functools import wraps
from urllib.parse import quote

from flask import jsonify, redirect, render_template, request

from . import helpers

log = logging.getLogger(__name__)

# --- capabilities ----------------------------------------------------------
# Keep this set SMALL and tied to the real havoc surfaces. Each constant is
# the token used both in @require_capability(...) and in the matrix below.
DEPLOY_SIDECAR = 'deploy.sidecar'        # build / activate / roll back / delete a live sidecar container
SEND_EXTERNAL = 'send.external'          # email · Teams · Webex · open a GitLab MR · create a ticket
DATA_DESTRUCTIVE = 'data.destructive'    # delete · reset · clear persistent data
RUN_BAS = 'run.bas'                      # fire a live AttackIQ breach-and-attack scenario at a real asset
ENFORCE_BLOCK = 'enforce.block'          # block/unblock a URL or domain (URL block, the corporate proxy blocklist) via Sleuth
CA_MANAGE = 'ca.manage'                  # draft/approve/edit answers + manage the KB on Customer Assurance
MANAGE_SILENCER = 'manage.silencer'      # create / activate / deactivate a Ticket Cannon Silencer or Noise Suppressor
RUN_DRYRUN = 'run.dryrun'                # fire a live XSIAM XQL dry-run (burns Cortex compute units)
MANAGE_DOMAIN_MONITORING_WATCHLIST = 'manage.domain_monitoring_watchlist'  # add / remove domains on the Domain Monitoring lists
RUN_RTR = 'run.rtr'                      # run an ad-hoc command on a live endpoint via CrowdStrike RTR (arbitrary on-host execution)

# Human-readable descriptions, surfaced on the 403 page and the admin UI.
CAPABILITIES: dict[str, str] = {
    DEPLOY_SIDECAR: 'Deploy, activate, roll back, or delete a vendor sidecar container',
    SEND_EXTERNAL: 'Send out of the platform — email, Teams/Webex, open a merge request, or create a ticket',
    DATA_DESTRUCTIVE: 'Delete, reset, or clear stored data',
    RUN_BAS: 'Execute a live AttackIQ breach-and-attack scenario against a real asset',
    ENFORCE_BLOCK: 'Block or unblock a URL/domain (URL block, the corporate proxy blocklist) from the Sleuth bot',
    CA_MANAGE: 'Draft, approve, edit, and export answers and manage the knowledge base on Customer Assurance',
    MANAGE_SILENCER: 'Create or toggle a Ticket Cannon Silencer / Noise Suppressor (auto-closes matching tickets)',
    RUN_DRYRUN: 'Run a live XSIAM XQL dry-run on the Detection-as-Code pipeline (consumes Cortex compute units)',
    MANAGE_DOMAIN_MONITORING_WATCHLIST: 'Add or remove domains on the Domain Monitoring monitored list and RF watchlist',
    RUN_RTR: 'Run an ad-hoc command on a live endpoint via CrowdStrike RTR (traceroute, ipconfig, etc.)',
}

ALL_CAPABILITIES: frozenset[str] = frozenset(CAPABILITIES)

# Default role for brand-new accounts: view + benign actions only, no
# capabilities. Elevation off this is an explicit admin action.
VIEWER_ROLE = 'viewer'

# --- role -> capability matrix ---------------------------------------------
# THE source of truth for what a ROLE confers. Roles not listed (including
# `viewer` and any custom free-text role) get NO capabilities. `admin` is
# special-cased to the full set in capabilities_for_role() and need not appear.
#
# data.destructive, run.bas, enforce.block, and run.rtr are intentionally NOT in
# any default role — deleting/resetting stored data, firing live BAS, blocking
# URLs/domains, and running an ad-hoc command on a live endpoint via CrowdStrike
# RTR are admin-only by default (these also gate the matching destructive Sleuth
# bot tools; see my_bot/auth/sleuth_rbac.py). run.rtr is the highest blast radius
# of the set (arbitrary on-host execution) and is kept admin-only — grant it to an
# individual only on deliberate request via a per-user grant (users.extra_capabilities
# / the /admin-users capability toggle), no role change or admin promotion needed.
#
# 'Customer Assurance Analyst' is a title-case key on purpose: it's a custom,
# admin-assigned role (held by the CA team), so the stored role string IS the
# display label. It carries ca.manage so only the CA team (and admin) can
# draft/approve/edit answers and manage the KB on /customer-assurance. It is
# NOT in PUBLIC_ROLES and, being capability-bearing, is hidden from the signup
# dropdown — a random signup can never self-assume it (their binding role is
# always `viewer`; their pick is only a non-binding requested_role hint).
ROLE_CAPABILITIES: dict[str, frozenset[str]] = {
    'response_engineer':         frozenset({SEND_EXTERNAL, MANAGE_SILENCER, MANAGE_DOMAIN_MONITORING_WATCHLIST}),
    'detection_engineer':        frozenset({DEPLOY_SIDECAR, SEND_EXTERNAL, RUN_DRYRUN}),
    'secops_analyst':            frozenset({MANAGE_SILENCER, MANAGE_DOMAIN_MONITORING_WATCHLIST}),
    'ai_project_submitter':      frozenset(),
    'Customer Assurance Analyst': frozenset({CA_MANAGE}),
    VIEWER_ROLE:                 frozenset(),
}


# Known vendor sidecars: deploy-portal key -> human label. This is the catalog
# the /admin-users ownership editor renders and the allowlist of keys an admin
# may assign an owner to. Keep it in sync with the ``sidecar='<key>'`` args on
# the @require_capability decorators in each sidecar route module.
SIDECAR_CATALOG: dict[str, str] = {
    'aj_threat_hunting':   'AJ Threat Hunting',
    'ai_drt':              'AI DRT',
    'cyber_simulator':     'Cyber Simulator',
    'db_config':           'Database Config',
    'db_security':         'Database Security',
    'dspm':                'DSPM',
    'exposed_api_scanner': 'Exposed API Scanner',
    'snr':                 'Signal to Noise (SNR)',
    'tipper_automation':   'Tipper Automation',
    'zero_hour':           'Zero Hour',
}

# Per-sidecar owners — BOOTSTRAP SEED ONLY. The live source of truth is the
# DB-backed ``sidecar_owners`` table (admin-editable on /admin-users, no deploy
# needed). This dict is used exactly once: to populate that table the first time
# the schema is created (see web/auth/db._seed_sidecar_owners). After that,
# edits happen in the DB; changing this dict will NOT affect an existing
# deployment. New installs bootstrap from here, so keep it roughly current.
#
# A listed email may deploy / activate / roll back / delete THAT sidecar (and
# only that one) without holding the global ``deploy.sidecar`` capability, on the
# principle that the vendor who owns a box should be able to ship it anytime.
# Ownership only ever ADDS access; engineers/admins with the global capability
# are unaffected. Owners must be registered, verified users (the email is
# matched against the logged-in account).
SIDECAR_OWNERS_SEED: dict[str, tuple[str, ...]] = {
    'aj_threat_hunting':   ('<redacted-email>',),
    'ai_drt':              ('<redacted-email>',),
    'dspm':                ('<redacted-email>',),
    'db_config':           ('<redacted-email>',),
    'db_security':         ('<redacted-email>',),
    'exposed_api_scanner': ('<redacted-email>',),
    'snr':                 ('<redacted-email>',),
}


def sidecar_owners(key: str) -> tuple[str, ...]:
    """Owner emails for a sidecar key (empty tuple if none).

    Reads the DB-backed ``sidecar_owners`` table — the live, admin-editable
    source of truth. Falls back to the in-code seed only if the DB read fails,
    so a transient DB hiccup can't silently strip a vendor's access mid-deploy.
    """
    from . import db  # local import: db lazily imports rbac when seeding
    try:
        return db.sidecar_owner_emails(key)
    except Exception:
        log.exception('[RBAC] sidecar_owners DB read failed for %r; using seed', key)
        return SIDECAR_OWNERS_SEED.get(key, ())


def parse_capabilities(raw: str | None) -> frozenset[str]:
    """Parse a stored comma-separated extra-grant string into known caps.
    Unknown/stale tokens are dropped (intersected with ALL_CAPABILITIES)."""
    if not raw:
        return frozenset()
    return frozenset({t.strip() for t in raw.split(',') if t.strip()}) & ALL_CAPABILITIES


def capabilities_for_role(role: str | None) -> frozenset[str]:
    """Capabilities a *role* confers (no env-admin special-casing)."""
    if role == helpers.ADMIN_ROLE:
        return ALL_CAPABILITIES
    return ROLE_CAPABILITIES.get(role or '', frozenset())


def is_managed_role(role: str | None) -> bool:
    """True if a role is **managed** — it confers one or more capabilities (or
    is admin), so it must NOT be self-granted at signup; an admin promotes the
    user into it. 'Open' roles (viewer + any zero-capability title) are
    self-serve. This is the real signup gate: it catches a managed role no
    matter how it arrives (dropdown or typed into the "Other" box).

    NOTE: open roles are granted directly at signup, so if you later add
    capabilities to a previously-open role in ROLE_CAPABILITIES, re-audit its
    existing holders — they were self-granted while it was still open.
    """
    return bool(capabilities_for_role(role))


def user_capabilities(user: dict | None) -> frozenset[str]:
    """Effective capabilities for a current_user() dict (or None): the union
    of what the user's role confers and any per-user extra grants.

    Anyone in AUTH_ADMIN_EMAILS is fully capable regardless of stored role —
    a safety net so the operator can't lock themselves out by editing the DB.
    """
    if not user:
        return frozenset()
    if helpers.is_admin_email(user.get('email', '')):
        return ALL_CAPABILITIES
    return (capabilities_for_role(user.get('role'))
            | parse_capabilities(user.get('extra_capabilities')))


def has_capability(user: dict | None, cap: str) -> bool:
    return cap in user_capabilities(user)


def require_capability(*caps: str, owner_emails=(), sidecar=None):
    """Gate a route on one or more capabilities (the user needs ANY of them).

    Anonymous            -> 401 (JSON) / redirect to /login (HTML).
    Logged-in but unable  -> 403, and the denial is logged for audit.
    On success, sets request.user (mirrors login_required) so the view can
    read the actor without a second lookup.

    Ownership exception: pass ``sidecar='<key>'`` to let that sidecar's owner(s)
    (from the DB-backed sidecar_owners table) pass even without the global
    capability — so a vendor
    can deploy / roll back *their own* sidecar without being handed
    ``deploy.sidecar`` over every other sidecar on the box. ``owner_emails`` adds
    one-off owners inline. The capability still works for engineers/admins;
    ownership only ever adds, never removes.
    """
    needed = frozenset(caps)
    resolved = tuple(owner_emails) + (sidecar_owners(sidecar) if sidecar else ())
    owners = frozenset(e.strip().lower() for e in resolved if e and e.strip())

    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            user = helpers.current_user()
            if not user:
                if request.is_json or request.accept_mimetypes.best == 'application/json':
                    return jsonify({'success': False, 'error': 'login_required'}), 401
                return redirect(f'/login?next={quote(request.full_path)}')
            if needed & user_capabilities(user):
                request.user = user  # type: ignore[attr-defined]
                return view(*args, **kwargs)
            if owners and user.get('email', '').strip().lower() in owners:
                request.user = user  # type: ignore[attr-defined]
                log.info('[RBAC] OWNER-GRANT user=%s needed=%s method=%s path=%s',
                         user.get('email'), '|'.join(sorted(needed)),
                         request.method, request.path)
                return view(*args, **kwargs)
            log.warning('[RBAC] DENY user=%s role=%s needed=%s method=%s path=%s',
                        user.get('email'), user.get('role'),
                        '|'.join(sorted(needed)), request.method, request.path)
            if request.is_json or request.accept_mimetypes.best == 'application/json':
                return jsonify({'success': False, 'error': 'forbidden',
                                'needed_capability': sorted(needed)}), 403
            return _render_forbidden(needed), 403
        return wrapper
    return decorator


def _render_forbidden(needed: frozenset[str]):
    """Friendly HTML 403. Falls back to plain text so the denial page can
    never itself raise (a 500 on a 403 would be a bad look)."""
    try:
        return render_template('auth/forbidden.html',
                               needed=sorted(needed),
                               descriptions=CAPABILITIES)
    except Exception:
        wanted = ', '.join(sorted(needed))
        return (f'Forbidden — this action requires the "{wanted}" capability. '
                f'Ask an admin to grant your account access.')
