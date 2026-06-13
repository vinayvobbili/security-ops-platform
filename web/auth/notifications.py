"""Sharing-alert notifications for the CCR PAT flow.

When a PAT is used from a new client IP, ping the admin's Webex space so
the human operator can decide whether to revoke. The PAT owner is NOT
emailed — alerts go to the operator only.

Routed via the Toodles bot token (same one used by oncall notifications)
because the alert is operator-facing. Target room defaults to the dev test
space; override via WEBEX_ROOM_ID_PAT_SHARING_ALERTS.
"""
from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timezone
from typing import Optional
from zoneinfo import ZoneInfo

_EASTERN = ZoneInfo('America/New_York')
_TIME_FMT = '%m/%d/%Y %I:%M %p %Z'  # 05/19/2026 10:07 AM EDT


def _fmt_when(ts: Optional[int]) -> str:
    epoch = ts if ts is not None else int(datetime.now(tz=timezone.utc).timestamp())
    return datetime.fromtimestamp(epoch, tz=_EASTERN).strftime(_TIME_FMT)

log = logging.getLogger(__name__)


def _admin_room_id() -> Optional[str]:
    override = os.environ.get('WEBEX_ROOM_ID_PAT_SHARING_ALERTS')
    if override:
        return override
    return os.environ.get('WEBEX_ROOM_ID_DEV_TEST_SPACE') or None


def _send_webex_blocking(markdown: str, room_id: str) -> None:
    try:
        from my_config import get_config
        from webexpythonsdk import WebexAPI
        cfg = get_config()
        token = getattr(cfg, 'webex_bot_access_token_toodles', None)
        if not token:
            log.warning('PAT-sharing alert dropped: no toodles bot token')
            return
        WebexAPI(access_token=token).messages.create(roomId=room_id, markdown=markdown)
    except Exception:
        log.exception('PAT-sharing Webex alert failed')


def notify_pat_created(user_email: str, pat_name: str, client_ip: str,
                       ts: Optional[int] = None) -> None:
    """Fire a Webex alert when a user clicks the Generate PAT button on
    /account. Best-effort, threaded, never raises out of the request path.
    """
    room_id = _admin_room_id()
    if not room_id:
        log.warning('PAT-created alert dropped: no target room configured')
        return
    when = _fmt_when(ts)
    markdown = (
        f'**New PAT generated**\n\n'
        f'- User: `{user_email}`\n'
        f'- Token name: `{pat_name}`\n'
        f'- Client IP: `{client_ip}`\n'
        f'- When: {when}\n\n'
        f'Review all PATs on [Traffic Logs → PATs tab](https://gdnr.the-company.com/traffic-logs).'
    )
    threading.Thread(target=_send_webex_blocking, args=(markdown, room_id), daemon=True).start()


def notify_new_signup(user_email: str, role_label: str, client_ip: str,
                      access_reason: str = '', is_admin: bool = False,
                      ad_status: str = 'skipped',
                      ts: Optional[int] = None) -> None:
    """Fire a Webex alert when a new account is registered. Sent at the
    /register step (pre-verification), so a flood of registrations from
    one IP is visible even if none of them complete email verification.

    Best-effort: runs in a thread, never raises out of the request path.
    """
    room_id = _admin_room_id()
    if not room_id:
        log.warning('Signup alert dropped: no target room configured')
        return
    when = _fmt_when(ts)
    admin_line = '\n- 🛡️ **Granted admin role** (matched AUTH_ADMIN_EMAILS)' if is_admin else ''
    reason_line = f'\n- Access reason: {access_reason}' if access_reason else ''
    # Only worth surfacing when AD couldn't confirm the address (fail-open path).
    # "found" is the happy default and needs no line; "skipped" means the check
    # didn't run (shouldn't normally happen on this path).
    if ad_status == 'unknown':
        ad_line = '\n- ⚠️ **AD: directory check unavailable** — address NOT verified against AD (allowed via fail-open)'
    elif ad_status == 'skipped':
        ad_line = '\n- ⚠️ AD: directory check did not run'
    else:
        ad_line = ''
    markdown = (
        f'**New IR signup**\n\n'
        f'- Email: `{user_email}`\n'
        f'- Role: {role_label}{reason_line}\n'
        f'- Client IP: `{client_ip}`\n'
        f'- When: {when}{admin_line}{ad_line}\n\n'
        f'They still need to verify the email link before they can sign in.'
    )
    threading.Thread(target=_send_webex_blocking, args=(markdown, room_id), daemon=True).start()


# Where the operator goes to promote a pending managed-role request. Override
# with ADMIN_USERS_URL; defaults to the production admin page.
_ADMIN_USERS_URL = os.environ.get('ADMIN_USERS_URL', 'https://gdnr.the-company.com/admin-users')


def notify_managed_role_request(user_email: str, requested_role: str,
                                client_ip: str, access_reason: str = '',
                                ad_status: str = 'skipped',
                                ts: Optional[int] = None) -> None:
    """Fire a Webex approval alert when a signup requests a **managed**
    (capability-bearing) role. The account is created at the open default
    (`viewer`); this pings the operator to review and promote it on
    /admin-users. Best-effort: threaded, never raises out of the request path.
    """
    room_id = _admin_room_id()
    if not room_id:
        log.warning('Managed-role request alert dropped: no target room configured')
        return
    when = _fmt_when(ts)
    reason_line = f'\n- 📝 Reason: {access_reason}' if access_reason else ''
    if ad_status == 'unknown':
        ad_line = '\n- ⚠️ **AD: directory check unavailable** — address NOT verified against AD (allowed via fail-open)'
    elif ad_status == 'skipped':
        ad_line = '\n- ⚠️ AD: directory check did not run'
    else:
        ad_line = ''
    markdown = (
        f'🔐 **Managed-role request — approval needed**\n\n'
        f'- 👤 Email: `{user_email}`\n'
        f'- 🎟️ Requested role: **{requested_role}** (capability-bearing)\n'
        f'- 🪪 Granted for now: `viewer` (open) — no capabilities until you promote'
        f'{reason_line}\n'
        f'- 🌐 Client IP: `{client_ip}`\n'
        f'- 🕒 When: {when}{ad_line}\n\n'
        f'➡️ **[Review & promote on the admin page]({_ADMIN_USERS_URL})** — '
        f'set their role to **{requested_role}**, or leave them as the open role. '
        f'They must verify their email link before they can sign in either way.'
    )
    threading.Thread(target=_send_webex_blocking, args=(markdown, room_id), daemon=True).start()
