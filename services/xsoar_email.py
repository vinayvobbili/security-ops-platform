"""Thin wrapper for sending email via XSOAR's `send-mail` integration command.

XSOAR requires every command to run inside an investigation. The API-key user
has no playground (admin can't bind keys to users in this XSOAR version), so
we pin every send to a long-lived "mail robot" incident. If that incident
gets closed, send-mail will fail — we detect that up front and ping Webex so
the ticket can be reopened.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, Optional, Union

from webexpythonsdk import WebexAPI

from my_config import get_config
from services.xsoar._client import ApiException, get_prod_client
from services.xsoar._utils import _parse_generic_response
from services.xsoar.ticket_handler import TicketHandler

log = logging.getLogger(__name__)
CONFIG = get_config()

MAIL_ROBOT_INCIDENT_ID = "1056832"
_XSOAR_ZERO_TIME = "0001-01-01T00:00:00Z"

Recipients = Union[str, Iterable[str]]


class MailRobotIncidentClosed(RuntimeError):
    """Raised when the mail-robot incident is closed and send-mail can't run."""


def _csv(value: Optional[Recipients]) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value.strip() or None
    cleaned = [str(item).strip() for item in value if str(item).strip()]
    return ",".join(cleaned) if cleaned else None


def _is_mail_robot_closed() -> bool:
    data = TicketHandler().get_case_data(MAIL_ROBOT_INCIDENT_ID)
    closed_at = data.get("closed") or ""
    return bool(closed_at) and closed_at != _XSOAR_ZERO_TIME


def _notify_mail_robot_closed(to: str, subject: str) -> None:
    room_id = CONFIG.webex_room_id_dev_test_space
    token = CONFIG.webex_bot_access_token_soar
    if not room_id or not token:
        log.warning("Mail robot closed but Webex dev room or token not configured")
        return
    try:
        WebexAPI(access_token=token).messages.create(
            roomId=room_id,
            markdown=(
                f"⚠️ **XSOAR mail-robot incident `{MAIL_ROBOT_INCIDENT_ID}` is closed** — "
                f"`send_email` is failing. Reopen the ticket to resume sends.\n\n"
                f"_Last attempt:_ to=`{to}` subject=`{subject}`"
            ),
        )
    except Exception as e:
        log.error("Failed to send mail-robot-closed Webex alert: %s", e)


def send_email(
    to: Recipients,
    subject: str,
    body: str,
    *,
    cc: Optional[Recipients] = None,
    bcc: Optional[Recipients] = None,
    html_body: Optional[str] = None,
    reply_to: Optional[str] = None,
    from_addr: Optional[str] = None,
    attach_ids: Optional[Recipients] = None,
    attach_names: Optional[Recipients] = None,
    additional_header: Optional[str] = None,
    using: Optional[str] = None,
) -> Dict[str, Any]:
    """Send an email through XSOAR's `send-mail` command.

    `to`, `cc`, `bcc`, `attach_ids`, `attach_names` may be a single string or
    an iterable of strings; iterables are joined into the CSV format XSOAR
    expects. `using` targets a specific integration instance (mailbox) — omit
    to let XSOAR route to its default instance.
    """
    to_csv = _csv(to)
    if not to_csv:
        raise ValueError("send_email requires at least one recipient in `to`")
    if not subject:
        raise ValueError("send_email requires a non-empty `subject`")

    if _is_mail_robot_closed():
        _notify_mail_robot_closed(to_csv, subject)
        raise MailRobotIncidentClosed(
            f"XSOAR mail-robot incident {MAIL_ROBOT_INCIDENT_ID} is closed"
        )

    raw_args: Dict[str, Optional[str]] = {
        "to": to_csv,
        "cc": _csv(cc),
        "bcc": _csv(bcc),
        "subject": subject,
        "body": body,
        "htmlBody": html_body,
        "replyTo": reply_to,
        "from": from_addr,
        "attachIDs": _csv(attach_ids),
        "attachNames": _csv(attach_names),
        "additionalHeader": additional_header,
        "using": using,
    }
    args = {k: {"simple": v} for k, v in raw_args.items() if v is not None}

    try:
        response = get_prod_client().generic_request(
            path="/entry/execute/sync",
            method="POST",
            body={
                "investigationId": MAIL_ROBOT_INCIDENT_ID,
                "data": "!send-mail",
                "args": args,
            },
        )
    except ApiException as e:
        log.error(
            "XSOAR send-mail failed: status=%s reason=%s to=%s subject=%r",
            e.status, getattr(e, "reason", ""), to_csv, subject,
        )
        raise

    parsed = _parse_generic_response(response)
    log.info("Sent email via XSOAR send-mail to=%s subject=%r", to_csv, subject)
    return parsed
