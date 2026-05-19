"""Thin wrapper for sending Microsoft Teams messages via XSOAR's `send-notification`.

Mirrors `services.xsoar_email`: pins every call to the mail-robot incident
(API-key user has no playground), and pings Webex if that ticket gets closed
so a new ID can be supplied.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from webexpythonsdk import WebexAPI

from my_config import get_config
from services.xsoar._client import ApiException, get_prod_client
from services.xsoar._utils import _parse_generic_response
from services.xsoar.ticket_handler import TicketHandler

log = logging.getLogger(__name__)
CONFIG = get_config()

MAIL_ROBOT_INCIDENT_ID = "1056832"
TEAMS_INSTANCE = "microsoftteamsinstance1"
_XSOAR_ZERO_TIME = "0001-01-01T00:00:00Z"


class MailRobotIncidentClosed(RuntimeError):
    """Raised when the mail-robot incident is closed and send-notification can't run."""


def _is_mail_robot_closed() -> bool:
    data = TicketHandler().get_case_data(MAIL_ROBOT_INCIDENT_ID)
    closed_at = data.get("closed") or ""
    return bool(closed_at) and closed_at != _XSOAR_ZERO_TIME


def _notify_mail_robot_closed(target: str, message: str) -> None:
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
                f"`send_teams_message` is failing. Reopen the ticket to resume sends.\n\n"
                f"_Last attempt:_ target=`{target}` message=`{message[:120]}`"
            ),
        )
    except Exception as e:
        log.error("Failed to send mail-robot-closed Webex alert: %s", e)


def send_teams_message(
    message: str,
    *,
    to: Optional[str] = None,
    channel: Optional[str] = None,
    team: Optional[str] = None,
    chat: Optional[str] = None,
) -> Dict[str, Any]:
    """Send a Microsoft Teams message through XSOAR.

    Provide exactly one destination:
      - `to`: email or username for a 1:1 DM (sent by the bot)
      - `channel` (+ optional `team`): channel inside a team (sent by the bot)
      - `chat`: standalone group chat — name (topic) or chat ID. Sent by the
        XSOAR consent user, NOT the bot, and the consent user must be a
        member of that chat.
    """
    if not message:
        raise ValueError("send_teams_message requires a non-empty `message`")
    destinations = sum(1 for v in (to, channel, chat) if v)
    if destinations != 1:
        raise ValueError("send_teams_message requires exactly one of `to`, `channel`, or `chat`")
    if team and not channel:
        raise ValueError("`team` is only valid alongside `channel`")

    target = to or chat or (f"{team}/{channel}" if team else channel or "")

    if _is_mail_robot_closed():
        _notify_mail_robot_closed(target, message)
        raise MailRobotIncidentClosed(
            f"XSOAR mail-robot incident {MAIL_ROBOT_INCIDENT_ID} is closed"
        )

    if chat:
        command = "!microsoft-teams-message-send-to-chat"
        raw_args: Dict[str, Optional[str]] = {
            "chat": chat,
            "content": message,
            "using": TEAMS_INSTANCE,
        }
    else:
        command = "!send-notification"
        raw_args = {
            "message": message,
            "to": to,
            "channel": channel,
            "team": team,
            "using": TEAMS_INSTANCE,
        }
    args = {k: {"simple": v} for k, v in raw_args.items() if v is not None}

    try:
        response = get_prod_client().generic_request(
            path="/entry/execute/sync",
            method="POST",
            body={
                "investigationId": MAIL_ROBOT_INCIDENT_ID,
                "data": command,
                "args": args,
            },
        )
    except ApiException as e:
        log.error(
            "XSOAR Teams send failed: status=%s reason=%s command=%s target=%s",
            e.status, getattr(e, "reason", ""), command, target,
        )
        raise

    parsed = _parse_generic_response(response)
    log.info("Sent Teams message via %s target=%s", command, target)
    return parsed
