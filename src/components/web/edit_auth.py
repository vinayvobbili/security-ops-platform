"""Shared edit-action Webex notification for web edit operations.

Edit authorization moved off per-page passwords onto the auth system —
callers now gate with ``helpers.current_user()`` (any signed-in user)
or ``helpers.is_admin()`` for admin-only paths.
"""

import logging
import threading

logger = logging.getLogger(__name__)


def notify_edit_async(page: str, action: str, detail: str = "") -> None:
    """Send an edit notification to the dev test Webex space in a background thread."""
    def _send():
        try:
            from my_config import get_config
            from webexpythonsdk import WebexAPI
            config = get_config()
            room_id = config.webex_room_id_dev_test_space
            if not room_id:
                return
            webex_api = WebexAPI(access_token=config.webex_bot_access_token_aide)
            msg = f"**[Web Edit — {page}]** {action}"
            if detail:
                msg += f"\n> {detail}"
            webex_api.messages.create(roomId=room_id, markdown=msg)
        except Exception as exc:
            logger.error("Edit notification failed: %s", exc)

    threading.Thread(target=_send, daemon=True).start()
