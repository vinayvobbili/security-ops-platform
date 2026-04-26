"""Shared edit-action auth and Webex notification for web edit operations."""

import logging
import secrets
import threading

logger = logging.getLogger(__name__)


def _get_provided_password(request) -> str:
    """Extract password from JSON body or multipart form field."""
    provided = (request.get_json(silent=True) or {}).get("password", "")
    if not provided:
        provided = request.form.get("password", "")
    return provided


_PAGE_PASSWORD_FIELDS = {
    "contacts": "contacts_edit_password",
    "docs": "docs_edit_password",
    "wiki": "wiki_edit_password",
    "favorites": "favorites_edit_password",
}


def check_edit_password(request, page: str) -> bool:
    """Return True if the request carries a valid edit password for the given page (or none is configured)."""
    from my_config import get_config
    field = _PAGE_PASSWORD_FIELDS[page]
    expected = (getattr(get_config(), field) or "").strip()
    if not expected:
        return True
    return secrets.compare_digest(_get_provided_password(request), expected)


def check_s3_password(request) -> bool:
    """Return True if the request carries a valid S3 scan password (or none is configured)."""
    from my_config import get_config
    expected = (get_config().scan_s3_password or "").strip()
    if not expected:
        return True
    return secrets.compare_digest(_get_provided_password(request), expected)


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
            webex_api = WebexAPI(access_token=config.webex_bot_access_token_toodles)
            msg = f"**[Web Edit — {page}]** {action}"
            if detail:
                msg += f"\n> {detail}"
            webex_api.messages.create(roomId=room_id, markdown=msg)
        except Exception as exc:
            logger.error("Edit notification failed: %s", exc)

    threading.Thread(target=_send, daemon=True).start()
