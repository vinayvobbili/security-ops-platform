"""
Graceful-degradation alerts for the CVE exposure pipeline.

The exposure flow has many moving parts (NVD, Tanium cloud + on-prem, SQLite
cache, correlator, AZDO) — any one of which can quietly break for a day if we
don't notice. These helpers post a one-shot Webex alert to the dev test space
so silent breakage gets surfaced. Dedup is in-memory, reset on process
restart — that way a systemd restart acts as "re-arm the alarm", useful for
confirming a fix took effect.
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

logger = logging.getLogger(__name__)

_NOTIFIED_KEYS: set[str] = set()
_LOCK = threading.Lock()


def notify_dev_space(issue_key: str, subject: str, detail: str = "") -> bool:
    """Send a one-shot Webex alert about an exposure-pipeline failure.

    issue_key is a stable identifier ("nvd_auth_failed", "tanium_sync_failed",
    etc.) — the same key won't re-alert in this process. Returns True if a
    message was posted, False if suppressed (dedup) or send failed.

    Never raises: alerting must not take down the caller.
    """
    with _LOCK:
        if issue_key in _NOTIFIED_KEYS:
            return False
        _NOTIFIED_KEYS.add(issue_key)

    try:
        from my_config import get_config
        from webexpythonsdk import WebexAPI

        config = get_config()
        room_id = getattr(config, "webex_room_id_dev_test_space", None)
        token = getattr(config, "webex_bot_access_token_pokedex", None)
        if not room_id or not token:
            logger.warning(
                "[exposure-alert] No dev-test-space room or bot token configured; "
                "skipping alert for %s", issue_key,
            )
            return False

        markdown = (
            f"⚠️ **CVE Exposure Pipeline — {subject}**\n\n"
            f"{detail}\n\n"
            f"_Issue key: `{issue_key}` · One alert per process; restart the "
            f"service to re-arm after fixing._"
        )
        WebexAPI(access_token=token).messages.create(roomId=room_id, markdown=markdown)
        logger.warning("[exposure-alert] Posted %s to dev test space", issue_key)
        return True
    except Exception as e:
        logger.error("[exposure-alert] Failed to post alert %s: %s", issue_key, e)
        return False


def reset_for_testing() -> None:
    """Clear the dedup set — only for use in tests."""
    with _LOCK:
        _NOTIFIED_KEYS.clear()
