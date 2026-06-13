"""
Resilient Webex delivery for tipper analysis cards.

Background: tipper analysis runs in the de-scheduler. When Webex egress has a
transient blip (observed 2026-06-03: ~90 min of 60s connect-timeouts to
webexapis.com), the primary analysis-card send would fail, get logged as a
warning, and the hourly job would advance its last-run state regardless — so
those cards were silently dropped from the room with no retry.

Two layers of defense live here:

1. ``send_with_retry`` — bounded in-process retry with backoff. Rides through
   sub-minute blips during a single job run.

2. A persistent retry queue (``enqueue_failed`` / ``flush_retry_queue``) — when
   the in-process retries are exhausted (a longer outage), the tipper id is
   parked on disk. The next hourly run re-analyzes JUST that tipper and re-sends
   the analysis card. It deliberately does NOT re-run IOC/behavioral hunts or
   re-post AZDO comments (those already succeeded), so a flush is idempotent
   from the room's perspective and cheap on the work item.
"""

import json
import logging
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Lives alongside the scheduler's other transient state.
RETRY_QUEUE_FILE = (
    Path(__file__).resolve().parents[3] / "data/transient/tipper_webex_retry_queue.json"
)


def send_with_retry(
    webex_api,
    room_id: str,
    markdown: str,
    parent_id: Optional[str] = None,
    attempts: int = 4,
    base_delay: float = 2.0,
):
    """Send a Webex markdown message, retrying transient failures with backoff.

    Returns the created message object on success; raises the last exception if
    every attempt fails (caller decides whether to enqueue for later).
    """
    kwargs = {"roomId": room_id, "markdown": markdown}
    if parent_id:
        kwargs["parentId"] = parent_id

    last_err = None
    for attempt in range(1, attempts + 1):
        try:
            return webex_api.messages.create(**kwargs)
        except Exception as err:  # noqa: BLE001 - webexpythonsdk raises broadly
            last_err = err
            if attempt < attempts:
                delay = base_delay * (2 ** (attempt - 1))
                logger.warning(
                    f"[webex] send attempt {attempt}/{attempts} failed "
                    f"({type(err).__name__}); retrying in {delay:.0f}s"
                )
                time.sleep(delay)
    raise last_err


def _read_queue() -> list:
    try:
        if RETRY_QUEUE_FILE.exists():
            data = json.loads(RETRY_QUEUE_FILE.read_text())
            if isinstance(data, list):
                # normalize to strings, drop dupes, preserve order
                seen, out = set(), []
                for tid in data:
                    tid = str(tid)
                    if tid not in seen:
                        seen.add(tid)
                        out.append(tid)
                return out
    except (OSError, ValueError) as e:
        logger.warning(f"[webex] failed to read retry queue: {e}")
    return []


def _write_queue(ids: list) -> None:
    try:
        RETRY_QUEUE_FILE.parent.mkdir(parents=True, exist_ok=True)
        RETRY_QUEUE_FILE.write_text(json.dumps(ids))
    except OSError as e:
        logger.warning(f"[webex] failed to write retry queue: {e}")


def pending() -> list:
    """Return the list of tipper ids currently parked for retry."""
    return _read_queue()


def enqueue_failed(tipper_id: str) -> None:
    """Park a tipper id whose analysis card could not be delivered."""
    tipper_id = str(tipper_id)
    ids = _read_queue()
    if tipper_id not in ids:
        ids.append(tipper_id)
        _write_queue(ids)
        logger.warning(
            f"[webex] tipper #{tipper_id} parked on retry queue "
            f"({len(ids)} pending); next run will re-send the card"
        )


def flush_retry_queue(analyzer, room_id: str, webex_api) -> int:
    """Re-send analysis cards parked by earlier delivery failures.

    Re-analyzes each queued tipper (analysis only — no hunts, no AZDO writes)
    and re-sends the card. Successfully delivered ids are dropped from the queue;
    ids that still fail stay parked for the next run. Returns count re-sent.
    """
    from .utils import linkify_work_items_markdown

    ids = _read_queue()
    if not ids:
        return 0

    if not room_id:
        return 0

    logger.info(f"[webex] flushing retry queue: {len(ids)} card(s) pending {ids}")
    still_failed, sent = [], 0
    for tid in ids:
        try:
            analysis = analyzer.analyze_tipper(tipper_id=tid)
            md = linkify_work_items_markdown(
                analyzer.format_analysis_for_display(analysis, source="retry")
            )
            send_with_retry(webex_api, room_id, md)
            sent += 1
            logger.info(f"[webex] retry-delivered analysis card for tipper #{tid}")
        except Exception as e:  # noqa: BLE001
            still_failed.append(tid)
            logger.warning(
                f"[webex] retry still failing for tipper #{tid} "
                f"({type(e).__name__}); leaving on queue"
            )

    _write_queue(still_failed)
    return sent
