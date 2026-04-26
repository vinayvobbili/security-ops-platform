"""XSOAR ticket poller for automated triage.

Polls XSOAR for open tickets and submits them to a background worker pool
for triage. The poll itself completes quickly (just the XSOAR fetch); heavy
enrichment / LLM / Webex work runs in worker threads.

Uses a persisted last-poll timestamp so that gaps (scheduler restarts, Ollama
outages, etc.) are automatically covered on the next successful poll.

Ticket-cannon protection:
- Per-poll cap (MAX_TICKETS_PER_POLL): only triage N tickets per cycle.
  Remaining tickets are picked up on the next poll via the widened lookback.
- Dedup by alert name: when multiple tickets share the same alert name,
  only one representative is fully triaged. The rest are noted in a
  single batch summary message to avoid flooding the Webex room.
"""

import json
import logging
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import my_config

logger = logging.getLogger(__name__)

CONFIG = my_config.get_config()

XSOAR_QUERY_BASE = f'type:{CONFIG.team_name} -category:job -owner:"" -type:"METCIRT IOC Hunt"'
DEFAULT_LOOKBACK_MINUTES = 5
MAX_LOOKBACK_MINUTES = 120  # 2-hour cap after long outages
MAX_TRIAGE_WORKERS = 4
MAX_TICKETS_PER_POLL = 10  # hard cap per poll cycle

_LAST_POLL_FILE = Path(__file__).parent.parent.parent.parent / "data/transient/xsoar_triage_last_poll.json"

# Regex to strip leading numeric ID and optional _AE_ tag from ticket names
_NAME_NORMALIZE_RE = re.compile(r"^\d+\s*(?:[-–—]\s*|_AE_\s*)?")

# Module-level worker pool — lives for the lifetime of the scheduler process.
_triage_pool = ThreadPoolExecutor(max_workers=MAX_TRIAGE_WORKERS, thread_name_prefix="xsoar-triage")


def _normalize_alert_name(name: str) -> str:
    """Normalize ticket name for dedup grouping (strip ID prefix, lowercase)."""
    return _NAME_NORMALIZE_RE.sub("", name).strip().lower()


def _load_last_poll_time() -> str | None:
    """Load the last successful poll timestamp from disk."""
    if _LAST_POLL_FILE.exists():
        try:
            with open(_LAST_POLL_FILE) as f:
                return json.load(f).get("last_poll")
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"[Sentinel XSOAR] Failed to read last-poll state: {e}")
    return None


def _save_last_poll_time(iso_ts: str) -> None:
    """Persist the last successful poll timestamp to disk."""
    try:
        _LAST_POLL_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(_LAST_POLL_FILE, "w") as f:
            json.dump({"last_poll": iso_ts}, f)
    except OSError as e:
        logger.warning(f"[Sentinel XSOAR] Failed to save last-poll state: {e}")


def _triage_worker(pipeline, ticket: dict) -> None:
    """Triage a single ticket in a worker thread."""
    ticket_id = ticket.get("id", "unknown")
    try:
        result = pipeline.triage_ticket(ticket)
        if result:
            logger.info(f"[Sentinel XSOAR] Worker finished triaging {ticket_id}")
    except Exception as e:
        logger.error(f"[Sentinel XSOAR] Triage failed for {ticket_id}: {e}", exc_info=True)


def _dedup_tickets(tickets: list) -> tuple[list, dict]:
    """Group tickets by normalized alert name. Return representatives + duplicates.

    Returns:
        (representatives, duplicates_map)
        - representatives: list of tickets to fully triage (one per unique alert name)
        - duplicates_map: {normalized_name: [list of duplicate ticket dicts]} for names
          that had more than one ticket. Only includes the extras (not the representative).
    """
    groups = defaultdict(list)
    for ticket in tickets:
        name = ticket.get("name", "")
        key = _normalize_alert_name(name)
        groups[key].append(ticket)

    representatives = []
    duplicates_map = {}
    for key, group in groups.items():
        # Pick the first ticket as the representative
        representatives.append(group[0])
        if len(group) > 1:
            duplicates_map[key] = group[1:]

    return representatives, duplicates_map


def _send_batch_summary(webex_api, room_id: str, duplicates_map: dict, capped_count: int) -> None:
    """Send a single summary message for deduplicated and capped tickets."""
    if not webex_api or not room_id:
        return
    if not duplicates_map and capped_count == 0:
        return

    lines = ["\U0001F4E2 **Sentinel Triage — Batch Summary**", ""]

    if duplicates_map:
        total_dupes = sum(len(v) for v in duplicates_map.values())
        lines.append(f"\U0001F501 **{total_dupes} duplicate tickets** grouped with their representative triage:")
        for key, dupes in duplicates_map.items():
            # Use the first dupe's original name for display
            display_name = dupes[0].get("name", key)[:60]
            ticket_ids = ", ".join(f"#{d.get('id', '?')}" for d in dupes)
            lines.append(f"  - **{display_name}** \u00d7{len(dupes)+1} \u2014 dupes: {ticket_ids}")
        lines.append("")

    if capped_count > 0:
        lines.append(f"\u23F3 **{capped_count} additional tickets** deferred to next poll cycle (cap: {MAX_TICKETS_PER_POLL}/poll)")

    try:
        webex_api.messages.create(roomId=room_id, markdown="\n".join(lines))
    except Exception as e:
        logger.warning(f"[Sentinel XSOAR] Failed to send batch summary: {e}")


def poll_once(webex_api=None, room_id: str = "") -> None:
    """Execute a single poll cycle: fetch new XSOAR tickets and submit them for triage.

    Uses a persisted last-poll timestamp to determine the lookback window.
    If the gap since the last poll exceeds the default interval, the window
    widens automatically (capped at MAX_LOOKBACK_MINUTES) so no tickets are
    missed after outages or restarts.

    Ticket-cannon protection:
    - Dedup: groups tickets by alert name, only triages one per unique name.
    - Cap: limits to MAX_TICKETS_PER_POLL per cycle. Excess is deferred.

    Args:
        webex_api: Webex API client for sending triage cards (optional).
        room_id: Webex room ID for triage notifications.
    """
    try:
        from services.xsoar.ticket_handler import TicketHandler
        from src.utils.xsoar_enums import XsoarEnvironment
        from src.components.xsoar_alert_triage.xsoar_triage_pipeline import XsoarTriagePipeline

        now = datetime.now(timezone.utc)

        # Determine lookback from last successful poll
        last_poll_iso = _load_last_poll_time()
        if last_poll_iso:
            try:
                last_poll_dt = datetime.fromisoformat(last_poll_iso)
                gap_minutes = (now - last_poll_dt).total_seconds() / 60
                lookback = min(max(gap_minutes, DEFAULT_LOOKBACK_MINUTES), MAX_LOOKBACK_MINUTES)
            except (ValueError, TypeError):
                lookback = DEFAULT_LOOKBACK_MINUTES
        else:
            lookback = DEFAULT_LOOKBACK_MINUTES

        lookback = int(lookback) + 1  # +1 for clock-skew safety margin

        if lookback > DEFAULT_LOOKBACK_MINUTES + 1:
            logger.info(f"[Sentinel XSOAR] Widened lookback to {lookback} mins (last poll: {last_poll_iso})")

        cutoff = now - timedelta(minutes=lookback)
        cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
        query = f'{XSOAR_QUERY_BASE} created:>="{cutoff_str}"'

        handler = TicketHandler(XsoarEnvironment.PROD)
        tickets = handler.get_tickets(
            query=query,
            paginate=False,
            read_timeout=15,
        )

        # Poll succeeded — update last-poll timestamp
        _save_last_poll_time(now.isoformat())

        if not tickets:
            logger.debug("[Sentinel XSOAR] No new tickets found")
            return

        logger.info(f"[Sentinel XSOAR] Found {len(tickets)} new tickets")

        # Step 1: Dedup by alert name
        representatives, duplicates_map = _dedup_tickets(tickets)
        deduped_count = sum(len(v) for v in duplicates_map.values())
        if deduped_count:
            logger.info(
                f"[Sentinel XSOAR] Deduped: {len(tickets)} → {len(representatives)} unique "
                f"({deduped_count} duplicates grouped)"
            )

        # Step 2: Apply per-poll cap
        capped_count = 0
        if len(representatives) > MAX_TICKETS_PER_POLL:
            capped_count = len(representatives) - MAX_TICKETS_PER_POLL
            logger.info(
                f"[Sentinel XSOAR] Capping at {MAX_TICKETS_PER_POLL}, "
                f"deferring {capped_count} to next poll"
            )
            representatives = representatives[:MAX_TICKETS_PER_POLL]

        logger.info(f"[Sentinel XSOAR] Submitting {len(representatives)} tickets to worker pool")

        pipeline = XsoarTriagePipeline(
            webex_api=webex_api,
            room_id=room_id,
        )

        for ticket in representatives:
            _triage_pool.submit(_triage_worker, pipeline, ticket)

        # Step 3: Send batch summary for deduped/capped tickets
        if duplicates_map or capped_count:
            _send_batch_summary(webex_api, room_id, duplicates_map, capped_count)

    except Exception as e:
        # Don't update last_poll on failure — preserve the wide window for next retry
        logger.error(f"[Sentinel XSOAR] Poll cycle failed: {e}", exc_info=True)
