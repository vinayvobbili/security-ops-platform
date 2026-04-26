#!/usr/bin/env python3
"""
Backfill user notes from the XSOAR API into the xsoar_timeline database.

Iterates all tickets in the timeline DB that have no user_notes yet,
fetches notes via the XSOAR investigation API, and stores the
concatenated note text.  Uses a thread pool for parallel API calls.

Run on lab-vm:
    python scripts/backfill_user_notes.py
    python scripts/backfill_user_notes.py --workers 10
    python scripts/backfill_user_notes.py --dry-run
"""

import argparse
import logging
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)

# Suppress noisy ERROR logs from the XSOAR client for missing investigations
logging.getLogger('services.xsoar._entries').setLevel(logging.CRITICAL)


def _format_notes_text(notes: list) -> str:
    """Concatenate a list of note dicts into a single text string."""
    parts = []
    for n in notes:
        text = (n.get('note_text') or '').strip()
        if text:
            parts.append(text)
    return '\n\n'.join(parts)


# Thread-safe counters
_lock = threading.Lock()
_counters = {'populated': 0, 'empty': 0, 'errors': 0, 'done': 0}


def _process_ticket(ticket_id: str, ticket_handler) -> None:
    """Fetch user notes for one ticket and write to DB."""
    from services.xsoar_timeline_db import get_connection, update_user_notes

    try:
        notes = ticket_handler.get_user_notes(ticket_id)
        notes_text = _format_notes_text(notes)

        with get_connection() as conn:
            update_user_notes(conn, ticket_id, notes_text)

        with _lock:
            if notes_text:
                _counters['populated'] += 1
            else:
                _counters['empty'] += 1
            _counters['done'] += 1

    except Exception as e:
        err_str = str(e)
        if '429' in err_str:
            time.sleep(5)

        # Mark as empty so we don't retry
        try:
            with get_connection() as conn:
                update_user_notes(conn, ticket_id, '')
        except Exception:
            pass

        with _lock:
            _counters['errors'] += 1
            _counters['empty'] += 1
            _counters['done'] += 1


def backfill_user_notes(workers: int = 10, dry_run: bool = False):
    from services.xsoar_timeline_db import init_db, get_connection, set_sync_metadata
    from web.config import prod_ticket_handler

    init_db()

    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id FROM xsoar_tickets WHERE user_notes IS NULL"
        ).fetchall()

    ticket_ids = [r['id'] for r in rows]
    total = len(ticket_ids)
    logger.info(f"Found {total} tickets missing user_notes (workers={workers})")

    if dry_run:
        logger.info("DRY RUN — no changes will be made")
        return

    start = time.time()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_process_ticket, tid, prod_ticket_handler): tid
            for tid in ticket_ids
        }

        for future in as_completed(futures):
            future.result()  # propagate any uncaught exceptions

            with _lock:
                done = _counters['done']
            if done % 500 == 0 or done == total:
                elapsed = time.time() - start
                rate = done / elapsed if elapsed > 0 else 0
                eta_min = (total - done) / rate / 60 if rate > 0 else 0
                logger.info(
                    f"  Progress: {done}/{total} "
                    f"({_counters['populated']} with notes, {_counters['empty']} empty, "
                    f"{_counters['errors']} errors) "
                    f"[{rate:.0f}/s, ETA {eta_min:.0f}m]"
                )

    elapsed = time.time() - start
    logger.info(
        f"Backfill complete in {elapsed / 60:.1f}m: "
        f"{_counters['populated']} populated, {_counters['empty']} empty, "
        f"{_counters['errors']} errors out of {total} tickets"
    )
    set_sync_metadata('user_notes_backfill_at', time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Backfill user notes from XSOAR API')
    parser.add_argument('--workers', type=int, default=10,
                        help='Number of parallel API threads (default: 10)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show count of tickets to backfill without making changes')
    args = parser.parse_args()

    backfill_user_notes(workers=args.workers, dry_run=args.dry_run)
