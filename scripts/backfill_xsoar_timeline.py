#!/usr/bin/env python3
"""
Backfill script to populate XSOAR ticket timeline database from production XSOAR.

Fetches historical incidents and stores them in the SQLite database used by
the animated bar chart race on the meaningful-metrics page.

Run on lab-vm:
    python scripts/backfill_xsoar_timeline.py
    python scripts/backfill_xsoar_timeline.py --days-back 1095
    python scripts/backfill_xsoar_timeline.py --from-date 2022-11-01 --to-date 2023-11-01
    python scripts/backfill_xsoar_timeline.py --incremental
    python scripts/backfill_xsoar_timeline.py --dry-run
"""

import argparse
import logging
import sys
from datetime import date, datetime, timezone
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def backfill(days_back: int = 1095, from_date: str = None, to_date: str = None,
             incremental: bool = False, dry_run: bool = False):
    """Fetch tickets from XSOAR and store in timeline database."""
    from services.xsoar_timeline_db import init_db, get_connection, upsert_ticket, set_sync_metadata, get_sync_metadata
    from web.config import prod_ticket_handler, CONFIG

    team_name = CONFIG.team_name

    init_db()

    # Build query
    query = f'type:{team_name} -category:job'
    period = None

    if from_date or to_date:
        # Date range mode: use created field in query
        if from_date:
            query += f' created:>="{from_date}"'
        if to_date:
            query += f' created:<"{to_date}"'
        logger.info(f"Date range mode: {from_date or 'beginning'} to {to_date or 'now'}")
    else:
        # Legacy days-back mode
        period = {'by': 'day', 'fromValue': days_back}

    # Incremental: only fetch since last sync
    if incremental:
        last_sync = get_sync_metadata('last_sync_created')
        if last_sync:
            logger.info(f"Incremental mode: fetching tickets created after {last_sync}")

    logger.info(f"Query: {query}")
    try:
        tickets = prod_ticket_handler.get_tickets(
            query=query,
            period=period,
            paginate=True
        )
    except Exception as e:
        logger.error(f"Failed to fetch tickets from XSOAR: {e}")
        sys.exit(1)

    logger.info(f"Fetched {len(tickets)} tickets from XSOAR")

    if dry_run:
        logger.info("DRY RUN — no database changes will be made")
        # Show a summary of what would be inserted
        severities = {}
        for t in tickets:
            sev = t.get('severity', 0)
            severities[sev] = severities.get(sev, 0) + 1
        logger.info(f"Severity breakdown: {severities}")
        return

    # Insert tickets in batches
    inserted = 0
    skipped = 0
    notes_populated = 0
    latest_created = None
    batch_size = 500

    with get_connection() as conn:
        for i, ticket in enumerate(tickets):
            ticket_id = str(ticket.get('id', ''))
            created = ticket.get('created', '')
            if not ticket_id or not created:
                skipped += 1
                continue

            # In incremental mode, skip older tickets
            if incremental and last_sync and created < last_sync:
                skipped += 1
                continue

            try:
                upsert_ticket(conn, ticket)
                inserted += 1
            except Exception as e:
                logger.debug(f"  Skipping ticket {ticket_id}: {e}")
                skipped += 1
                continue

            # Fetch user notes from XSOAR API and store
            try:
                notes = prod_ticket_handler.get_user_notes(ticket_id)
                parts = [n.get('note_text', '').strip() for n in notes if n.get('note_text', '').strip()]
                if parts:
                    from services.xsoar_timeline_db import update_user_notes
                    update_user_notes(conn, ticket_id, '\n\n'.join(parts))
                    notes_populated += 1
            except Exception as e:
                logger.debug(f"  Could not fetch notes for {ticket_id}: {e}")

            # Track latest created date
            if created and (latest_created is None or created > latest_created):
                latest_created = created

            # Progress logging
            if (i + 1) % batch_size == 0:
                logger.info(f"  Processed {i + 1}/{len(tickets)} tickets ({inserted} inserted, {skipped} skipped, {notes_populated} with notes)")

    # Update sync metadata
    now = datetime.now(timezone.utc).isoformat()
    set_sync_metadata('last_sync_at', now)
    if latest_created:
        set_sync_metadata('last_sync_created', latest_created)
    set_sync_metadata('total_tickets_synced', str(inserted))

    logger.info(f"Backfill complete: {inserted} tickets inserted, {skipped} skipped")
    logger.info(f"Sync metadata updated (last_sync_at={now})")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Backfill XSOAR ticket timeline database')
    parser.add_argument('--days-back', type=int, default=1095,
                        help='Number of days of history to fetch (default: 1095 = ~3 years)')
    parser.add_argument('--from-date', type=str, default=None,
                        help='Start date for range query (YYYY-MM-DD). Overrides --days-back.')
    parser.add_argument('--to-date', type=str, default=None,
                        help='End date for range query (YYYY-MM-DD). Overrides --days-back.')
    parser.add_argument('--incremental', action='store_true',
                        help='Only fetch tickets newer than last sync')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would be done without making changes')
    args = parser.parse_args()

    backfill(days_back=args.days_back, from_date=args.from_date, to_date=args.to_date,
             incremental=args.incremental, dry_run=args.dry_run)
