#!/usr/bin/env python3
"""
Backfill script to extract untagged host breakdown reasons from existing
CrowdStrike Excel result files and update the tagging_runs table.

Reads EPP-Falcon ring tagging result files, classifies untagged hosts
by reason (missing Snow data, no Snow entry, API error), and updates
the corresponding database rows.

Usage:
    python scripts/backfill_untagged_breakdown.py [--dry-run]
"""

import argparse
import logging
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd

from services.epp_tagging_db import init_db, get_connection

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

SOURCE_DIR = PROJECT_ROOT / "data" / "transient" / "epp_device_tagging"


def classify_status(status: str) -> str:
    """Classify an untagged host's reason from its status message."""
    if not isinstance(status, str):
        return 'missing_snow_data'
    msg = status.lower()
    if 'not found in servicenow' in msg:
        return 'no_snow_entry'
    if 'error' in msg:
        return 'error'
    return 'missing_snow_data'


def process_cs_file(filepath: Path) -> dict | None:
    """
    Extract untagged breakdown counts from a CrowdStrike result Excel file.

    Returns dict with keys: missing_snow_data, no_snow_entry, error
    or None if the file can't be processed.
    """
    try:
        df = pd.read_excel(filepath)
    except Exception as e:
        logger.warning(f"  Could not read {filepath.name}: {e}")
        return None

    if 'Generated CS Tag' not in df.columns or 'Status' not in df.columns:
        logger.warning(f"  Missing required columns in {filepath.name}")
        return None

    # Find untagged hosts (empty Generated CS Tag)
    untagged = df[df['Generated CS Tag'].isna() | (df['Generated CS Tag'].astype(str).str.strip() == '')]

    counts = {'missing_snow_data': 0, 'no_snow_entry': 0, 'error': 0}
    for _, row in untagged.iterrows():
        reason = classify_status(row.get('Status', ''))
        counts[reason] += 1

    return counts


def backfill(dry_run: bool = False):
    """Backfill untagged breakdown data from Excel files into the database."""
    logger.info(f"Starting untagged breakdown backfill from {SOURCE_DIR}")
    logger.info(f"Dry run: {dry_run}")

    if not SOURCE_DIR.exists():
        logger.error(f"Source directory does not exist: {SOURCE_DIR}")
        return

    init_db()

    # Get all CrowdStrike runs from the database that have zero breakdown values
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, run_date, source_file, run_timestamp
            FROM tagging_runs
            WHERE platform = 'CrowdStrike'
              AND (untagged_missing_snow_data = 0 AND untagged_no_snow_entry = 0 AND untagged_error = 0)
            ORDER BY run_date
        """)
        runs_to_update = [dict(r) for r in cursor.fetchall()]

    logger.info(f"Found {len(runs_to_update)} CrowdStrike runs with no breakdown data")

    updated = 0
    skipped = 0

    for run in runs_to_update:
        run_id = run['id']
        run_date = run['run_date']
        source_file = run['source_file']

        if not source_file:
            logger.debug(f"  Run {run_id} ({run_date}): no source_file recorded, skipping")
            skipped += 1
            continue

        # Find the Excel file - try the date-based directory structure
        # run_date is stored as YYYY-MM-DD, directory is MM-DD-YYYY
        try:
            from datetime import datetime
            dt = datetime.strptime(run_date, '%Y-%m-%d')
            date_dir = dt.strftime('%m-%d-%Y')
        except (ValueError, TypeError):
            logger.warning(f"  Run {run_id}: could not parse run_date '{run_date}'")
            skipped += 1
            continue

        filepath = SOURCE_DIR / date_dir / source_file
        if not filepath.exists():
            logger.debug(f"  Run {run_id} ({run_date}): file not found: {filepath}")
            skipped += 1
            continue

        counts = process_cs_file(filepath)
        if counts is None:
            skipped += 1
            continue

        total_untagged = counts['missing_snow_data'] + counts['no_snow_entry'] + counts['error']
        if total_untagged == 0:
            logger.debug(f"  Run {run_id} ({run_date}): all hosts were tagged, no breakdown to store")
            skipped += 1
            continue

        logger.info(
            f"  Run {run_id} ({run_date}): {total_untagged} untagged - "
            f"missing_snow_data={counts['missing_snow_data']}, "
            f"no_snow_entry={counts['no_snow_entry']}, "
            f"error={counts['error']}"
        )

        if not dry_run:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE tagging_runs
                    SET untagged_missing_snow_data = ?,
                        untagged_no_snow_entry = ?,
                        untagged_error = ?
                    WHERE id = ?
                """, (counts['missing_snow_data'], counts['no_snow_entry'], counts['error'], run_id))

        updated += 1

    logger.info(f"Backfill complete: {updated} runs updated, {skipped} skipped")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Backfill untagged breakdown data from Excel files')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without making changes')
    args = parser.parse_args()

    backfill(dry_run=args.dry_run)
