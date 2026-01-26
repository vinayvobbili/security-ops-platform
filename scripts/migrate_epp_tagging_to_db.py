#!/usr/bin/env python3
"""
Migration script to extract EPP device tagging metrics from Excel files
and populate the SQLite database.

This script reads all existing tagging result files from
data/transient/epp_device_tagging/ and inserts aggregated metrics
into the SQLite database.

Usage:
    python scripts/migrate_epp_tagging_to_db.py [--dry-run]
"""

import argparse
import logging
import os
import re
import sys
from datetime import datetime
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd

from services.epp_tagging_db import (
    init_db,
    insert_tagging_run,
    bulk_insert_results,
    run_exists,
    get_summary_stats,
    update_run_by_for_historical_data,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Source directory
SOURCE_DIR = PROJECT_ROOT / "data" / "transient" / "epp_device_tagging"


def parse_date_from_dirname(dirname: str) -> datetime:
    """Parse MM-DD-YYYY format from directory name."""
    return datetime.strptime(dirname, '%m-%d-%Y')


def parse_timestamp_from_filename(filename: str) -> datetime | None:
    """
    Extract timestamp from filename patterns like:
    - Tanium_Ring_Tagging_Results_12_30_2025 03:45 PM EST.xlsx
    - EPP-Falcon ring tagging 12_11_2025 07:59 AM EST.xlsx
    """
    # Pattern for timestamps in filenames
    patterns = [
        r'(\d{2}_\d{2}_\d{4})\s+(\d{1,2}:\d{2})\s*(AM|PM)\s*(E[SD]T)?',
        r'(\d{2}-\d{2}-\d{4})\s+(\d{1,2}:\d{2})\s*(AM|PM)\s*(E[SD]T)?',
    ]

    for pattern in patterns:
        match = re.search(pattern, filename)
        if match:
            date_str = match.group(1).replace('_', '-')
            time_str = match.group(2)
            ampm = match.group(3)
            try:
                dt = datetime.strptime(f"{date_str} {time_str} {ampm}", '%m-%d-%Y %I:%M %p')
                return dt
            except ValueError:
                pass
    return None


def extract_region_from_ring_tag(ring_tag: str) -> str | None:
    """
    Extract region from ring tag format like 'EPP_ECMTag_LATAM_Wks_Ring3'.

    Common patterns:
    - EPP_ECMTag_<Region>_<Category>_Ring<N>
    - EPP_ECMTag_<Country>_<Category>_Ring<N>
    """
    if not ring_tag or not isinstance(ring_tag, str):
        return None

    # Known regions/countries in ring tags
    region_mapping = {
        'LATAM': 'LATAM',
        'US': 'United States',
        'EMEA': 'EMEA',
        'APAC': 'APAC',
        'JP': 'Japan',
        'Korea': 'Korea',
        'India': 'India',
    }

    parts = ring_tag.split('_')
    for part in parts:
        if part in region_mapping:
            return region_mapping[part]

    return None


def process_tanium_tagging_results(filepath: Path, run_date: datetime, dry_run: bool = False) -> dict:
    """
    Process Tanium_Ring_Tagging_Results files.

    These files may have varying columns. Common columns include:
    - Computer Name, Tanium ID, Source, Country, Region, Environment,
      Ring Tag, Package ID, Action ID, Current Tags, Status
    - Or minimal: Computer Name, Source, Ring Tag, Action ID, Current Tags, Comments, Status
    """
    logger.info(f"Processing Tanium tagging results: {filepath.name}")

    try:
        df = pd.read_excel(filepath)
    except Exception as e:
        logger.error(f"Failed to read {filepath}: {e}")
        return {'skipped': True, 'reason': str(e)}

    if 'Status' not in df.columns:
        logger.warning(f"No Status column in {filepath.name}, skipping")
        return {'skipped': True, 'reason': 'No Status column'}

    # Get timestamp from filename
    run_timestamp = parse_timestamp_from_filename(filepath.name)

    # Calculate totals
    total_devices = len(df)
    successfully_tagged = len(df[df['Status'] == 'Successfully Tagged'])
    failed = total_devices - successfully_tagged

    # Aggregate results
    results = []
    has_country = 'Country' in df.columns
    has_region = 'Region' in df.columns
    has_environment = 'Environment' in df.columns
    has_ring_tag = 'Ring Tag' in df.columns

    if has_country:
        # Standard format with Country column
        groupby_cols = ['Country']
        if has_region:
            groupby_cols.append('Region')
        if has_environment:
            groupby_cols.append('Environment')

        for group_key, group_df in df.groupby(groupby_cols, dropna=False):
            if isinstance(group_key, tuple):
                country = group_key[0] if pd.notna(group_key[0]) else 'Unknown'
                region = group_key[1] if len(group_key) > 1 and pd.notna(group_key[1]) else None
                environment = group_key[2] if len(group_key) > 2 and pd.notna(group_key[2]) else None
            else:
                country = group_key if pd.notna(group_key) else 'Unknown'
                region = None
                environment = None

            # Further breakdown by ring tag if available
            if has_ring_tag:
                for ring_tag, tag_df in group_df.groupby('Ring Tag', dropna=False):
                    ring_tag_val = ring_tag if pd.notna(ring_tag) else None
                    results.append({
                        'country': country,
                        'region': region,
                        'category': None,
                        'environment': environment,
                        'ring_tag': ring_tag_val,
                        'total_devices': len(tag_df),
                        'successfully_tagged': len(tag_df[tag_df['Status'] == 'Successfully Tagged']),
                        'failed': len(tag_df[tag_df['Status'] != 'Successfully Tagged']),
                        'country_guessed': 0
                    })
            else:
                results.append({
                    'country': country,
                    'region': region,
                    'category': None,
                    'environment': environment,
                    'ring_tag': None,
                    'total_devices': len(group_df),
                    'successfully_tagged': len(group_df[group_df['Status'] == 'Successfully Tagged']),
                    'failed': len(group_df[group_df['Status'] != 'Successfully Tagged']),
                    'country_guessed': 0
                })
    elif has_ring_tag:
        # Minimal format - extract region from ring tag
        for ring_tag, tag_df in df.groupby('Ring Tag', dropna=False):
            ring_tag_val = ring_tag if pd.notna(ring_tag) else None
            region = extract_region_from_ring_tag(ring_tag_val)
            results.append({
                'country': region or 'Unknown',  # Use region as country approximation
                'region': region,
                'category': None,
                'environment': None,
                'ring_tag': ring_tag_val,
                'total_devices': len(tag_df),
                'successfully_tagged': len(tag_df[tag_df['Status'] == 'Successfully Tagged']),
                'failed': len(tag_df[tag_df['Status'] != 'Successfully Tagged']),
                'country_guessed': 0
            })
    else:
        # No grouping possible, insert as single record
        results.append({
            'country': 'Unknown',
            'region': None,
            'category': None,
            'environment': None,
            'ring_tag': None,
            'total_devices': total_devices,
            'successfully_tagged': successfully_tagged,
            'failed': failed,
            'country_guessed': 0
        })

    if dry_run:
        logger.info(f"  [DRY RUN] Would insert run with {total_devices} devices, {len(results)} result groups")
        return {
            'platform': 'Tanium',
            'total_devices': total_devices,
            'successfully_tagged': successfully_tagged,
            'result_groups': len(results)
        }

    # Check if already exists
    if run_exists(run_date.date(), 'Tanium', run_timestamp):
        logger.info(f"  Run already exists, skipping")
        return {'skipped': True, 'reason': 'Already exists'}

    # Insert into database
    run_id = insert_tagging_run(
        run_date=run_date.date(),
        platform='Tanium',
        run_timestamp=run_timestamp,
        source_file=filepath.name,
        total_devices=total_devices,
        successfully_tagged=successfully_tagged,
        failed=failed
    )
    bulk_insert_results(run_id, results)

    logger.info(f"  Inserted run {run_id} with {total_devices} devices, {len(results)} result groups")
    return {
        'run_id': run_id,
        'platform': 'Tanium',
        'total_devices': total_devices,
        'successfully_tagged': successfully_tagged,
        'result_groups': len(results)
    }


def process_crowdstrike_tagging_results(filepath: Path, run_date: datetime, dry_run: bool = False) -> dict:
    """
    Process EPP-Falcon ring tagging files.

    These files have columns:
    - Name, CS Device ID, Category, Environment, Life Cycle Status,
      Country, Region, Was Country Guessed, Current CS Tags, Generated CS Tag, Status
    """
    logger.info(f"Processing CrowdStrike tagging results: {filepath.name}")

    try:
        df = pd.read_excel(filepath)
    except Exception as e:
        logger.error(f"Failed to read {filepath}: {e}")
        return {'skipped': True, 'reason': str(e)}

    # Get timestamp from filename
    run_timestamp = parse_timestamp_from_filename(filepath.name)

    # Calculate totals
    total_devices = len(df)
    # CS files typically don't have explicit success status - all are tagged
    successfully_tagged = total_devices
    failed = 0

    # Aggregate by country/region/category/environment/ring_tag
    results = []
    groupby_cols = ['Country']
    if 'Region' in df.columns:
        groupby_cols.append('Region')
    if 'Category' in df.columns:
        groupby_cols.append('Category')
    if 'Environment' in df.columns:
        groupby_cols.append('Environment')

    for group_key, group_df in df.groupby(groupby_cols, dropna=False):
        if isinstance(group_key, tuple):
            country = group_key[0] if pd.notna(group_key[0]) else 'Unknown'
            region = group_key[1] if len(group_key) > 1 and pd.notna(group_key[1]) else None
            category = group_key[2] if len(group_key) > 2 and pd.notna(group_key[2]) else None
            environment = group_key[3] if len(group_key) > 3 and pd.notna(group_key[3]) else None
        else:
            country = group_key if pd.notna(group_key) else 'Unknown'
            region = None
            category = None
            environment = None

        # Count country guessed
        country_guessed = 0
        if 'Was Country Guessed' in group_df.columns:
            country_guessed = len(group_df[group_df['Was Country Guessed'].astype(str).str.lower() == 'yes'])

        # Further breakdown by ring tag
        ring_tag_col = 'Generated CS Tag' if 'Generated CS Tag' in group_df.columns else None
        if ring_tag_col:
            for ring_tag, tag_df in group_df.groupby(ring_tag_col, dropna=False):
                ring_tag_val = ring_tag if pd.notna(ring_tag) else None
                guessed = 0
                if 'Was Country Guessed' in tag_df.columns:
                    guessed = len(tag_df[tag_df['Was Country Guessed'].astype(str).str.lower() == 'yes'])

                results.append({
                    'country': country,
                    'region': region,
                    'category': category,
                    'environment': environment,
                    'ring_tag': ring_tag_val,
                    'total_devices': len(tag_df),
                    'successfully_tagged': len(tag_df),
                    'failed': 0,
                    'country_guessed': guessed
                })
        else:
            results.append({
                'country': country,
                'region': region,
                'category': category,
                'environment': environment,
                'ring_tag': None,
                'total_devices': len(group_df),
                'successfully_tagged': len(group_df),
                'failed': 0,
                'country_guessed': country_guessed
            })

    if dry_run:
        logger.info(f"  [DRY RUN] Would insert run with {total_devices} devices, {len(results)} result groups")
        return {
            'platform': 'CrowdStrike',
            'total_devices': total_devices,
            'successfully_tagged': successfully_tagged,
            'result_groups': len(results)
        }

    # Check if already exists
    if run_exists(run_date.date(), 'CrowdStrike', run_timestamp):
        logger.info(f"  Run already exists, skipping")
        return {'skipped': True, 'reason': 'Already exists'}

    # Insert into database
    run_id = insert_tagging_run(
        run_date=run_date.date(),
        platform='CrowdStrike',
        run_timestamp=run_timestamp,
        source_file=filepath.name,
        total_devices=total_devices,
        successfully_tagged=successfully_tagged,
        failed=failed
    )
    bulk_insert_results(run_id, results)

    logger.info(f"  Inserted run {run_id} with {total_devices} devices, {len(results)} result groups")
    return {
        'run_id': run_id,
        'platform': 'CrowdStrike',
        'total_devices': total_devices,
        'successfully_tagged': successfully_tagged,
        'result_groups': len(results)
    }


def migrate_all(dry_run: bool = False):
    """Migrate all EPP tagging data from Excel files to SQLite."""
    logger.info(f"Starting migration from {SOURCE_DIR}")
    logger.info(f"Dry run: {dry_run}")

    if not SOURCE_DIR.exists():
        logger.error(f"Source directory does not exist: {SOURCE_DIR}")
        return

    # Initialize database
    init_db()

    stats = {
        'tanium_runs': 0,
        'cs_runs': 0,
        'tanium_devices': 0,
        'cs_devices': 0,
        'skipped': 0,
        'errors': 0
    }

    # Process each date directory
    for date_dir in sorted(SOURCE_DIR.iterdir()):
        if not date_dir.is_dir():
            continue

        try:
            run_date = parse_date_from_dirname(date_dir.name)
        except ValueError:
            logger.warning(f"Skipping directory with invalid date format: {date_dir.name}")
            continue

        logger.info(f"\nProcessing date: {date_dir.name}")

        # Process files in directory
        for filepath in date_dir.iterdir():
            if filepath.suffix != '.xlsx':
                continue

            fname_lower = filepath.name.lower()

            # Tanium tagging results
            if 'tanium_ring_tagging_results' in fname_lower:
                result = process_tanium_tagging_results(filepath, run_date, dry_run)
                if result.get('skipped'):
                    stats['skipped'] += 1
                elif 'run_id' in result or dry_run:
                    stats['tanium_runs'] += 1
                    stats['tanium_devices'] += result.get('total_devices', 0)

            # CrowdStrike tagging results
            elif 'epp-falcon ring tagging' in fname_lower:
                result = process_crowdstrike_tagging_results(filepath, run_date, dry_run)
                if result.get('skipped'):
                    stats['skipped'] += 1
                elif 'run_id' in result or dry_run:
                    stats['cs_runs'] += 1
                    stats['cs_devices'] += result.get('total_devices', 0)

    # Print summary
    logger.info("\n" + "=" * 60)
    logger.info("MIGRATION SUMMARY")
    logger.info("=" * 60)
    logger.info(f"Tanium runs processed: {stats['tanium_runs']}")
    logger.info(f"Tanium devices: {stats['tanium_devices']:,}")
    logger.info(f"CrowdStrike runs processed: {stats['cs_runs']}")
    logger.info(f"CrowdStrike devices: {stats['cs_devices']:,}")
    logger.info(f"Total devices: {stats['tanium_devices'] + stats['cs_devices']:,}")
    logger.info(f"Skipped (already exists): {stats['skipped']}")
    logger.info("=" * 60)

    if not dry_run:
        # Update run_by for historical data
        logger.info("\nUpdating run_by for historical data...")
        run_by_result = update_run_by_for_historical_data()
        logger.info(f"  - Recent runs (last 7 days) set to 'scheduled job': {run_by_result['recent_updated']}")
        logger.info(f"  - Older runs set to 'Ashok': {run_by_result['older_updated']}")

        # Print database summary
        db_stats = get_summary_stats()
        logger.info("\nDATABASE SUMMARY:")
        logger.info(f"Total runs in DB: {db_stats['total_runs']}")
        logger.info(f"Total devices in DB: {db_stats['total_devices']:,}")
        logger.info(f"Total tagged in DB: {db_stats['total_tagged']:,}")
        logger.info(f"Date range: {db_stats['earliest_date']} to {db_stats['latest_date']}")


def main():
    parser = argparse.ArgumentParser(description='Migrate EPP tagging data to SQLite database')
    parser.add_argument('--dry-run', action='store_true', help='Preview migration without writing to database')
    args = parser.parse_args()

    migrate_all(dry_run=args.dry_run)


if __name__ == '__main__':
    main()
