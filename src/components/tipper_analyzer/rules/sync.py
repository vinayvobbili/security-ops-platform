"""Sync logic for the detection rules catalog.

Orchestrates parallel fetching from all platforms and upserting into ChromaDB.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from .catalog import RulesCatalog
from .fetchers import get_fetcher, get_all_platforms
from .models import DetectionRule, PlatformSyncStatus, CatalogSyncResult

logger = logging.getLogger(__name__)


def sync_catalog(platforms: Optional[List[str]] = None, full_rebuild: bool = False) -> CatalogSyncResult:
    """Sync detection rules from platforms into the ChromaDB catalog.

    Fetches rules from specified platforms (or all) in parallel,
    then upserts them into the catalog.

    Args:
        platforms: List of platform names to sync (default: all)
        full_rebuild: If True, delete and rebuild the entire catalog

    Returns:
        CatalogSyncResult with per-platform stats
    """
    target_platforms = platforms or get_all_platforms()
    catalog = RulesCatalog()
    result = CatalogSyncResult()

    # Fetch rules from all platforms in parallel
    all_rules: List[DetectionRule] = []
    platform_statuses: List[PlatformSyncStatus] = []

    logger.info(f"Syncing rules catalog from: {', '.join(target_platforms)}")

    with ThreadPoolExecutor(max_workers=3) as executor:
        future_to_platform = {}
        for platform in target_platforms:
            try:
                fetcher = get_fetcher(platform)
                future = executor.submit(fetcher)
                future_to_platform[future] = platform
            except ValueError as e:
                platform_statuses.append(PlatformSyncStatus(
                    platform=platform, success=False, error=str(e)
                ))

        for future in as_completed(future_to_platform):
            platform = future_to_platform[future]
            try:
                rules = future.result()
                all_rules.extend(rules)
                platform_statuses.append(PlatformSyncStatus(
                    platform=platform,
                    success=True,
                    rules_fetched=len(rules),
                ))
                logger.info(f"  {platform}: {len(rules)} rules fetched")
            except Exception as e:
                logger.error(f"  {platform}: fetch failed: {e}")
                platform_statuses.append(PlatformSyncStatus(
                    platform=platform, success=False, error=str(e)
                ))

    # Upsert into catalog
    if all_rules:
        if full_rebuild:
            upserted = catalog.rebuild(all_rules)
        else:
            upserted = catalog.upsert_rules(all_rules)

        # Update stats with upsert counts
        for status in platform_statuses:
            if status.success:
                status.rules_upserted = status.rules_fetched  # All fetched rules are upserted
    else:
        upserted = 0
        logger.warning("No rules fetched from any platform")

    result.platforms = platform_statuses
    result.total_rules = len(all_rules)
    result.total_upserted = upserted

    logger.info(f"Sync complete: {result.total_rules} rules fetched, {result.total_upserted} upserted")
    return result
