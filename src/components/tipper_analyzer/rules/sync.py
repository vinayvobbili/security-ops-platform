"""Sync logic for the detection rules catalog.

Orchestrates parallel fetching from all platforms, caching results locally,
and upserting into ChromaDB.

The sync follows this strategy for each platform:
1. Try to fetch fresh rules from API
2. On success: merge with existing cache and save
3. On failure: fall back to cached rules
4. Upsert all rules to ChromaDB

This ensures the catalog remains populated even when APIs are unavailable.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Tuple

from .cache import save_rules_to_cache, load_rules_from_cache, merge_rules
from .catalog import RulesCatalog
from .fetchers import get_fetcher, get_all_platforms
from .models import DetectionRule, PlatformSyncStatus, CatalogSyncResult

logger = logging.getLogger(__name__)


def _fetch_with_cache_fallback(platform: str) -> Tuple[List[DetectionRule], bool, str]:
    """Fetch rules for a platform with cache fallback.

    Args:
        platform: Platform name

    Returns:
        Tuple of (rules, success, error_message)
        - success=True means fresh data from API
        - success=False with rules means cache fallback
        - success=False with empty rules means total failure
    """
    rules = []
    api_error = ""

    # Try API fetch first
    try:
        fetcher = get_fetcher(platform)
        rules = fetcher()

        if rules:
            # API succeeded - merge with existing cache and save
            existing = load_rules_from_cache(platform) or []
            if existing:
                merged = merge_rules(existing, rules)
                logger.info(f"{platform}: Merged {len(rules)} API rules with {len(existing)} cached -> {len(merged)} total")
                rules = merged

            save_rules_to_cache(platform, rules)
            return rules, True, ""

        # API returned empty - this might be an error or genuinely empty
        api_error = "API returned no rules"

    except Exception as e:
        api_error = str(e)
        logger.warning(f"{platform}: API fetch failed: {api_error}")

    # Fall back to cache
    cached_rules = load_rules_from_cache(platform)
    if cached_rules:
        logger.info(f"{platform}: Using {len(cached_rules)} cached rules (API failed: {api_error})")
        return cached_rules, False, f"Using cache (API: {api_error})"

    # No cache available either
    logger.error(f"{platform}: No rules available (API failed, no cache)")
    return [], False, api_error


def sync_catalog(platforms: Optional[List[str]] = None, full_rebuild: bool = False) -> CatalogSyncResult:
    """Sync detection rules from platforms into the ChromaDB catalog.

    For each platform:
    1. Attempts to fetch fresh rules from API
    2. On success: merges with cache, saves updated cache
    3. On failure: falls back to cached rules
    4. Upserts all available rules to ChromaDB

    This ensures the catalog stays populated even when some APIs are unavailable.

    Args:
        platforms: List of platform names to sync (default: all)
        full_rebuild: If True, delete and rebuild the entire catalog

    Returns:
        CatalogSyncResult with per-platform stats
    """
    target_platforms = platforms or get_all_platforms()
    catalog = RulesCatalog()
    result = CatalogSyncResult()

    all_rules: List[DetectionRule] = []
    platform_statuses: List[PlatformSyncStatus] = []

    logger.info(f"Syncing rules catalog from: {', '.join(target_platforms)}")

    # Fetch rules from all platforms in parallel
    with ThreadPoolExecutor(max_workers=3) as executor:
        future_to_platform = {
            executor.submit(_fetch_with_cache_fallback, platform): platform
            for platform in target_platforms
        }

        for future in as_completed(future_to_platform):
            platform = future_to_platform[future]
            try:
                rules, api_success, error_msg = future.result()

                if rules:
                    all_rules.extend(rules)
                    status_msg = "API" if api_success else "cache"
                    logger.info(f"  {platform}: {len(rules)} rules ({status_msg})")

                platform_statuses.append(PlatformSyncStatus(
                    platform=platform,
                    success=bool(rules),  # Success if we have rules (from API or cache)
                    rules_fetched=len(rules),
                    error=error_msg if not rules else "",
                ))

            except Exception as e:
                logger.error(f"  {platform}: unexpected error: {e}")
                platform_statuses.append(PlatformSyncStatus(
                    platform=platform, success=False, error=str(e)
                ))

    # Upsert into catalog
    if all_rules:
        if full_rebuild:
            upserted = catalog.rebuild(all_rules)
        else:
            upserted = catalog.upsert_rules(all_rules)

        for status in platform_statuses:
            if status.rules_fetched > 0:
                status.rules_upserted = status.rules_fetched
    else:
        upserted = 0
        logger.warning("No rules fetched from any platform (APIs failed, no caches)")

    result.platforms = platform_statuses
    result.total_rules = len(all_rules)
    result.total_upserted = upserted

    # Log summary
    api_ok = sum(1 for s in platform_statuses if s.success and not s.error)
    cache_ok = sum(1 for s in platform_statuses if s.success and s.error)
    failed = sum(1 for s in platform_statuses if not s.success)

    logger.info(
        f"Sync complete: {result.total_rules} rules "
        f"(API: {api_ok}, cache: {cache_ok}, failed: {failed})"
    )
    return result
