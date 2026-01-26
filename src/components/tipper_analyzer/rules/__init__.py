"""Detection Rules Catalog - searchable index of rules from QRadar, CrowdStrike, and Tanium.

Public API:
    search_rules(query, k, platform) - Search the catalog
    sync_catalog(platforms, full_rebuild) - Sync rules from platforms
    get_catalog_stats() - Get catalog statistics
"""

from typing import List, Optional, Dict

from .catalog import RulesCatalog
from .models import RuleCatalogSearchResult, CatalogSyncResult
from .sync import sync_catalog  # noqa: F401


def search_rules(query: str, k: int = 10, platform: str = None) -> RuleCatalogSearchResult:
    """Search the detection rules catalog.

    Args:
        query: Search query (malware name, actor, technique, etc.)
        k: Number of results to return
        platform: Optional platform filter ("qradar", "crowdstrike", "tanium")

    Returns:
        RuleCatalogSearchResult with matched rules
    """
    catalog = RulesCatalog()
    return catalog.search(query, k=k, platform=platform)


def get_catalog_stats() -> Dict:
    """Get detection rules catalog statistics.

    Returns:
        Dict with total count, platform breakdown, status
    """
    catalog = RulesCatalog()
    return catalog.get_stats()
