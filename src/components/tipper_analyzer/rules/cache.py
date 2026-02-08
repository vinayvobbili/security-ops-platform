"""Local cache layer for detection rules.

Provides persistent JSON caching for rules from each platform.
This allows the sync job to gracefully handle API failures by
falling back to cached data.
"""

import json
import logging
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from .models import DetectionRule

logger = logging.getLogger(__name__)

# Cache directory
CACHE_DIR = Path(__file__).parent.parent.parent.parent.parent / "data" / "rules_cache"


def _get_cache_path(platform: str) -> Path:
    """Get the cache file path for a platform."""
    return CACHE_DIR / f"{platform}_rules.json"


def _rule_to_dict(rule: DetectionRule) -> Dict[str, Any]:
    """Convert DetectionRule to a JSON-serializable dict."""
    return {
        "rule_id": rule.rule_id,
        "platform": rule.platform,
        "name": rule.name,
        "description": rule.description,
        "rule_type": rule.rule_type,
        "enabled": rule.enabled,
        "severity": rule.severity,
        "tags": rule.tags,
        "malware_families": rule.malware_families,
        "threat_actors": rule.threat_actors,
        "mitre_techniques": rule.mitre_techniques,
        "created_date": rule.created_date,
        "modified_date": rule.modified_date,
    }


def _dict_to_rule(data: Dict[str, Any]) -> DetectionRule:
    """Convert a dict back to DetectionRule."""
    return DetectionRule(
        rule_id=data.get("rule_id", ""),
        platform=data.get("platform", ""),
        name=data.get("name", ""),
        description=data.get("description", ""),
        rule_type=data.get("rule_type", ""),
        enabled=data.get("enabled", True),
        severity=data.get("severity", ""),
        tags=data.get("tags", []),
        malware_families=data.get("malware_families", []),
        threat_actors=data.get("threat_actors", []),
        mitre_techniques=data.get("mitre_techniques", []),
        created_date=data.get("created_date", ""),
        modified_date=data.get("modified_date", ""),
    )


def save_rules_to_cache(platform: str, rules: List[DetectionRule]) -> bool:
    """Save rules to the local cache file.

    Args:
        platform: Platform name (qradar, crowdstrike, tanium)
        rules: List of DetectionRule objects

    Returns:
        True if saved successfully
    """
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_path = _get_cache_path(platform)

        cache_data = {
            "platform": platform,
            "updated_at": datetime.now(UTC).isoformat() + "Z",
            "count": len(rules),
            "rules": [_rule_to_dict(r) for r in rules],
        }

        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cache_data, f, indent=2)

        logger.info(f"Saved {len(rules)} {platform} rules to cache: {cache_path}")
        return True

    except Exception as e:
        logger.error(f"Failed to save {platform} rules to cache: {e}")
        return False


def load_rules_from_cache(platform: str) -> Optional[List[DetectionRule]]:
    """Load rules from the local cache file.

    Args:
        platform: Platform name

    Returns:
        List of DetectionRule objects, or None if cache doesn't exist/is invalid
    """
    cache_path = _get_cache_path(platform)

    if not cache_path.exists():
        logger.debug(f"No cache file found for {platform}: {cache_path}")
        return None

    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            cache_data = json.load(f)

        rules = [_dict_to_rule(r) for r in cache_data.get("rules", [])]
        updated_at = cache_data.get("updated_at", "unknown")

        logger.info(f"Loaded {len(rules)} {platform} rules from cache (updated: {updated_at})")
        return rules

    except Exception as e:
        logger.error(f"Failed to load {platform} rules from cache: {e}")
        return None


def get_cache_stats() -> Dict[str, Any]:
    """Get statistics about all cached platforms.

    Returns:
        Dict with per-platform stats
    """
    stats = {}

    if not CACHE_DIR.exists():
        return {"status": "no_cache_dir", "platforms": {}}

    for platform in ["qradar", "crowdstrike", "tanium"]:
        cache_path = _get_cache_path(platform)

        if not cache_path.exists():
            stats[platform] = {"exists": False, "count": 0}
            continue

        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cache_data = json.load(f)

            stats[platform] = {
                "exists": True,
                "count": cache_data.get("count", 0),
                "updated_at": cache_data.get("updated_at", "unknown"),
                "file_size_kb": round(cache_path.stat().st_size / 1024, 1),
            }
        except Exception as e:
            stats[platform] = {"exists": True, "error": str(e)}

    return {"status": "ready", "platforms": stats}


def merge_rules(existing: List[DetectionRule], new_rules: List[DetectionRule]) -> List[DetectionRule]:
    """Merge new rules into existing, updating by rule_id.

    This allows incremental updates where new API results
    update/add to the cache without losing rules that may
    have been removed from API results temporarily.

    Args:
        existing: Current cached rules
        new_rules: Fresh rules from API

    Returns:
        Merged list with updates applied
    """
    rules_by_id = {r.rule_id: r for r in existing}

    # Update/add new rules
    for rule in new_rules:
        rules_by_id[rule.rule_id] = rule

    return list(rules_by_id.values())
