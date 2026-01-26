"""QRadar detection rules fetcher.

Fetches custom analytics rules and saved searches from QRadar,
normalizing them into DetectionRule objects.
"""

import logging
import re
from typing import List

from ..models import DetectionRule
from . import register_fetcher

logger = logging.getLogger(__name__)

# Patterns for extracting threat context from rule names/descriptions
MALWARE_PATTERNS = re.compile(
    r'\b(emotet|trickbot|cobalt\s*strike|qakbot|qbot|icedid|bumblebee|'
    r'raspberry\s*robin|socgholish|gootloader|dridex|ryuk|conti|lockbit|'
    r'blackcat|alphv|royal|clop|revil|sodinokibi|darkside|babuk|hive|'
    r'maze|ragnar\s*locker|blackmatter|avos\s*locker|play|nokoyawa|'
    r'mimikatz|lazagne|bloodhound|sharphound|rubeus|certify|sliver|'
    r'brute\s*ratel|mythic|havoc|nighthawk|silver|merlin|poshc2)\b',
    re.IGNORECASE
)

ACTOR_PATTERNS = re.compile(
    r'\b(APT\d+|UNC\d+|FIN\d+|TA\d+|DEV-\d+|TEMP\.\w+|'
    r'lazarus|kimsuky|turla|fancy\s*bear|cozy\s*bear|'
    r'wizard\s*spider|scattered\s*spider|lapsus|'
    r'sandworm|gamaredon|nobelium|hafnium|volt\s*typhoon|'
    r'charcoal\s*typhoon|forest\s*blizzard|midnight\s*blizzard)\b',
    re.IGNORECASE
)

MITRE_PATTERN = re.compile(r'\b(T\d{4}(?:\.\d{3})?)\b')


def _extract_threat_context(text: str) -> dict:
    """Extract malware families, threat actors, and MITRE techniques from text."""
    malware = list(set(m.group(0).lower() for m in MALWARE_PATTERNS.finditer(text)))
    actors = list(set(m.group(0) for m in ACTOR_PATTERNS.finditer(text)))
    mitre = list(set(m.group(0) for m in MITRE_PATTERN.finditer(text)))
    return {"malware": malware, "actors": actors, "mitre": mitre}


@register_fetcher("qradar")
def fetch_qradar_rules() -> List[DetectionRule]:
    """Fetch custom rules and saved searches from QRadar."""
    from services.qradar import QRadarClient

    rules = []
    client = QRadarClient()

    if not client.is_configured():
        logger.warning("QRadar not configured, skipping")
        return rules

    # Fetch custom analytics rules
    logger.info("Fetching QRadar custom analytics rules...")
    result = client.list_analytics_rules(origin="USER")
    if "error" not in result:
        for rule in result.get("rules", []):
            name = rule.get("name", "")
            notes = rule.get("notes", "")
            search_text = f"{name} {notes}"
            context = _extract_threat_context(search_text)

            rules.append(DetectionRule(
                rule_id=f"qradar-rule-{rule.get('id', '')}",
                platform="qradar",
                name=name,
                description=notes,
                rule_type="custom_rule",
                enabled=rule.get("enabled", True),
                severity="",  # QRadar rules don't have severity in the API response
                tags=[],
                malware_families=context["malware"],
                threat_actors=context["actors"],
                mitre_techniques=context["mitre"],
                created_date=rule.get("creation_date", ""),
                modified_date=rule.get("modification_date", ""),
            ))
        logger.info(f"Fetched {len(result.get('rules', []))} custom analytics rules")
    else:
        logger.warning(f"Failed to fetch QRadar rules: {result['error']}")

    # Fetch saved searches
    logger.info("Fetching QRadar saved searches...")
    result = client.list_saved_searches()
    if "error" not in result:
        for search in result.get("searches", []):
            name = search.get("name", "")
            description = search.get("description", "") or ""
            aql = search.get("aql", "") or ""
            search_text = f"{name} {description} {aql}"
            context = _extract_threat_context(search_text)

            rules.append(DetectionRule(
                rule_id=f"qradar-search-{search.get('id', '')}",
                platform="qradar",
                name=name,
                description=description,
                rule_type="saved_search",
                enabled=True,  # Saved searches are always "enabled"
                tags=[],
                malware_families=context["malware"],
                threat_actors=context["actors"],
                mitre_techniques=context["mitre"],
                created_date="",
                modified_date="",
            ))
        logger.info(f"Fetched {len(result.get('searches', []))} saved searches")
    else:
        logger.warning(f"Failed to fetch QRadar saved searches: {result['error']}")

    logger.info(f"Total QRadar rules: {len(rules)}")
    return rules
