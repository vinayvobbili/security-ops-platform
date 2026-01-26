"""Tanium detection rules fetcher.

Fetches Threat Response signals from Tanium,
normalizing them into DetectionRule objects.
"""

import logging
from typing import List

from ..models import DetectionRule
from . import register_fetcher
from .qradar import _extract_threat_context  # Reuse shared extraction logic

logger = logging.getLogger(__name__)

# Tanium severity mapping (numeric to label)
TANIUM_SEVERITY_MAP = {
    1: "low",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
}


@register_fetcher("tanium")
def fetch_tanium_rules() -> List[DetectionRule]:
    """Fetch Threat Response signals from Tanium."""
    from services.tanium import TaniumClient

    rules = []

    try:
        client = TaniumClient()
    except Exception as e:
        logger.warning(f"Tanium client initialization failed: {e}")
        return rules

    if not client.instances:
        logger.warning("No Tanium instances available, skipping")
        return rules

    logger.info("Fetching Tanium Threat Response signals...")
    result = client.list_all_signals()

    if "error" in result:
        logger.warning(f"Failed to fetch Tanium signals: {result['error']}")
        return rules

    for signal in result.get("signals", []):
        name = signal.get("name", "")
        description = signal.get("description", "") or ""
        search_text = f"{name} {description}"
        context = _extract_threat_context(search_text)

        # Extract MITRE techniques from both the text and dedicated fields
        mitre_techniques = list(set(
            context["mitre"] +
            (signal.get("mitreTechniques") or [])
        ))

        # Map numeric severity
        severity_num = signal.get("severity")
        if isinstance(severity_num, int):
            severity = TANIUM_SEVERITY_MAP.get(severity_num, "medium")
        elif isinstance(severity_num, str):
            severity = severity_num.lower() if severity_num.lower() in ("low", "medium", "high", "critical") else "medium"
        else:
            severity = "medium"

        # Use MITRE tactics as tags
        tactics = signal.get("mitreTactics") or []

        rules.append(DetectionRule(
            rule_id=f"tanium-signal-{signal.get('id', '')}",
            platform="tanium",
            name=name,
            description=description,
            rule_type="signal",
            enabled=signal.get("enabled", True),
            severity=severity,
            tags=tactics,
            malware_families=context["malware"],
            threat_actors=context["actors"],
            mitre_techniques=mitre_techniques,
            created_date=signal.get("createdAt", ""),
            modified_date=signal.get("updatedAt", ""),
        ))

    logger.info(f"Total Tanium signals: {len(rules)}")
    return rules
