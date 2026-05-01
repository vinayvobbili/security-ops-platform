"""Microsoft Defender (XDR) detection rules fetcher.

Fetches Custom Detection Rules and Threat Intelligence indicators from
Microsoft Graph and normalizes them into DetectionRule objects.
"""

import logging
from typing import List

from ..models import DetectionRule
from . import register_fetcher
from .qradar import _extract_threat_context  # Reuse shared extraction logic

logger = logging.getLogger(__name__)

# Microsoft Defender severity values map 1:1 to ours, but lowercase them defensively.
DEFENDER_SEVERITY_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
}

# Map TI-indicator action -> our severity (mirrors crowdstrike fetcher's choice).
INDICATOR_ACTION_TO_SEVERITY = {
    "block": "critical",
    "alert": "high",
    "alertandblock": "critical",
    "allow": "low",
    "audit": "medium",
}


@register_fetcher("defender")
def fetch_defender_rules() -> List[DetectionRule]:
    """Fetch custom detection rules + TI indicators from Microsoft Defender."""
    from services.defender import DefenderClient

    rules: List[DetectionRule] = []

    try:
        client = DefenderClient()
    except Exception as e:
        logger.warning(f"Defender client initialization failed: {e}")
        return rules

    if not client.is_configured():
        logger.warning("Defender not configured, skipping")
        return rules

    # --- Custom detection rules ---
    logger.info("Fetching Defender custom detection rules...")
    result = client.list_custom_detection_rules()
    if "error" not in result:
        for rule in result.get("rules", []):
            name = rule.get("displayName", "")
            alert_tpl = rule.get("detectionAction", {}).get("alertTemplate", {}) or {}
            description = alert_tpl.get("description", "") or ""

            # MITRE techniques are returned as IDs already (e.g. "T1059.001").
            mitre_ids = alert_tpl.get("mitreTechniques", []) or []
            categories = alert_tpl.get("category", "")
            if isinstance(categories, str) and categories:
                categories = [categories]
            elif not isinstance(categories, list):
                categories = []

            search_text = f"{name} {description} {' '.join(categories)}"
            context = _extract_threat_context(search_text)

            severity_raw = (alert_tpl.get("severity") or "").lower()

            rules.append(DetectionRule(
                rule_id=f"defender-rule-{rule.get('id', '')}",
                platform="defender",
                name=name,
                description=description,
                rule_type="custom_detection",
                enabled=rule.get("isEnabled", True),
                severity=DEFENDER_SEVERITY_MAP.get(severity_raw, severity_raw or ""),
                tags=categories,
                malware_families=context["malware"],
                threat_actors=context["actors"],
                # Prefer Defender's own MITRE labels; fall back to regex extraction.
                mitre_techniques=mitre_ids or context["mitre"],
                created_date=rule.get("createdDateTime", ""),
                modified_date=rule.get("lastModifiedDateTime", ""),
            ))
        logger.info(f"Fetched {len(result.get('rules', []))} custom detection rules")
    else:
        logger.warning(f"Failed to fetch Defender custom detections: {result['error']}")

    # --- TI indicators ---
    logger.info("Fetching Defender threat-intel indicators...")
    result = client.list_indicators()
    if "error" not in result:
        for ind in result.get("indicators", []):
            description = ind.get("description", "") or ""
            # Pick whichever observable field is populated.
            value = (
                ind.get("fileHashValue")
                or ind.get("networkDestinationIPv4")
                or ind.get("networkDestinationIPv6")
                or ind.get("domainName")
                or ind.get("url")
                or ind.get("emailSenderAddress")
                or ""
            )
            kill_chain = ind.get("killChain", []) or []
            tags_list = ind.get("tags", []) or []

            search_text = f"{value} {description} {' '.join(kill_chain)}"
            context = _extract_threat_context(search_text)

            action = (ind.get("action", "") or "").lower()
            severity = INDICATOR_ACTION_TO_SEVERITY.get(action, "medium")

            display_name = f"IOC: {value}" if value else f"IOC: {ind.get('id', '')}"
            if len(display_name) > 80:
                display_name = display_name[:77] + "..."

            rules.append(DetectionRule(
                rule_id=f"defender-ioc-{ind.get('id', '')}",
                platform="defender",
                name=display_name,
                description=description,
                rule_type="ioc",
                # Microsoft Graph filters expired indicators server-side, so
                # anything we get back is considered active.
                enabled=True,
                severity=severity,
                tags=tags_list if isinstance(tags_list, list) else [str(tags_list)],
                malware_families=context["malware"],
                threat_actors=context["actors"],
                mitre_techniques=context["mitre"],
                created_date=ind.get("ingestedDateTime", ""),
                modified_date=ind.get("lastReportedDateTime", ""),
            ))
        logger.info(f"Fetched {len(result.get('indicators', []))} TI indicators")
    else:
        logger.warning(f"Failed to fetch Defender indicators: {result['error']}")

    logger.info(f"Total Defender rules: {len(rules)}")
    return rules
