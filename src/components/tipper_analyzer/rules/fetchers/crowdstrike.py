"""CrowdStrike detection rules fetcher.

Fetches custom IOA rule groups, IOC indicators, and Intel YARA rules from
CrowdStrike Falcon, normalizing them into DetectionRule objects.
"""

import logging
from typing import List

from ..models import DetectionRule
from . import register_fetcher
from .qradar import _extract_threat_context  # Reuse shared extraction logic

logger = logging.getLogger(__name__)

# Severity mapping for CrowdStrike
CS_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
}


@register_fetcher("crowdstrike")
def fetch_crowdstrike_rules() -> List[DetectionRule]:
    """Fetch custom IOA rule groups, IOC indicators, and Intel YARA rules from CrowdStrike."""
    from services.crowdstrike import CrowdStrikeClient

    rules = []

    try:
        client = CrowdStrikeClient()
    except Exception as e:
        logger.warning(f"CrowdStrike client initialization failed: {e}")
        return rules

    # Fetch Custom IOA Rule Groups
    logger.info("Fetching CrowdStrike custom IOA rule groups...")
    result = client.list_custom_ioa_rule_groups()
    if "error" not in result:
        for group in result.get("rule_groups", []):
            group_name = group.get("name", "")
            group_desc = group.get("description", "")
            group_enabled = group.get("enabled", True)

            # Each group contains multiple rules
            for rule in group.get("rules", []):
                rule_name = rule.get("name", "") or group_name
                rule_desc = rule.get("description", "") or group_desc
                search_text = f"{rule_name} {rule_desc} {group_name} {group_desc}"
                context = _extract_threat_context(search_text)

                severity = CS_SEVERITY_MAP.get(
                    rule.get("severity_name", "").lower(),
                    rule.get("disposition_id_name", "").lower()
                )

                rules.append(DetectionRule(
                    rule_id=f"cs-ioa-{rule.get('instance_id', group.get('id', ''))}",
                    platform="crowdstrike",
                    name=f"{group_name}: {rule_name}" if rule_name != group_name else rule_name,
                    description=rule_desc,
                    rule_type="ioa_rule",
                    enabled=group_enabled and rule.get("enabled", True),
                    severity=severity or "",
                    tags=[group.get("platform", ""), group.get("rule_type_name", "")],
                    malware_families=context["malware"],
                    threat_actors=context["actors"],
                    mitre_techniques=context["mitre"],
                    created_date=rule.get("created_on", ""),
                    modified_date=rule.get("modified_on", ""),
                ))

            # If group has no individual rules, add the group itself
            if not group.get("rules"):
                context = _extract_threat_context(f"{group_name} {group_desc}")
                rules.append(DetectionRule(
                    rule_id=f"cs-ioa-group-{group.get('id', '')}",
                    platform="crowdstrike",
                    name=group_name,
                    description=group_desc,
                    rule_type="ioa_rule",
                    enabled=group_enabled,
                    severity="",
                    tags=[group.get("platform", "")],
                    malware_families=context["malware"],
                    threat_actors=context["actors"],
                    mitre_techniques=context["mitre"],
                    created_date=group.get("created_on", ""),
                    modified_date=group.get("modified_on", ""),
                ))

        logger.info(f"Fetched {len(result.get('rule_groups', []))} IOA rule groups")
    else:
        logger.warning(f"Failed to fetch IOA rule groups: {result['error']}")

    # Fetch Custom IOC Indicators
    logger.info("Fetching CrowdStrike IOC indicators...")
    result = client.list_ioc_indicators(limit=500)
    if "error" not in result:
        for indicator in result.get("indicators", []):
            value = indicator.get("value", "")
            ioc_type = indicator.get("type", "")
            description = indicator.get("description", "") or ""
            search_text = f"{value} {description} {indicator.get('source', '')}"
            context = _extract_threat_context(search_text)

            # Map IOC action to severity
            action = indicator.get("action", "").lower()
            severity_from_action = {
                "prevent": "critical",
                "detect": "high",
                "allow": "low",
            }.get(action, "medium")

            tags_list = indicator.get("tags", []) or []

            rules.append(DetectionRule(
                rule_id=f"cs-ioc-{indicator.get('id', '')}",
                platform="crowdstrike",
                name=f"IOC: {value}" if len(value) < 80 else f"IOC: {value[:77]}...",
                description=description,
                rule_type="ioc",
                enabled=not indicator.get("expired", False),
                severity=severity_from_action,
                tags=tags_list if isinstance(tags_list, list) else [tags_list],
                malware_families=context["malware"],
                threat_actors=context["actors"],
                mitre_techniques=context["mitre"],
                created_date=indicator.get("created_on", ""),
                modified_date=indicator.get("modified_on", ""),
            ))

        logger.info(f"Fetched {len(result.get('indicators', []))} IOC indicators")
    else:
        logger.warning(f"Failed to fetch IOC indicators: {result['error']}")

    # Fetch Intel YARA Rules
    logger.info("Fetching CrowdStrike Intel YARA rules...")
    result = client.list_intel_yara_rules(limit=500)
    if "error" not in result:
        for rule in result.get("rules", []):
            rule_name = rule.get("name", "")
            rule_desc = rule.get("description", "") or ""
            search_text = f"{rule_name} {rule_desc}"
            context = _extract_threat_context(search_text)

            rules.append(DetectionRule(
                rule_id=f"cs-yara-{rule.get('id', '')}",
                platform="crowdstrike",
                name=rule_name,
                description=rule_desc,
                rule_type="yara_rule",
                enabled=True,
                severity="medium",
                tags=[rule.get("ruletype", ""), rule.get("customer_id", "")],
                malware_families=context["malware"],
                threat_actors=context["actors"],
                mitre_techniques=context["mitre"],
                created_date=rule.get("created_date", ""),
                modified_date=rule.get("last_modified_date", ""),
            ))

        logger.info(f"Fetched {len(result.get('rules', []))} Intel YARA rules")
    else:
        logger.warning(f"Failed to fetch Intel YARA rules: {result['error']}")

    logger.info(f"Total CrowdStrike rules: {len(rules)}")
    return rules
