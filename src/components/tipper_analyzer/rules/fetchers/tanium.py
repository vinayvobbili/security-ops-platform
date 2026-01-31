"""Tanium detection rules fetcher.

Fetches Threat Response signals from Tanium,
normalizing them into DetectionRule objects.

Supports both API fetching and CSV import for when API access is unavailable.
"""

import csv
import hashlib
import logging
from pathlib import Path
from typing import List, Optional

from ..models import DetectionRule
from . import register_fetcher
from .qradar import _extract_threat_context  # Reuse shared extraction logic

logger = logging.getLogger(__name__)

# Default CSV path for Tanium signals catalog
DEFAULT_CSV_PATH = Path(__file__).parent.parent.parent.parent.parent.parent / "data" / "tanium_signals_catalog.csv"

# Tanium severity mapping (numeric to label)
TANIUM_SEVERITY_MAP = {
    1: "low",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
}


def fetch_tanium_rules_from_csv(csv_path: Optional[Path] = None) -> List[DetectionRule]:
    """Import Tanium signals from a CSV export.

    The CSV should have columns: name, description, platforms, technique_id, technique_name

    Since the same signal can have multiple rows (one per MITRE technique),
    this function aggregates techniques per unique signal name.

    Args:
        csv_path: Path to the CSV file. Defaults to data/tanium_signals_catalog.csv

    Returns:
        List of DetectionRule objects
    """
    csv_path = csv_path or DEFAULT_CSV_PATH

    if not csv_path.exists():
        logger.warning(f"Tanium CSV not found at {csv_path}")
        return []

    logger.info(f"Loading Tanium signals from CSV: {csv_path}")

    # First pass: aggregate techniques per signal name
    signals_map: dict = {}  # name -> {description, platforms, techniques}

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = row.get("name", "").strip()
            if not name:
                continue

            if name not in signals_map:
                signals_map[name] = {
                    "description": row.get("description", "").strip(),
                    "platforms": set(),
                    "techniques": [],  # List of (id, name) tuples
                }

            # Add platforms
            platforms_str = row.get("platforms", "")
            for p in platforms_str.split(","):
                p = p.strip().lower()
                if p:
                    signals_map[name]["platforms"].add(p)

            # Add technique if present
            technique_id = row.get("technique_id", "").strip()
            technique_name = row.get("technique_name", "").strip()
            if technique_id:
                signals_map[name]["techniques"].append((technique_id, technique_name))

    # Second pass: create DetectionRule objects
    rules = []
    for name, data in signals_map.items():
        # Generate stable rule ID from name
        name_hash = hashlib.md5(name.encode()).hexdigest()[:8]
        rule_id = f"tanium-signal-{name_hash}"

        description = data["description"]
        search_text = f"{name} {description}"
        context = _extract_threat_context(search_text)

        # Collect unique MITRE technique IDs
        mitre_techniques = list(set(
            context["mitre"] + [t[0] for t in data["techniques"] if t[0]]
        ))

        # Use platforms as tags
        platforms = sorted(data["platforms"]) if data["platforms"] else ["windows"]

        rules.append(DetectionRule(
            rule_id=rule_id,
            platform="tanium",
            name=name,
            description=description,
            rule_type="signal",
            enabled=True,
            severity="medium",  # CSV doesn't include severity
            tags=platforms,
            malware_families=context["malware"],
            threat_actors=context["actors"],
            mitre_techniques=mitre_techniques,
            created_date="",
            modified_date="",
        ))

    logger.info(f"Loaded {len(rules)} Tanium signals from CSV")
    return rules


@register_fetcher("tanium")
def fetch_tanium_rules() -> List[DetectionRule]:
    """Fetch Threat Response signals from Tanium.

    Tries API first, falls back to CSV import if API is unavailable.
    """
    from services.tanium import TaniumClient

    rules = []

    try:
        client = TaniumClient()
    except Exception as e:
        logger.warning(f"Tanium client initialization failed: {e}")
        logger.info("Falling back to CSV import...")
        return fetch_tanium_rules_from_csv()

    if not client.instances:
        logger.warning("No Tanium instances available")
        logger.info("Falling back to CSV import...")
        return fetch_tanium_rules_from_csv()

    logger.info("Fetching Tanium Threat Response signals...")
    result = client.list_all_signals()

    if "error" in result:
        logger.warning(f"Failed to fetch Tanium signals: {result['error']}")
        logger.info("Falling back to CSV import...")
        return fetch_tanium_rules_from_csv()

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
