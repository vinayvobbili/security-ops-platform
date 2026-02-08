"""
Tanium Signals Catalog Sync

Fetches Threat Response signals from Tanium Cloud instance
using the dedicated signals API token, and rebuilds the local CSV catalog.

Note: On-Prem does not have Threat Response installed, so only Cloud is used.

Runs daily at 6 AM ET to keep the catalog fresh for tipper analysis.

Usage:
    # Manual sync
    python -m src.components.tanium_signals_sync

    # Scheduled via all_jobs.py
"""

import csv
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from my_config import get_config
from services.tanium import TaniumInstance

# Import for ChromaDB catalog update
from src.components.tipper_analyzer.rules.fetchers.tanium import fetch_tanium_rules_from_csv
from src.components.tipper_analyzer.rules.catalog import RulesCatalog

logger = logging.getLogger(__name__)

# Output path for the signals catalog
ROOT_DIRECTORY = Path(__file__).parent.parent.parent
SIGNALS_CATALOG_PATH = ROOT_DIRECTORY / "data" / "tanium_signals_catalog.csv"


@dataclass
class TaniumSignal:
    """Represents a Tanium Threat Response signal."""
    id: str
    name: str
    description: str
    severity: int
    enabled: bool
    platforms: List[str]
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    created_at: str
    updated_at: str
    source: str  # "Cloud" or "On-Prem"


class TaniumSignalsClient:
    """Client for fetching signals from Tanium using dedicated signals API tokens."""

    def __init__(self):
        self.config = get_config()
        self.instances: List[TaniumInstance] = []
        self._setup_instances()

    def _setup_instances(self):
        """Initialize Tanium Cloud instance using signals-specific API token.

        Note: On-Prem is excluded — Threat Response is not installed there.
        """
        cloud_url = self.config.tanium_cloud_api_url
        cloud_signals_token = self.config.tanium_cloud_signals_api_token

        if cloud_url and cloud_signals_token:
            cloud_instance = TaniumInstance(
                name="Cloud",
                server_url=cloud_url,
                token=cloud_signals_token,
                verify_ssl=True
            )
            if cloud_instance.validate_token():
                self.instances.append(cloud_instance)
                logger.info("Cloud signals instance initialized successfully")
            else:
                logger.warning(f"Cloud signals token validation failed: {cloud_instance.last_error}")
        else:
            logger.info("Cloud signals API not configured (missing URL or token)")

        if not self.instances:
            logger.warning("No Tanium signals instances available")

    def fetch_all_signals(self) -> List[TaniumSignal]:
        """Fetch signals from all configured instances."""
        all_signals: List[TaniumSignal] = []
        seen_names: set = set()  # Track signal names to avoid duplicates

        for instance in self.instances:
            logger.info(f"Fetching signals from {instance.name}...")
            try:
                result = instance.list_signals()

                if "error" in result:
                    logger.error(f"Error fetching signals from {instance.name}: {result['error']}")
                    continue

                signals_data = result.get("signals", [])
                logger.info(f"Retrieved {len(signals_data)} raw signals from {instance.name}")

                # Filter to production signals only (DE_ prefix)
                prod_signals = [s for s in signals_data if s.get("name", "").startswith("DE_")]
                skipped = len(signals_data) - len(prod_signals)
                if skipped:
                    logger.info(f"Filtered out {skipped} non-production signals (missing DE_ prefix)")
                logger.info(f"{len(prod_signals)} production signals from {instance.name}")

                for signal_data in prod_signals:
                    signal = self._parse_signal(signal_data, instance.name)
                    if signal and signal.name not in seen_names:
                        all_signals.append(signal)
                        seen_names.add(signal.name)
                    elif signal and signal.name in seen_names:
                        logger.debug(f"Skipping duplicate signal: {signal.name}")

            except Exception as e:
                logger.error(f"Failed to fetch signals from {instance.name}: {e}")
                continue

        logger.info(f"Total unique signals fetched: {len(all_signals)}")
        return all_signals

    def _parse_signal(self, data: Dict[str, Any], source: str) -> Optional[TaniumSignal]:
        """Parse raw signal data into a TaniumSignal object."""
        try:
            # Extract platforms from various possible fields
            # Tanium signals don't always have explicit platform info,
            # so we default to Windows if not specified
            platforms = ["windows"]  # Default

            return TaniumSignal(
                id=str(data.get("id", "")),
                name=data.get("name", ""),
                description=data.get("description", "") or "",
                severity=data.get("severity", 3),  # Default to medium
                enabled=data.get("enabled", True),
                platforms=platforms,
                mitre_tactics=data.get("mitreTactics") or [],
                mitre_techniques=data.get("mitreTechniques") or [],
                created_at=data.get("createdAt", ""),
                updated_at=data.get("updatedAt", ""),
                source=source
            )
        except Exception as e:
            logger.warning(f"Failed to parse signal: {e}")
            return None


def write_signals_catalog(signals: List[TaniumSignal], output_path: Path = None) -> int:
    """Write signals to CSV catalog.

    The CSV format has one row per signal-technique combination to support
    multiple MITRE techniques per signal.

    Args:
        signals: List of TaniumSignal objects
        output_path: Path to write CSV (defaults to data/tanium_signals_catalog.csv)

    Returns:
        Number of rows written
    """
    output_path = output_path or SIGNALS_CATALOG_PATH

    # Ensure parent directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows_written = 0
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["name", "description", "platforms", "technique_id", "technique_name"])

        for signal in signals:
            platforms_str = ",".join(signal.platforms)

            # If signal has MITRE techniques, write one row per technique
            if signal.mitre_techniques:
                for technique in signal.mitre_techniques:
                    writer.writerow([
                        signal.name,
                        signal.description,
                        platforms_str,
                        technique,
                        ""  # technique_name not provided by API
                    ])
                    rows_written += 1
            else:
                # Write one row with empty technique fields
                writer.writerow([
                    signal.name,
                    signal.description,
                    platforms_str,
                    "",
                    ""
                ])
                rows_written += 1

    logger.info(f"Wrote {rows_written} rows to {output_path}")
    return rows_written


def sync_tanium_signals_catalog() -> Dict[str, Any]:
    """Main entry point: fetch signals and rebuild the catalog.

    This function:
    1. Fetches signals from Tanium Cloud using the dedicated signals API token
    2. Writes signals to CSV catalog (data/tanium_signals_catalog.csv)
    3. Updates ChromaDB rules catalog with fresh Tanium rules

    NOTE: If no signals are fetched (API errors, permission issues), the existing
    CSV and ChromaDB are preserved. This prevents data loss while API access is
    being resolved.

    Returns:
        Dict with sync results including counts and any errors
    """
    logger.info("=" * 60)
    logger.info("TANIUM SIGNALS CATALOG SYNC STARTING")
    logger.info(f"Timestamp: {datetime.now().isoformat()}")
    logger.info("=" * 60)

    result = {
        "success": True,  # Default to success - we don't want to fail the scheduler
        "signals_count": 0,
        "rows_written": 0,
        "rules_upserted": 0,
        "skipped": False,
        "errors": []
    }

    try:
        client = TaniumSignalsClient()

        if not client.instances:
            result["skipped"] = True
            result["errors"].append("No Tanium signals instances available - skipping sync")
            logger.warning("No Tanium signals instances configured or accessible - skipping sync (existing catalog preserved)")
            return result

        # Fetch signals from all instances
        signals = client.fetch_all_signals()
        result["signals_count"] = len(signals)

        if not signals:
            result["skipped"] = True
            result["errors"].append("No signals fetched from any instance - preserving existing catalog")
            logger.warning("No signals fetched - skipping catalog update (existing CSV and ChromaDB preserved)")
            logger.warning("This may be due to API permission issues. Check Tanium RBAC settings.")
            logger.info("=" * 60)
            logger.info("TANIUM SIGNALS CATALOG SYNC SKIPPED (no data)")
            logger.info("=" * 60)
            return result

        # Write to CSV catalog
        rows_written = write_signals_catalog(signals)
        result["rows_written"] = rows_written

        # Update ChromaDB rules catalog with fresh Tanium rules
        logger.info("Updating ChromaDB rules catalog with Tanium signals...")
        try:
            # Load rules from the freshly written CSV
            tanium_rules = fetch_tanium_rules_from_csv(SIGNALS_CATALOG_PATH)

            if tanium_rules:
                catalog = RulesCatalog()
                rules_upserted = catalog.upsert_rules(tanium_rules)
                result["rules_upserted"] = rules_upserted
                logger.info(f"Upserted {rules_upserted} Tanium rules to ChromaDB")
            else:
                logger.warning("No rules loaded from CSV for ChromaDB update")
        except Exception as e:
            error_msg = f"ChromaDB update failed: {e}"
            result["errors"].append(error_msg)
            logger.error(error_msg, exc_info=True)

        logger.info("=" * 60)
        logger.info("TANIUM SIGNALS CATALOG SYNC COMPLETED")
        logger.info(f"Signals: {len(signals)}, CSV Rows: {rows_written}, ChromaDB Rules: {result['rules_upserted']}")
        logger.info("=" * 60)

    except Exception as e:
        error_msg = f"Sync failed: {e}"
        result["errors"].append(error_msg)
        logger.error(error_msg, exc_info=True)
        # Still return success=True to not break the scheduler
        result["skipped"] = True

    return result


if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    result = sync_tanium_signals_catalog()

    print(f"\nSync Result:")
    print(f"  Success: {result['success']}")
    if result.get('skipped'):
        print(f"  Status: SKIPPED (existing catalog preserved)")
    print(f"  Signals fetched: {result['signals_count']}")
    print(f"  CSV rows written: {result['rows_written']}")
    print(f"  ChromaDB rules upserted: {result['rules_upserted']}")
    if result['errors']:
        print(f"  Notes: {result['errors']}")

    # Always exit 0 - we don't want to fail the scheduler
    sys.exit(0)
