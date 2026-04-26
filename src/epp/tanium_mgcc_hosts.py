"""
Tanium MGCC Hosts Report Generator

Identifies all MGCC (India non-PMLI) hosts in Tanium that currently have
APAC ring tags, enriches them with ServiceNow CMDB data.

MGCC hosts are detected by:
1. Host has an APAC ring tag (EPP_ECMTag_APAC_*)
2. Host does NOT match PMLI hostname patterns
3. ServiceNow country is India
"""
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
from rich.progress import track

from my_config import get_config
from services.tanium import TaniumClient, Computer
from services.service_now import ServiceNowClient
from src.epp.tanium_pmli_hosts import is_pmli_hostname

logger = logging.getLogger(__name__)

MAX_WORKERS_SNOW = 30
APAC_RING_PATTERN = re.compile(r'EPP_ECMTag_APAC_', re.IGNORECASE)
US_RING_PATTERN = re.compile(r'EPP_ECMTag_US_', re.IGNORECASE)


def _has_old_ring_tag(tags: List[str]) -> bool:
    """Check if any tag matches APAC or US ring tag patterns (tags to be replaced by MGCC)."""
    return any(APAC_RING_PATTERN.search(t) or US_RING_PATTERN.search(t) for t in tags)


def _is_india_country(country: str) -> bool:
    """Check if country value indicates India (but not India PMLI)."""
    if not country:
        return False
    normalized = country.strip().lower()
    return normalized == 'india'


@dataclass
class MGCCHost:
    """Represents an MGCC host with enrichment data"""
    hostname: str
    tanium_id: str
    ip_address: str
    os_platform: str
    source: str
    last_seen: str
    current_tags: List[str]
    mgcc_match_reason: str = ""

    # ServiceNow enrichment
    snow_lifecycle_status: str = ""
    snow_environment: str = ""
    snow_category: str = ""
    snow_ci_class: str = ""
    snow_operating_system: str = ""
    snow_os_domain: str = ""
    snow_country: str = ""
    snow_status: str = ""


class TaniumMGCCHostsProcessor:
    """Processes and reports on MGCC hosts in Tanium"""

    def __init__(self, instance_filter: Optional[str] = None):
        self.config = get_config()
        self.instance_filter = instance_filter
        self.root_dir = Path(__file__).parent.parent.parent
        self.data_dir = self.root_dir / "data" / "transient" / "epp_device_tagging"

    def get_mgcc_candidates(self, test_limit: Optional[int] = None) -> List[MGCCHost]:
        """Get non-PMLI hosts with APAC ring tags from Tanium."""
        logger.info(f"Fetching Tanium hosts (instance: {self.instance_filter or 'all'})...")

        normalized_filter = None
        if self.instance_filter:
            normalized = self.instance_filter.lower().replace("-", "")
            if normalized in ["cloud", "onprem"]:
                normalized_filter = normalized

        client = TaniumClient(instance=normalized_filter)
        all_computers = client._get_all_computers()
        logger.info(f"Retrieved {len(all_computers)} total hosts from Tanium")

        candidates = []
        for computer in all_computers:
            # Skip PMLI hosts
            if is_pmli_hostname(computer.name):
                continue

            tags = computer.custom_tags or []

            # Only hosts with APAC or US ring tags (to be replaced by MGCC)
            if not _has_old_ring_tag(tags):
                continue

            old_tags = [t for t in tags if APAC_RING_PATTERN.search(t) or US_RING_PATTERN.search(t)]
            reason = f"Old tag: {', '.join(old_tags)}"

            candidates.append(MGCCHost(
                hostname=computer.name,
                tanium_id=computer.id,
                ip_address=computer.ip or "",
                os_platform=computer.os_platform or "",
                source=computer.source,
                last_seen=computer.eidLastSeen or "",
                current_tags=tags,
                mgcc_match_reason=reason,
            ))

        logger.info(f"Found {len(candidates)} non-PMLI hosts with APAC ring tags out of {len(all_computers)} total")

        if test_limit and test_limit > 0:
            candidates = candidates[:test_limit]
            logger.info(f"Test mode: limiting to {test_limit} hosts")

        return candidates

    def enrich_with_servicenow(self, hosts: List[MGCCHost]) -> List[MGCCHost]:
        """Enrich hosts with ServiceNow CMDB data."""
        if not hosts:
            return hosts

        logger.info(f"Enriching {len(hosts)} hosts with ServiceNow CMDB data...")

        snow_client = ServiceNowClient(requests_per_second=30)

        def enrich_single_host(host: MGCCHost) -> MGCCHost:
            try:
                details = snow_client.get_host_details(host.hostname)

                if details.get('status') == 'Not Found':
                    host.snow_status = "Not Found"
                elif details.get('status') == 'ServiceNow API Error':
                    host.snow_status = f"Error: {details.get('error', 'Unknown')}"
                else:
                    host.snow_status = "Found"
                    host.snow_lifecycle_status = details.get('lifecycleStatus', '')
                    host.snow_environment = details.get('environment', '')
                    host.snow_category = details.get('category', '')
                    host.snow_ci_class = details.get('ciClass', '')
                    host.snow_operating_system = details.get('operatingSystem', '')
                    host.snow_os_domain = details.get('osDomain', '')
                    host.snow_country = details.get('country', '')

            except Exception as e:
                host.snow_status = f"Error: {str(e)}"
                logger.warning(f"Error enriching {host.hostname} with SNOW: {e}")

            return host

        enriched_hosts = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS_SNOW) as executor:
            futures = {executor.submit(enrich_single_host, host): host for host in hosts}

            for future in track(as_completed(futures), total=len(futures),
                               description="Enriching with ServiceNow",
                               disable=not logger.isEnabledFor(logging.INFO)):
                enriched_hosts.append(future.result())

        found_count = sum(1 for h in enriched_hosts if h.snow_status == "Found")
        logger.info(f"ServiceNow enrichment complete: {found_count}/{len(enriched_hosts)} found in CMDB")

        return enriched_hosts

    def filter_to_india(self, hosts: List[MGCCHost]) -> List[MGCCHost]:
        """Keep only hosts where ServiceNow country is India (non-PMLI = MGCC)."""
        mgcc_hosts = []
        for host in hosts:
            if _is_india_country(host.snow_country):
                host.mgcc_match_reason += " + SNOW country: India (non-PMLI → MGCC)"
                mgcc_hosts.append(host)

        logger.info(f"Filtered to {len(mgcc_hosts)} MGCC hosts (India non-PMLI) from {len(hosts)} candidates")
        return mgcc_hosts

    def export_to_excel(self, hosts: List[MGCCHost], output_path: Optional[Path] = None) -> str:
        """Export the MGCC hosts report to Excel."""
        if output_path is None:
            today = datetime.now().strftime('%m-%d-%Y')
            output_dir = self.data_dir / today
            output_dir.mkdir(parents=True, exist_ok=True)

            instance_suffix = f"_{self.instance_filter.replace('-', '_')}" if self.instance_filter else ""
            output_path = output_dir / f"Tanium_MGCC_Hosts{instance_suffix}.xlsx"

        data = []
        for host in hosts:
            data.append({
                'Hostname': host.hostname,
                'Tanium ID': host.tanium_id,
                'Source': host.source,
                'IP Address': host.ip_address,
                'OS Platform': host.os_platform,
                'Last Seen': host.last_seen,
                'Current Tags': ', '.join(host.current_tags) if host.current_tags else '',
                'MGCC Match Reason': host.mgcc_match_reason,
                'SNOW Status': host.snow_status,
                'SNOW Lifecycle': host.snow_lifecycle_status,
                'SNOW Environment': host.snow_environment,
                'SNOW Category': host.snow_category,
                'SNOW OS Domain': host.snow_os_domain,
                'SNOW Country': host.snow_country,
            })

        df = pd.DataFrame(data)
        df = df.sort_values(by=['Hostname'], ascending=True)
        df.to_excel(output_path, index=False, engine='openpyxl')

        from src.utils.excel_formatting import apply_professional_formatting
        column_widths = {
            'hostname': 35,
            'tanium id': 15,
            'source': 12,
            'ip address': 15,
            'os platform': 12,
            'last seen': 25,
            'current tags': 40,
            'mgcc match reason': 45,
            'snow status': 15,
            'snow lifecycle': 15,
            'snow environment': 15,
            'snow category': 15,
            'snow os domain': 20,
            'snow country': 15,
        }
        wrap_columns = {'current tags', 'mgcc match reason'}
        apply_professional_formatting(output_path, column_widths=column_widths, wrap_columns=wrap_columns)

        # Add clickable Tanium ID hyperlinks
        from src.utils.excel_formatting import add_tanium_hyperlinks
        from services.tanium import TaniumClient
        try:
            tanium_client = TaniumClient()
            add_tanium_hyperlinks(output_path, action_id_column=None,
                                  portal_urls_by_source=tanium_client.get_portal_urls_by_source())
        except Exception as e:
            logger.warning(f"Could not add Tanium hyperlinks: {e}")

        logger.info(f"Exported {len(hosts)} MGCC hosts to {output_path}")
        return str(output_path)

    def process(self, test_limit: Optional[int] = None) -> str:
        """Main processing pipeline."""
        try:
            # Step 1: Get non-PMLI hosts with APAC ring tags
            logger.info("=" * 60)
            logger.info("Step 1: Getting APAC-tagged non-PMLI hosts from Tanium...")
            candidates = self.get_mgcc_candidates(test_limit)

            if not candidates:
                logger.info("No APAC-tagged non-PMLI hosts found!")
                return self._create_empty_report()

            # Step 2: Enrich with ServiceNow CMDB data
            logger.info("=" * 60)
            logger.info("Step 2: Enriching with ServiceNow CMDB data...")
            candidates = self.enrich_with_servicenow(candidates)

            # Step 3: Filter to India (MGCC)
            logger.info("=" * 60)
            logger.info("Step 3: Filtering to India (MGCC) hosts...")
            mgcc_hosts = self.filter_to_india(candidates)

            if not mgcc_hosts:
                logger.info("No MGCC hosts found after filtering!")
                return self._create_empty_report()

            # Step 4: Export report
            logger.info("=" * 60)
            logger.info("Step 4: Generating Excel report...")
            report_path = self.export_to_excel(mgcc_hosts)

            # Summary
            logger.info("=" * 60)
            logger.info("Processing complete!")
            logger.info(f"  APAC-tagged non-PMLI candidates: {len(candidates)}")
            logger.info(f"  Confirmed MGCC (India non-PMLI): {len(mgcc_hosts)}")
            logger.info(f"  Found in ServiceNow: {sum(1 for h in mgcc_hosts if h.snow_status == 'Found')}")
            logger.info(f"  Report: {report_path}")
            logger.info("=" * 60)

            return report_path

        except Exception as e:
            logger.error(f"Processing failed: {e}", exc_info=True)
            raise

    def _create_empty_report(self) -> str:
        """Create an empty report when no MGCC hosts are found."""
        today = datetime.now().strftime('%m-%d-%Y')
        output_dir = self.data_dir / today
        output_dir.mkdir(parents=True, exist_ok=True)

        instance_suffix = f"_{self.instance_filter.replace('-', '_')}" if self.instance_filter else ""
        output_path = output_dir / f"Tanium_MGCC_Hosts{instance_suffix}.xlsx"

        df = pd.DataFrame(columns=[
            'Hostname', 'Tanium ID', 'Source', 'IP Address', 'OS Platform',
            'Last Seen', 'Current Tags', 'MGCC Match Reason',
            'SNOW Status', 'SNOW Lifecycle', 'SNOW Environment',
            'SNOW Category', 'SNOW OS Domain', 'SNOW Country',
        ])
        df.to_excel(output_path, index=False, engine='openpyxl')

        logger.info(f"Created empty report at {output_path}")
        return str(output_path)


def create_processor(instance_filter: Optional[str] = None) -> TaniumMGCCHostsProcessor:
    """Factory function to create an MGCC hosts processor."""
    return TaniumMGCCHostsProcessor(instance_filter=instance_filter)
