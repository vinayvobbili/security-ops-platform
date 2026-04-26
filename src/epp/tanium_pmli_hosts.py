"""
Tanium PMLI Hosts Report Generator

Identifies all PMLI (India PMLI) hosts in Tanium and enriches them with
ServiceNow CMDB data for visibility and reporting.

PMLI hosts are detected by:
1. Hostname starts with 'metlap', 'pmdesk', 'inblr', or 'inmum' (case-insensitive)
2. Hostname contains 'pmli' (case-insensitive)
3. ServiceNow osDomain contains 'pmli' (discovered during enrichment)
"""
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
from rich.progress import track

from my_config import get_config
from services.tanium import TaniumClient, Computer
from services.service_now import ServiceNowClient

logger = logging.getLogger(__name__)

MAX_WORKERS_SNOW = 30


def is_pmli_hostname(hostname: str) -> bool:
    """Check if a hostname matches PMLI naming patterns."""
    name = hostname.strip().lower()
    return name.startswith(('metlap', 'pmdesk', 'inblr', 'inmum')) or 'pmli' in name


@dataclass
class PMLIHost:
    """Represents a PMLI host with enrichment data"""
    hostname: str
    tanium_id: str
    ip_address: str
    os_platform: str
    source: str
    last_seen: str
    current_tags: List[str]
    pmli_match_reason: str = ""

    # ServiceNow enrichment
    snow_lifecycle_status: str = ""
    snow_environment: str = ""
    snow_category: str = ""
    snow_ci_class: str = ""
    snow_operating_system: str = ""
    snow_os_domain: str = ""
    snow_country: str = ""
    snow_status: str = ""


class TaniumPMLIHostsProcessor:
    """Processes and reports on PMLI hosts in Tanium"""

    def __init__(self, instance_filter: Optional[str] = None):
        self.config = get_config()
        self.instance_filter = instance_filter
        self.root_dir = Path(__file__).parent.parent.parent
        self.data_dir = self.root_dir / "data" / "transient" / "epp_device_tagging"

    def get_pmli_hosts(self, test_limit: Optional[int] = None) -> List[PMLIHost]:
        """Get all PMLI hosts from Tanium based on hostname patterns."""
        logger.info(f"Fetching Tanium hosts (instance: {self.instance_filter or 'all'})...")

        normalized_filter = None
        if self.instance_filter:
            normalized = self.instance_filter.lower().replace("-", "")
            if normalized in ["cloud", "onprem"]:
                normalized_filter = normalized

        client = TaniumClient(instance=normalized_filter)
        all_computers = client._get_all_computers()
        logger.info(f"Retrieved {len(all_computers)} total hosts from Tanium")

        # Filter to PMLI hosts by hostname
        pmli_hosts = []
        for computer in all_computers:
            if not is_pmli_hostname(computer.name):
                continue

            name_lower = computer.name.strip().lower()
            if name_lower.startswith('metlap'):
                reason = "Hostname starts with 'METLAP'"
            elif name_lower.startswith('pmdesk'):
                reason = "Hostname starts with 'PMDESK'"
            elif name_lower.startswith('inblr'):
                reason = "Hostname starts with 'INBLR'"
            elif name_lower.startswith('inmum'):
                reason = "Hostname starts with 'INMUM'"
            else:
                reason = "Hostname contains 'PMLI'"

            pmli_hosts.append(PMLIHost(
                hostname=computer.name,
                tanium_id=computer.id,
                ip_address=computer.ip or "",
                os_platform=computer.os_platform or "",
                source=computer.source,
                last_seen=computer.eidLastSeen or "",
                current_tags=computer.custom_tags or [],
                pmli_match_reason=reason,
            ))

        logger.info(f"Found {len(pmli_hosts)} PMLI hosts out of {len(all_computers)} total")

        if test_limit and test_limit > 0:
            pmli_hosts = pmli_hosts[:test_limit]
            logger.info(f"Test mode: limiting to {test_limit} hosts")

        return pmli_hosts

    def enrich_with_servicenow(self, hosts: List[PMLIHost]) -> List[PMLIHost]:
        """Enrich PMLI hosts with ServiceNow CMDB data."""
        if not hosts:
            return hosts

        logger.info(f"Enriching {len(hosts)} PMLI hosts with ServiceNow CMDB data...")

        snow_client = ServiceNowClient(requests_per_second=30)

        def enrich_single_host(host: PMLIHost) -> PMLIHost:
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

                    # If osDomain confirms PMLI and reason was hostname-only, note it
                    if 'pmli' in host.snow_os_domain.lower() and 'osDomain' not in host.pmli_match_reason:
                        host.pmli_match_reason += " + osDomain confirms PMLI"

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

    def export_to_excel(self, hosts: List[PMLIHost], output_path: Optional[Path] = None) -> str:
        """Export the PMLI hosts report to Excel."""
        if output_path is None:
            today = datetime.now().strftime('%m-%d-%Y')
            output_dir = self.data_dir / today
            output_dir.mkdir(parents=True, exist_ok=True)

            instance_suffix = f"_{self.instance_filter.replace('-', '_')}" if self.instance_filter else ""
            output_path = output_dir / f"Tanium_PMLI_Hosts{instance_suffix}.xlsx"

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
                'PMLI Match Reason': host.pmli_match_reason,
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
            'pmli match reason': 40,
            'snow status': 15,
            'snow lifecycle': 15,
            'snow environment': 15,
            'snow category': 15,
            'snow os domain': 20,
            'snow country': 15,
        }
        wrap_columns = {'current tags', 'pmli match reason'}
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

        logger.info(f"Exported {len(hosts)} PMLI hosts to {output_path}")
        return str(output_path)

    def process(self, test_limit: Optional[int] = None) -> str:
        """Main processing pipeline."""
        try:
            # Step 1: Get PMLI hosts from Tanium
            logger.info("=" * 60)
            logger.info("Step 1: Getting PMLI hosts from Tanium...")
            hosts = self.get_pmli_hosts(test_limit)

            if not hosts:
                logger.info("No PMLI hosts found!")
                return self._create_empty_report()

            # Step 2: Enrich with ServiceNow CMDB data
            logger.info("=" * 60)
            logger.info("Step 2: Enriching with ServiceNow CMDB data...")
            hosts = self.enrich_with_servicenow(hosts)

            # Step 3: Export report
            logger.info("=" * 60)
            logger.info("Step 3: Generating Excel report...")
            report_path = self.export_to_excel(hosts)

            # Summary
            logger.info("=" * 60)
            logger.info("Processing complete!")
            logger.info(f"  Total PMLI hosts: {len(hosts)}")
            logger.info(f"  Found in ServiceNow: {sum(1 for h in hosts if h.snow_status == 'Found')}")
            logger.info(f"  Report: {report_path}")
            logger.info("=" * 60)

            return report_path

        except Exception as e:
            logger.error(f"Processing failed: {e}", exc_info=True)
            raise

    def _create_empty_report(self) -> str:
        """Create an empty report when no PMLI hosts are found."""
        today = datetime.now().strftime('%m-%d-%Y')
        output_dir = self.data_dir / today
        output_dir.mkdir(parents=True, exist_ok=True)

        instance_suffix = f"_{self.instance_filter.replace('-', '_')}" if self.instance_filter else ""
        output_path = output_dir / f"Tanium_PMLI_Hosts{instance_suffix}.xlsx"

        df = pd.DataFrame(columns=[
            'Hostname', 'Tanium ID', 'Source', 'IP Address', 'OS Platform',
            'Last Seen', 'Current Tags', 'PMLI Match Reason',
            'SNOW Status', 'SNOW Lifecycle', 'SNOW Environment',
            'SNOW Category', 'SNOW OS Domain', 'SNOW Country',
        ])
        df.to_excel(output_path, index=False, engine='openpyxl')

        logger.info(f"Created empty report at {output_path}")
        return str(output_path)


def create_processor(instance_filter: Optional[str] = None) -> TaniumPMLIHostsProcessor:
    """Factory function to create a PMLI hosts processor."""
    return TaniumPMLIHostsProcessor(instance_filter=instance_filter)
