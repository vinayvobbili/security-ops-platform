"""
Tanium Unhealthy Hosts Report Generator

This module identifies Tanium agents that are unhealthy (not seen for > 1 day)
and enriches the data with ServiceNow CMDB and CrowdStrike online status.

The report helps identify hosts that are:
1. Unhealthy in Tanium (last seen > 1 day ago)
2. Operational in ServiceNow CMDB (lifecycle status)
3. Online in CrowdStrike

Hosts meeting all three criteria are candidates for automated Tanium agent
reinstallation via CrowdStrike RTR.

Workflow (based on XSOAR playbook):
1. Get unhealthy Tanium hosts (last seen > 1 day)
2. Query ServiceNow CMDB for lifecycle status
3. Check CrowdStrike for online status
4. Generate report for review
"""
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
from rich.progress import track

from my_config import get_config
from services.tanium import TaniumClient, Computer
from services.service_now import ServiceNowClient
from services.crowdstrike import CrowdStrikeClient

# Setup logging
logger = logging.getLogger(__name__)

# Constants
UNHEALTHY_THRESHOLD_DAYS_SERVER = 1  # Servers not seen for more than 1 day are unhealthy
UNHEALTHY_THRESHOLD_DAYS_WORKSTATION = 3  # Workstations not seen for more than 3 days are unhealthy
MAX_WORKERS_SNOW = 30  # Parallel workers for ServiceNow enrichment
MAX_WORKERS_CS = 10  # Parallel workers for CrowdStrike checks

# Lifecycle statuses eligible for RTR remediation
RTR_ELIGIBLE_LIFECYCLE_STATUSES = {"operational", "pipeline"}


@dataclass
class UnhealthyHost:
    """Represents an unhealthy Tanium host with enrichment data"""
    hostname: str
    tanium_id: str
    ip_address: str
    os_platform: str
    source: str  # Cloud or On-Prem
    last_seen: str
    days_since_last_seen: int
    current_tags: List[str]
    unhealthy_reason: str = ""  # Why this host is considered unhealthy

    # ServiceNow enrichment
    snow_lifecycle_status: str = ""
    snow_environment: str = ""
    snow_ci_class: str = ""
    snow_operating_system: str = ""
    snow_country: str = ""
    snow_status: str = ""  # "Found", "Not Found", or error message

    # CrowdStrike enrichment
    cs_online_status: str = ""  # "online", "offline", "unknown", or error
    cs_status: str = ""  # "Found", "Not Found", or error message

    # Remediation eligibility
    is_rtr_candidate: bool = False
    rtr_candidate_reason: str = ""


class TaniumUnhealthyHostsProcessor:
    """Processes and reports on unhealthy Tanium hosts"""

    def __init__(self, instance_filter: Optional[str] = None):
        """
        Initialize the processor.

        Args:
            instance_filter: Filter for Tanium instance - "cloud", "on-prem", or None for all
        """
        self.config = get_config()
        self.instance_filter = instance_filter
        self.root_dir = Path(__file__).parent.parent.parent
        self.data_dir = self.root_dir / "data" / "transient" / "epp_device_tagging"

    def _is_workstation(self, os_platform: str) -> bool:
        """
        Determine if a host is a workstation based on OS platform.

        Workstations are typically Windows clients (not Server), macOS, etc.
        Servers are Windows Server, Linux, etc.
        """
        if not os_platform:
            return False

        os_lower = os_platform.lower()

        # Windows workstations (not Server)
        if "windows" in os_lower and "server" not in os_lower:
            return True

        # macOS is typically workstation
        if "mac" in os_lower or "darwin" in os_lower:
            return True

        # Linux is typically server (unless explicitly desktop)
        # Default to server for unknown
        return False

    def get_unhealthy_hosts(self, test_limit: Optional[int] = None) -> List[UnhealthyHost]:
        """
        Get all Tanium hosts that haven't been seen for more than the threshold.

        Different thresholds are applied:
        - Servers: UNHEALTHY_THRESHOLD_DAYS_SERVER (1 day)
        - Workstations: UNHEALTHY_THRESHOLD_DAYS_WORKSTATION (3 days)

        Args:
            test_limit: Optional limit for testing (process only N hosts)

        Returns:
            List of UnhealthyHost objects
        """
        logger.info(f"Fetching Tanium hosts (instance: {self.instance_filter or 'all'})...")

        # Normalize instance filter for TaniumClient
        normalized_filter = None
        if self.instance_filter:
            normalized = self.instance_filter.lower().replace("-", "")
            if normalized in ["cloud", "onprem"]:
                normalized_filter = normalized

        client = TaniumClient(instance=normalized_filter)

        # Get all computers from Tanium
        all_computers = client._get_all_computers()
        logger.info(f"Retrieved {len(all_computers)} total hosts from Tanium")

        # Filter for unhealthy hosts (last seen > threshold, based on device type)
        now = datetime.now(timezone.utc)
        server_threshold = now - timedelta(days=UNHEALTHY_THRESHOLD_DAYS_SERVER)
        workstation_threshold = now - timedelta(days=UNHEALTHY_THRESHOLD_DAYS_WORKSTATION)

        unhealthy_hosts = []
        for computer in all_computers:
            last_seen = self._parse_last_seen(computer.eidLastSeen)
            if not last_seen:
                continue

            # Determine threshold based on device type
            is_workstation = self._is_workstation(computer.os_platform or "")
            threshold = workstation_threshold if is_workstation else server_threshold
            threshold_days = UNHEALTHY_THRESHOLD_DAYS_WORKSTATION if is_workstation else UNHEALTHY_THRESHOLD_DAYS_SERVER

            if last_seen < threshold:
                days_since = (now - last_seen).days
                device_type = "workstation" if is_workstation else "server"

                # Generate unhealthy reason
                if days_since == 1:
                    unhealthy_reason = f"Tanium agent not seen for {days_since} day (last seen: {computer.eidLastSeen})"
                else:
                    unhealthy_reason = f"Tanium agent not seen for {days_since} days (last seen: {computer.eidLastSeen})"

                unhealthy_hosts.append(UnhealthyHost(
                    hostname=computer.name,
                    tanium_id=computer.id,
                    ip_address=computer.ip or "",
                    os_platform=computer.os_platform or "",
                    source=computer.source,
                    last_seen=computer.eidLastSeen or "",
                    days_since_last_seen=days_since,
                    current_tags=computer.custom_tags or [],
                    unhealthy_reason=unhealthy_reason
                ))

        logger.info(f"Found {len(unhealthy_hosts)} unhealthy hosts "
                   f"(servers: >{UNHEALTHY_THRESHOLD_DAYS_SERVER} day(s), "
                   f"workstations: >{UNHEALTHY_THRESHOLD_DAYS_WORKSTATION} day(s))")

        # Apply test limit if specified
        if test_limit and test_limit > 0:
            unhealthy_hosts = unhealthy_hosts[:test_limit]
            logger.info(f"Test mode: limiting to {test_limit} hosts")

        return unhealthy_hosts

    def _parse_last_seen(self, last_seen_str: str) -> Optional[datetime]:
        """Parse the last seen timestamp from Tanium"""
        if not last_seen_str:
            return None

        try:
            # Handle ISO format with timezone
            if 'Z' in last_seen_str:
                return datetime.fromisoformat(last_seen_str.replace('Z', '+00:00'))
            elif '+' in last_seen_str or last_seen_str.endswith('00'):
                return datetime.fromisoformat(last_seen_str)
            else:
                # Assume UTC if no timezone
                dt = datetime.fromisoformat(last_seen_str)
                return dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError) as e:
            logger.debug(f"Could not parse last_seen '{last_seen_str}': {e}")
            return None

    def enrich_with_servicenow(self, hosts: List[UnhealthyHost]) -> List[UnhealthyHost]:
        """
        Enrich hosts with ServiceNow CMDB data (lifecycle status, environment, etc.)

        Args:
            hosts: List of unhealthy hosts to enrich

        Returns:
            List of hosts enriched with ServiceNow data
        """
        if not hosts:
            return hosts

        logger.info(f"Enriching {len(hosts)} hosts with ServiceNow CMDB data...")

        snow_client = ServiceNowClient(requests_per_second=30)

        def enrich_single_host(host: UnhealthyHost) -> UnhealthyHost:
            """Enrich a single host with ServiceNow data"""
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
                    host.snow_ci_class = details.get('ciClass', '')
                    host.snow_operating_system = details.get('operatingSystem', '')
                    host.snow_country = details.get('country', '')

            except Exception as e:
                host.snow_status = f"Error: {str(e)}"
                logger.warning(f"Error enriching {host.hostname} with SNOW: {e}")

            return host

        # Process in parallel with progress bar
        enriched_hosts = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS_SNOW) as executor:
            futures = {executor.submit(enrich_single_host, host): host for host in hosts}

            for future in track(as_completed(futures), total=len(futures),
                               description="Enriching with ServiceNow",
                               disable=not logger.isEnabledFor(logging.INFO)):
                enriched_hosts.append(future.result())

        # Log summary
        found_count = sum(1 for h in enriched_hosts if h.snow_status == "Found")
        eligible_count = sum(1 for h in enriched_hosts
                            if h.snow_lifecycle_status.lower() in RTR_ELIGIBLE_LIFECYCLE_STATUSES)
        logger.info(f"ServiceNow enrichment complete: {found_count} found, {eligible_count} operational/pipeline")

        return enriched_hosts

    def enrich_with_crowdstrike(self, hosts: List[UnhealthyHost],
                                 only_operational: bool = True) -> List[UnhealthyHost]:
        """
        Check CrowdStrike online status for hosts.

        Args:
            hosts: List of hosts to check
            only_operational: If True, only check hosts with lifecycle_status == "Operational"

        Returns:
            List of hosts enriched with CrowdStrike data
        """
        if not hosts:
            return hosts

        # Filter to only check hosts with eligible lifecycle status if specified
        if only_operational:
            hosts_to_check = [h for h in hosts
                            if h.snow_lifecycle_status.lower() in RTR_ELIGIBLE_LIFECYCLE_STATUSES]
            hosts_skip = [h for h in hosts
                         if h.snow_lifecycle_status.lower() not in RTR_ELIGIBLE_LIFECYCLE_STATUSES]

            # Mark skipped hosts
            for host in hosts_skip:
                host.cs_status = "Skipped (not operational/pipeline)"
                host.cs_online_status = ""
        else:
            hosts_to_check = hosts
            hosts_skip = []

        if not hosts_to_check:
            logger.info("No operational hosts to check in CrowdStrike")
            return hosts

        logger.info(f"Checking CrowdStrike online status for {len(hosts_to_check)} operational hosts...")

        cs_client = CrowdStrikeClient()

        def check_single_host(host: UnhealthyHost) -> UnhealthyHost:
            """Check CrowdStrike status for a single host"""
            try:
                online_state = cs_client.get_device_online_state(host.hostname)

                if online_state is None:
                    host.cs_status = "Not Found"
                    host.cs_online_status = ""
                else:
                    host.cs_status = "Found"
                    host.cs_online_status = online_state

            except Exception as e:
                host.cs_status = f"Error: {str(e)}"
                host.cs_online_status = ""
                logger.warning(f"Error checking CS status for {host.hostname}: {e}")

            return host

        # Process in parallel with progress bar
        checked_hosts = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS_CS) as executor:
            futures = {executor.submit(check_single_host, host): host for host in hosts_to_check}

            for future in track(as_completed(futures), total=len(futures),
                               description="Checking CrowdStrike",
                               disable=not logger.isEnabledFor(logging.INFO)):
                checked_hosts.append(future.result())

        # Combine with skipped hosts
        all_hosts = checked_hosts + hosts_skip

        # Log summary
        online_count = sum(1 for h in all_hosts if h.cs_online_status == "online")
        logger.info(f"CrowdStrike check complete: {online_count} hosts online")

        return all_hosts

    def determine_rtr_candidates(self, hosts: List[UnhealthyHost]) -> List[UnhealthyHost]:
        """
        Determine which hosts are candidates for RTR remediation.

        A host is a candidate if:
        1. ServiceNow lifecycle status is "Operational" or "Pipeline"
        2. CrowdStrike shows the host as "online"

        Args:
            hosts: List of enriched hosts

        Returns:
            Same list with is_rtr_candidate and rtr_candidate_reason populated
        """
        for host in hosts:
            reasons = []
            is_candidate = True

            # Check ServiceNow lifecycle (operational or pipeline)
            if host.snow_status != "Found":
                is_candidate = False
                reasons.append(f"SNOW: {host.snow_status}")
            elif host.snow_lifecycle_status.lower() not in RTR_ELIGIBLE_LIFECYCLE_STATUSES:
                is_candidate = False
                reasons.append(f"Lifecycle: {host.snow_lifecycle_status or 'Unknown'}")

            # Check CrowdStrike online status
            if host.cs_status != "Found":
                is_candidate = False
                reasons.append(f"CS: {host.cs_status}")
            elif host.cs_online_status != "online":
                is_candidate = False
                reasons.append(f"CS Online: {host.cs_online_status or 'Unknown'}")

            host.is_rtr_candidate = is_candidate
            if is_candidate:
                host.rtr_candidate_reason = "Ready for RTR remediation"
            else:
                host.rtr_candidate_reason = "; ".join(reasons)

        # Log summary
        candidate_count = sum(1 for h in hosts if h.is_rtr_candidate)
        logger.info(f"RTR candidates: {candidate_count} out of {len(hosts)} hosts")

        return hosts

    def export_to_excel(self, hosts: List[UnhealthyHost], output_path: Optional[Path] = None) -> str:
        """
        Export the unhealthy hosts report to Excel.

        Args:
            hosts: List of enriched unhealthy hosts
            output_path: Optional output path (defaults to data directory)

        Returns:
            Path to the generated Excel file
        """
        if output_path is None:
            today = datetime.now().strftime('%m-%d-%Y')
            output_dir = self.data_dir / today
            output_dir.mkdir(parents=True, exist_ok=True)

            instance_suffix = f"_{self.instance_filter.replace('-', '_')}" if self.instance_filter else ""
            output_path = output_dir / f"Tanium_Unhealthy_Hosts{instance_suffix}.xlsx"

        # Prepare data for DataFrame
        data = []
        for host in hosts:
            data.append({
                'Hostname': host.hostname,
                'Tanium ID': host.tanium_id,
                'Source': host.source,
                'IP Address': host.ip_address,
                'OS Platform': host.os_platform,
                'Unhealthy Reason': host.unhealthy_reason,
                'Last Seen in Tanium': host.last_seen,
                'Days Since Last Seen': host.days_since_last_seen,
                'Current Tags': ', '.join(host.current_tags) if host.current_tags else '',
                'SNOW Status': host.snow_status,
                'SNOW Lifecycle': host.snow_lifecycle_status,
                'SNOW Environment': host.snow_environment,
                'SNOW CI Class': host.snow_ci_class,
                'SNOW Country': host.snow_country,
                'CS Status': host.cs_status,
                'CS Online State': host.cs_online_status,
                'RTR Candidate': 'Yes' if host.is_rtr_candidate else 'No',
                'RTR Candidate Reason': host.rtr_candidate_reason
            })

        df = pd.DataFrame(data)

        # Deduplicate by hostname, keeping the row with the most recent last-seen
        df = df.sort_values('Days Since Last Seen', ascending=True)
        df = df.drop_duplicates(subset=['Hostname'], keep='first')

        # Sort by RTR candidates first, then by days since last seen
        df = df.sort_values(
            by=['RTR Candidate', 'Days Since Last Seen'],
            ascending=[False, False]
        )

        # Write to Excel
        df.to_excel(output_path, index=False, engine='openpyxl')

        # Apply professional formatting
        from src.utils.excel_formatting import apply_professional_formatting
        column_widths = {
            'hostname': 35,
            'tanium id': 15,
            'source': 12,
            'ip address': 15,
            'os platform': 12,
            'unhealthy reason': 55,
            'last seen in tanium': 25,
            'days since last seen': 18,
            'current tags': 40,
            'snow status': 15,
            'snow lifecycle': 15,
            'snow environment': 15,
            'snow ci class': 15,
            'snow country': 15,
            'cs status': 15,
            'cs online state': 15,
            'rtr candidate': 12,
            'rtr candidate reason': 50
        }
        wrap_columns = {'current tags', 'rtr candidate reason', 'unhealthy reason'}
        apply_professional_formatting(output_path, column_widths=column_widths, wrap_columns=wrap_columns)

        logger.info(f"Exported {len(hosts)} unhealthy hosts to {output_path}")
        return str(output_path)

    def process(self, test_limit: Optional[int] = None,
                skip_cs_check: bool = False) -> str:
        """
        Main processing pipeline.

        Args:
            test_limit: Optional limit for testing
            skip_cs_check: Skip CrowdStrike online check (faster but less complete)

        Returns:
            Path to the generated report
        """
        try:
            # Step 1: Get unhealthy Tanium hosts
            logger.info("=" * 60)
            logger.info("Step 1: Getting unhealthy Tanium hosts...")
            hosts = self.get_unhealthy_hosts(test_limit)

            if not hosts:
                logger.warning("No unhealthy hosts found!")
                return self._create_empty_report()

            # Step 2: Enrich with ServiceNow CMDB data
            logger.info("=" * 60)
            logger.info("Step 2: Enriching with ServiceNow CMDB data...")
            hosts = self.enrich_with_servicenow(hosts)

            # Step 3: Check CrowdStrike online status (only for operational hosts)
            if not skip_cs_check:
                logger.info("=" * 60)
                logger.info("Step 3: Checking CrowdStrike online status...")
                hosts = self.enrich_with_crowdstrike(hosts, only_operational=True)
            else:
                logger.info("Step 3: Skipping CrowdStrike check (skip_cs_check=True)")

            # Step 4: Determine RTR candidates
            logger.info("=" * 60)
            logger.info("Step 4: Determining RTR remediation candidates...")
            hosts = self.determine_rtr_candidates(hosts)

            # Step 5: Export report
            logger.info("=" * 60)
            logger.info("Step 5: Generating Excel report...")
            report_path = self.export_to_excel(hosts)

            # Final summary
            logger.info("=" * 60)
            logger.info("Processing complete!")
            logger.info(f"  Total unhealthy hosts: {len(hosts)}")
            logger.info(f"  Found in ServiceNow: {sum(1 for h in hosts if h.snow_status == 'Found')}")
            logger.info(f"  Operational/Pipeline in SNOW: {sum(1 for h in hosts if h.snow_lifecycle_status.lower() in RTR_ELIGIBLE_LIFECYCLE_STATUSES)}")
            logger.info(f"  Online in CrowdStrike: {sum(1 for h in hosts if h.cs_online_status == 'online')}")
            logger.info(f"  RTR Candidates: {sum(1 for h in hosts if h.is_rtr_candidate)}")
            logger.info(f"  Report: {report_path}")
            logger.info("=" * 60)

            return report_path

        except Exception as e:
            logger.error(f"Processing failed: {e}", exc_info=True)
            raise

    def _create_empty_report(self) -> str:
        """Create an empty report when no unhealthy hosts are found"""
        today = datetime.now().strftime('%m-%d-%Y')
        output_dir = self.data_dir / today
        output_dir.mkdir(parents=True, exist_ok=True)

        instance_suffix = f"_{self.instance_filter.replace('-', '_')}" if self.instance_filter else ""
        output_path = output_dir / f"Tanium_Unhealthy_Hosts{instance_suffix}.xlsx"

        df = pd.DataFrame(columns=[
            'Hostname', 'Tanium ID', 'Source', 'IP Address', 'OS Platform',
            'Unhealthy Reason', 'Last Seen in Tanium', 'Days Since Last Seen', 'Current Tags',
            'SNOW Status', 'SNOW Lifecycle', 'SNOW Environment', 'SNOW CI Class', 'SNOW Country',
            'CS Status', 'CS Online State', 'RTR Candidate', 'RTR Candidate Reason'
        ])
        df.to_excel(output_path, index=False, engine='openpyxl')

        logger.info(f"Created empty report at {output_path}")
        return str(output_path)


def create_processor(instance_filter: Optional[str] = None) -> TaniumUnhealthyHostsProcessor:
    """
    Factory function to create an unhealthy hosts processor.

    Args:
        instance_filter: Filter for Tanium instance - "cloud", "on-prem", or None for all

    Returns:
        Configured TaniumUnhealthyHostsProcessor instance
    """
    return TaniumUnhealthyHostsProcessor(instance_filter=instance_filter)


def main():
    """Command-line entry point for testing"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Test with a small limit
    processor = create_processor(instance_filter=None)
    report_path = processor.process(test_limit=50)
    print(f"\nReport generated: {report_path}")


if __name__ == "__main__":
    main()
