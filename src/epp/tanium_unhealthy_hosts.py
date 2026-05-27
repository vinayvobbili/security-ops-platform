"""
Tanium Unhealthy Hosts Report Generator

This module identifies Tanium agents that are truly unhealthy — not just powered off.

A host is considered truly unhealthy when:
1. Tanium says it's unhealthy (servers: not seen >1 day, workstations: >3 days)
2. CrowdStrike has seen it within the last 24 hours (confirming the machine is on)

Hosts not found in CrowdStrike at all are flagged as risk (no EDR visibility).
Hosts found in CS but not seen recently are excluded (likely just powered off).

Workflow:
1. Get unhealthy Tanium hosts (servers >1 day, workstations >3 days)
2. Check CrowdStrike for all hosts (last_seen, online state, status, tags)
3. Filter: keep hosts seen in CS within 24h + hosts not found in CS
4. Ping hosts for network reachability (ICMP)
5. Enrich with ServiceNow CMDB (lifecycle, environment)
6. Determine RTR remediation candidates
7. Generate Excel report
"""
import logging
import os
import platform
import shlex
import subprocess
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
CS_LAST_SEEN_THRESHOLD_HOURS = 24  # Host must have been seen in CrowdStrike within this window to be considered truly unhealthy
MAX_WORKERS_SNOW = 30  # Parallel workers for ServiceNow enrichment
MAX_WORKERS_CS = 10  # Parallel workers for CrowdStrike checks
MAX_WORKERS_PING = 100  # Parallel workers for ICMP pings
PING_DOMAIN_SUFFIX = ".internal.local"  # Appended to bare hostnames for DNS resolution
REVERSE_SSH_PORT = 2222  # Reverse SSH tunnel to Mac for ping routing
REVERSE_SSH_USER = os.getenv("REVERSE_SSH_USER", "")  # Mac username for SSH tunnel

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
    cs_last_seen: str = ""  # ISO timestamp from CrowdStrike
    cs_device_status: str = ""  # "Normal", "Contained", etc.
    cs_tags: List[str] = None  # CrowdStrike Falcon Grouping Tags

    # Ping reachability
    ping_reachable: Optional[bool] = None  # True/False/None (not yet pinged)
    ping_latency_ms: Optional[float] = None

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

        # Deduplicate by hostname, keeping the entry with the most recent last_seen.
        # Tanium can have multiple entries for the same host (e.g. re-imaged, re-registered,
        # or listed as both short name and FQDN like "HOST" vs "HOST.domain.corp").
        # We only want to evaluate the freshest entry per hostname.
        deduped: Dict[str, Computer] = {}
        for computer in all_computers:
            key = computer.name.split('.')[0].lower()
            existing = deduped.get(key)
            if existing is None:
                deduped[key] = computer
            else:
                existing_ts = self._parse_last_seen(existing.eidLastSeen)
                current_ts = self._parse_last_seen(computer.eidLastSeen)
                if current_ts and (not existing_ts or current_ts > existing_ts):
                    deduped[key] = computer
        logger.info(f"After dedup by hostname: {len(deduped)} unique hosts (from {len(all_computers)} entries)")

        # Filter for unhealthy hosts (last seen > threshold, based on device type)
        now = datetime.now(timezone.utc)
        server_threshold = now - timedelta(days=UNHEALTHY_THRESHOLD_DAYS_SERVER)
        workstation_threshold = now - timedelta(days=UNHEALTHY_THRESHOLD_DAYS_WORKSTATION)

        unhealthy_hosts = []
        for computer in deduped.values():
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

    @staticmethod
    def _ssh_ping_available() -> bool:
        """Check if reverse SSH tunnel to Mac is available for remote pings."""
        if not REVERSE_SSH_USER:
            return False
        try:
            result = subprocess.run(
                ["ssh", "-p", str(REVERSE_SSH_PORT), "-o", "BatchMode=yes",
                 "-o", "ConnectTimeout=3", f"{REVERSE_SSH_USER}@localhost", "echo", "ok"],
                capture_output=True, text=True, timeout=5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    def _ping_via_ssh(self, unique_names: List[str],
                      ip_by_hostname: Optional[Dict[str, str]] = None) -> Dict[str, tuple]:
        """Ping hosts through Mac reverse SSH tunnel (batch all pings in one SSH session).

        Tries FQDN first; if that fails and an IP is available, retries by IP.
        """
        ip_map = ip_by_hostname or {}
        targets_map = {}  # FQDN target -> original hostname
        ip_for_target = {}  # FQDN target -> fallback IP
        for h in unique_names:
            target = h if h.endswith(PING_DOMAIN_SUFFIX) else h + PING_DOMAIN_SUFFIX
            targets_map[target] = h
            key = h.split('.')[0].lower()
            ip = ip_map.get(key, "")
            if ip:
                ip_for_target[target] = ip

        # Build pairs: "fqdn,ip" (ip may be empty)
        pairs = []
        for target in targets_map:
            ip = ip_for_target.get(target, "")
            pairs.append(shlex.quote(f"{target},{ip}"))
        pairs_args = ' '.join(pairs)

        script = f'''
for pair in {pairs_args}; do
    host="${{pair%%,*}}"
    ip="${{pair##*,}}"
    (
        if result=$(ping -c 1 -t 2 "$host" 2>/dev/null); then
            latency=$(echo "$result" | grep -o 'time=[0-9.]*' | head -1 | cut -d= -f2)
            printf '%s|OK|%s\\n' "$host" "$latency"
        elif [ -n "$ip" ]; then
            if result=$(ping -c 1 -t 2 "$ip" 2>/dev/null); then
                latency=$(echo "$result" | grep -o 'time=[0-9.]*' | head -1 | cut -d= -f2)
                printf '%s|OK|%s\\n' "$host" "$latency"
            else
                printf '%s|FAIL|\\n' "$host"
            fi
        else
            printf '%s|FAIL|\\n' "$host"
        fi
    ) &
done
wait
'''
        ping_results = {}
        try:
            proc = subprocess.Popen(
                ["ssh", "-p", str(REVERSE_SSH_PORT), "-o", "BatchMode=yes",
                 "-o", "ConnectTimeout=5", f"{REVERSE_SSH_USER}@localhost", "bash"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True,
            )
            proc.stdin.write(script)
            proc.stdin.close()

            for line in proc.stdout:
                line = line.strip()
                if not line or '|' not in line:
                    continue
                parts = line.split('|', 2)
                if len(parts) != 3:
                    continue
                target, status, latency_str = parts
                hostname = targets_map.get(target, target)
                latency = None
                if latency_str:
                    try:
                        latency = float(latency_str)
                    except ValueError:
                        pass
                key = hostname.split('.')[0].lower()
                ping_results[key] = (status == 'OK', latency)

            proc.wait(timeout=30)
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.warning(f"SSH ping session error: {e}")

        # Fill in any hosts that didn't return a result
        for h in unique_names:
            key = h.split('.')[0].lower()
            if key not in ping_results:
                ping_results[key] = (False, None)

        return ping_results

    def _ping_local(self, unique_names: List[str]) -> Dict[str, tuple]:
        """Ping hosts directly from this machine (fallback)."""
        is_mac = platform.system() == "Darwin"
        timeout_flag = "-t" if is_mac else "-W"

        def ping_one(hostname: str):
            target = hostname if hostname.endswith(PING_DOMAIN_SUFFIX) else hostname + PING_DOMAIN_SUFFIX
            try:
                result = subprocess.run(
                    ["ping", "-c", "1", timeout_flag, "2", target],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0:
                    latency = None
                    for line in result.stdout.splitlines():
                        if "time=" in line:
                            try:
                                latency = float(line.split("time=")[1].split()[0].rstrip("ms"))
                            except (ValueError, IndexError):
                                pass
                            break
                    return hostname, True, latency
                return hostname, False, None
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                return hostname, False, None

        ping_results = {}
        with ThreadPoolExecutor(max_workers=MAX_WORKERS_PING) as executor:
            futures = {executor.submit(ping_one, h): h for h in unique_names}
            for future in track(as_completed(futures), total=len(futures),
                                description="Pinging hosts",
                                disable=not logger.isEnabledFor(logging.INFO)):
                hostname, reachable, latency = future.result()
                key = hostname.split('.')[0].lower()
                ping_results[key] = (reachable, latency)

        return ping_results

    def ping_hosts(self, hosts: List[UnhealthyHost]) -> List[UnhealthyHost]:
        """
        Ping each unique hostname to determine network reachability.

        Routes pings through the Mac reverse SSH tunnel (port 2222) when
        available, since this VM is not on the corporate network. Falls
        back to local pings if the tunnel is down.

        Args:
            hosts: List of unhealthy hosts to ping

        Returns:
            Same list with ping_reachable and ping_latency_ms populated
        """
        if not hosts:
            return hosts

        # Deduplicate by short hostname (same key used in get_unhealthy_hosts)
        unique_hostnames = {}
        ip_by_hostname = {}  # key -> ip_address (for DNS fallback)
        for host in hosts:
            key = host.hostname.split('.')[0].lower()
            if key not in unique_hostnames:
                unique_hostnames[key] = host.hostname
            if host.ip_address and key not in ip_by_hostname:
                ip_by_hostname[key] = host.ip_address

        unique_names = list(unique_hostnames.values())
        logger.info(f"Pinging {len(unique_names)} unique hosts...")

        use_ssh = self._ssh_ping_available()
        if use_ssh:
            logger.info("Routing pings through Mac reverse SSH tunnel (port %d)", REVERSE_SSH_PORT)
            ping_results = self._ping_via_ssh(unique_names, ip_by_hostname)
        else:
            logger.warning("SSH tunnel unavailable — falling back to local pings (may not reach internal hosts)")
            ping_results = self._ping_local(unique_names)

        # Apply results to all hosts
        for host in hosts:
            key = host.hostname.split('.')[0].lower()
            result = ping_results.get(key)
            if result:
                host.ping_reachable, host.ping_latency_ms = result

        reachable = sum(1 for r in ping_results.values() if r[0])
        logger.info(f"Ping complete: {reachable} reachable, {len(ping_results) - reachable} unreachable")

        return hosts

    def enrich_with_crowdstrike(self, hosts: List[UnhealthyHost]) -> List[UnhealthyHost]:
        """
        Check CrowdStrike status for ALL hosts using batched API calls.

        Steps:
        1. Batch query device IDs by hostname (100 per call)
        2. Batch fetch device details for found IDs (last_seen, status, tags)
        3. Filter by last_seen to find hosts that pass the 24h threshold
        4. Batch fetch online state only for those hosts (saves API calls)

        Args:
            hosts: List of hosts to check

        Returns:
            List of hosts enriched with CrowdStrike data
        """
        if not hosts:
            return hosts

        logger.info(f"Checking CrowdStrike status for {len(hosts)} hosts (batched)...")

        cs_client = CrowdStrikeClient()
        batch_size = 100

        # Build lookup: short_hostname -> host object
        # Tanium returns FQDNs (e.g. HOST.internal.local), CS stores short hostnames
        short_to_host: Dict[str, UnhealthyHost] = {}
        for host in hosts:
            short = host.hostname.split('.')[0].upper()
            short_to_host[short] = host

        short_hostnames = list(short_to_host.keys())

        # Step 1: Batch query device IDs + details
        # query_devices_by_filter returns device IDs, then get_device_details returns full info
        logger.info(f"  Step 1: Querying device IDs in {len(range(0, len(short_hostnames), batch_size))} batches...")
        device_map: Dict[str, Dict[str, Any]] = {}  # short_hostname_upper -> {device_id, last_seen, status, tags}

        for i in range(0, len(short_hostnames), batch_size):
            batch = short_hostnames[i:i + batch_size]
            host_filter = "hostname:['" + "','".join(batch) + "']"

            try:
                response = cs_client.hosts_client.query_devices_by_filter(
                    filter=host_filter, limit=len(batch)
                )
                if response.get("status_code") != 200:
                    continue

                device_ids = response["body"].get("resources", [])
                if not device_ids:
                    continue

                # Batch get device details
                details_response = cs_client.hosts_client.get_device_details_v2(ids=device_ids)
                if details_response.get("status_code") != 200:
                    continue

                for device in details_response["body"].get("resources", []):
                    cs_hostname = (device.get("hostname") or "").upper()
                    if cs_hostname in short_to_host:
                        device_map[cs_hostname] = {
                            "device_id": device.get("device_id", ""),
                            "last_seen": device.get("last_seen", ""),
                            "status": device.get("status", ""),
                            "tags": device.get("tags", []),
                        }
            except Exception as e:
                logger.warning(f"Error in CS batch query (batch {i // batch_size + 1}): {e}")

        # Apply device details to hosts and mark not-found
        for short, host in short_to_host.items():
            info = device_map.get(short)
            if info:
                host.cs_status = "Found"
                host.cs_last_seen = info["last_seen"]
                host.cs_device_status = info["status"]
                host.cs_tags = info["tags"]
            else:
                host.cs_status = "Not Found"

        found_count = sum(1 for h in hosts if h.cs_status == "Found")
        logger.info(f"  Found {found_count}/{len(hosts)} hosts in CrowdStrike")

        # Step 2: Batch get online state only for hosts that pass the last_seen filter
        # (saves API calls — no point checking online state for hosts we'll filter out)
        now = datetime.now(timezone.utc)
        cs_threshold = now - timedelta(hours=CS_LAST_SEEN_THRESHOLD_HOURS)

        ids_needing_online_state = []
        id_to_host: Dict[str, UnhealthyHost] = {}
        for short, host in short_to_host.items():
            info = device_map.get(short)
            if not info:
                continue
            cs_last_seen = self._parse_last_seen(info["last_seen"])
            if cs_last_seen and cs_last_seen >= cs_threshold:
                ids_needing_online_state.append(info["device_id"])
                id_to_host[info["device_id"]] = host

        logger.info(f"  Step 2: Fetching online state for {len(ids_needing_online_state)} hosts "
                    f"(seen in CS within {CS_LAST_SEEN_THRESHOLD_HOURS}h)...")

        for i in range(0, len(ids_needing_online_state), batch_size):
            batch_ids = ids_needing_online_state[i:i + batch_size]
            try:
                response = cs_client.hosts_client.get_online_state(ids=batch_ids)
                if response.get("status_code") == 200:
                    for resource in response["body"].get("resources", []):
                        device_id = resource.get("id", "")
                        state = resource.get("state", "")
                        host = id_to_host.get(device_id)
                        if host:
                            host.cs_online_status = state
            except Exception as e:
                logger.warning(f"Error in CS online state batch: {e}")

        # Log summary
        not_found_count = sum(1 for h in hosts if h.cs_status == "Not Found")
        online_count = sum(1 for h in hosts if h.cs_online_status == "online")
        logger.info(f"CrowdStrike check complete: {found_count} found, {not_found_count} not found, {online_count} online")

        return hosts

    def filter_by_cs_last_seen(self, hosts: List[UnhealthyHost]) -> List[UnhealthyHost]:
        """
        Filter to hosts that are truly unhealthy: either seen in CrowdStrike within
        the last CS_LAST_SEEN_THRESHOLD_HOURS (machine is on but Tanium agent is broken)
        or not found in CrowdStrike at all (risky — no EDR visibility).

        Hosts found in CS but NOT seen recently are likely just powered off — excluded.

        Args:
            hosts: List of CS-enriched hosts

        Returns:
            Filtered list of truly unhealthy hosts
        """
        now = datetime.now(timezone.utc)
        cs_threshold = now - timedelta(hours=CS_LAST_SEEN_THRESHOLD_HOURS)

        truly_unhealthy = []
        excluded_powered_off = 0

        for host in hosts:
            # Not found in CS → risky, keep
            if host.cs_status == "Not Found":
                truly_unhealthy.append(host)
                continue

            # Error checking CS → keep to be safe
            if host.cs_status != "Found":
                truly_unhealthy.append(host)
                continue

            # Found in CS — check last_seen
            cs_last_seen = self._parse_last_seen(host.cs_last_seen)
            if cs_last_seen and cs_last_seen >= cs_threshold:
                # Seen recently in CS → truly unhealthy (Tanium agent broken)
                truly_unhealthy.append(host)
            else:
                # Not seen recently in CS → probably powered off
                excluded_powered_off += 1

        logger.info(f"CS last-seen filter: {len(truly_unhealthy)} truly unhealthy, "
                    f"{excluded_powered_off} excluded (likely powered off)")

        return truly_unhealthy

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
                'Pingable': 'Yes' if host.ping_reachable else ('No' if host.ping_reachable is False else ''),
                'Ping Latency (ms)': host.ping_latency_ms if host.ping_latency_ms else '',
                'SNOW Status': host.snow_status,
                'SNOW Lifecycle': host.snow_lifecycle_status,
                'SNOW Environment': host.snow_environment,
                'SNOW CI Class': host.snow_ci_class,
                'SNOW Country': host.snow_country,
                'CS Status': host.cs_status,
                'CS Last Seen': host.cs_last_seen,
                'CS Online State': host.cs_online_status,
                'CS Device Status': host.cs_device_status,
                'CS Tags': ', '.join(host.cs_tags) if host.cs_tags else '',
                'RTR Candidate': 'Yes' if host.is_rtr_candidate else 'No',
                'RTR Candidate Reason': host.rtr_candidate_reason
            })

        df = pd.DataFrame(data)

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
            'pingable': 10,
            'ping latency (ms)': 16,
            'snow status': 15,
            'snow lifecycle': 15,
            'snow environment': 15,
            'snow ci class': 15,
            'snow country': 15,
            'cs status': 15,
            'cs last seen': 25,
            'cs online state': 15,
            'cs device status': 15,
            'cs tags': 40,
            'rtr candidate': 12,
            'rtr candidate reason': 50
        }
        wrap_columns = {'current tags', 'rtr candidate reason', 'unhealthy reason', 'cs tags'}
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

            # Step 2: CrowdStrike enrichment (all hosts — needed for last-seen filter)
            if not skip_cs_check:
                logger.info("=" * 60)
                logger.info("Step 2: Checking CrowdStrike status for all hosts...")
                hosts = self.enrich_with_crowdstrike(hosts)

                # Step 3: Filter to truly unhealthy (seen in CS within 24h OR not found in CS)
                logger.info("=" * 60)
                logger.info("Step 3: Filtering by CrowdStrike last seen...")
                pre_filter_count = len(hosts)
                hosts = self.filter_by_cs_last_seen(hosts)
                logger.info(f"  Filtered: {pre_filter_count} → {len(hosts)} hosts")

                if not hosts:
                    logger.warning("No truly unhealthy hosts after CS filter!")
                    return self._create_empty_report()
            else:
                logger.info("Steps 2-3: Skipping CrowdStrike check (skip_cs_check=True)")

            # Step 4: Ping hosts
            logger.info("=" * 60)
            logger.info("Step 4: Pinging hosts for network reachability...")
            hosts = self.ping_hosts(hosts)

            # Step 5: Enrich with ServiceNow CMDB data
            logger.info("=" * 60)
            logger.info("Step 5: Enriching with ServiceNow CMDB data...")
            hosts = self.enrich_with_servicenow(hosts)

            # Step 6: Determine RTR candidates
            logger.info("=" * 60)
            logger.info("Step 6: Determining RTR remediation candidates...")
            hosts = self.determine_rtr_candidates(hosts)

            # Step 7: Export report
            logger.info("=" * 60)
            logger.info("Step 7: Generating Excel report...")
            report_path = self.export_to_excel(hosts)

            # Final summary
            logger.info("=" * 60)
            logger.info("Processing complete!")
            logger.info(f"  Total unhealthy hosts: {len(hosts)}")
            logger.info(f"  Pingable: {sum(1 for h in hosts if h.ping_reachable)}")
            logger.info(f"  Not found in CrowdStrike (risk): {sum(1 for h in hosts if h.cs_status == 'Not Found')}")
            logger.info(f"  Online in CrowdStrike: {sum(1 for h in hosts if h.cs_online_status == 'online')}")
            logger.info(f"  Found in ServiceNow: {sum(1 for h in hosts if h.snow_status == 'Found')}")
            logger.info(f"  Operational/Pipeline in SNOW: {sum(1 for h in hosts if h.snow_lifecycle_status.lower() in RTR_ELIGIBLE_LIFECYCLE_STATUSES)}")
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
            'Pingable', 'Ping Latency (ms)',
            'SNOW Status', 'SNOW Lifecycle', 'SNOW Environment', 'SNOW CI Class', 'SNOW Country',
            'CS Status', 'CS Last Seen', 'CS Online State', 'CS Device Status', 'CS Tags',
            'RTR Candidate', 'RTR Candidate Reason'
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
