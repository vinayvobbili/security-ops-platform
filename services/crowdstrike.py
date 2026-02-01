import urllib3
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)

import concurrent.futures
import logging
import sys
import time
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, Optional, Any, List

import pandas as pd
import requests
import tqdm

from falconpy import Hosts, OAuth2, Detects, Incidents, Alerts, IOC, Intel
from my_config import get_config
from src.utils.http_utils import get_session

# Setup logger
logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent.parent / "data" / "transient" / "epp_device_tagging"
CS_FETCH_MAX_WORKERS = 10

# Get robust HTTP session instance
http_session = get_session()


class CSCredentialProfile(Enum):
    """CrowdStrike API credential profiles for different permission levels."""
    READ = "read"
    WRITE = "write"
    RTR = "rtr"


class CrowdStrikeClient:
    """Client for interacting with the CrowdStrike Falcon API."""

    def __init__(self, credential_profile: CSCredentialProfile = CSCredentialProfile.READ, max_workers: Optional[int] = None):
        self.config = get_config()
        self.base_url = "api.us-2.crowdstrike.com"
        self.proxies = self._setup_proxy()
        self.last_error: str | None = None  # Stores last API/auth error for better error reporting
        if self.proxies:
            logger.info(f"[CrowdStrikeClient] Proxy enabled: {self.proxies}")
        else:
            logger.info("[CrowdStrikeClient] Proxy not enabled.")
        self.credential_profile = credential_profile
        self.auth = self._create_auth()
        self.hosts_client = Hosts(auth_object=self.auth, timeout=30)
        self.detects_client = Detects(auth_object=self.auth, timeout=30)
        self.alerts_client = Alerts(auth_object=self.auth, timeout=30)
        self.incidents_client = Incidents(auth_object=self.auth, timeout=30)
        # Allow thread pool size to be set via env or parameter
        self.max_workers = max_workers or CS_FETCH_MAX_WORKERS

    def _get_client_id_secret(self):
        match self.credential_profile:
            case CSCredentialProfile.READ:
                return self.config.cs_ro_client_id, self.config.cs_ro_client_secret
            case CSCredentialProfile.WRITE:
                return self.config.cs_host_write_client_id, self.config.cs_host_write_client_secret
            case CSCredentialProfile.RTR:
                return self.config.cs_rtr_client_id, self.config.cs_rtr_client_secret

    def _setup_proxy(self):
        """Setup proxy configuration if jump server is enabled"""
        if not self.config.should_use_jump_server:
            return None

        proxy_url = f"http://{self.config.jump_server_host}:8081"
        return {"http": proxy_url, "https": proxy_url}

    def _create_auth(self):
        client_id, client_secret = self._get_client_id_secret()
        """Create OAuth2 authentication object"""
        return OAuth2(
            client_id=client_id,
            client_secret=client_secret,
            base_url=self.base_url,
            ssl_verify=False,
            proxy=self.proxies,
            timeout=30  # 30 second timeout to prevent indefinite hangs
        )

    def get_access_token(self) -> str:
        """Get CrowdStrike access token using direct API call"""
        url = f'https://{self.base_url}/oauth2/token'
        client_id, client_secret = self._get_client_id_secret()
        body = {
            'client_id': client_id,
            'client_secret': client_secret
        }

        response = http_session.post(url, data=body, verify=False, proxies=self.proxies)
        if response is None:
            raise requests.exceptions.ConnectionError("Failed to connect after multiple retries")
        response.raise_for_status()
        return response.json()['access_token']

    def validate_auth(self) -> bool:
        """Validate that CrowdStrike API authentication is working.

        Makes a simple API call to verify credentials are valid.
        Stores any error in self.last_error for better error reporting.

        Returns:
            True if authentication is valid, False otherwise.
        """
        try:
            # Use a minimal query to validate auth - limit=1 for efficiency
            response = self.hosts_client.query_devices_by_filter_scroll(limit=1)

            if response.get("status_code") == 200:
                self.last_error = None
                logger.info("CrowdStrike API authentication validated successfully")
                return True

            # Extract error details from response
            status_code = response.get("status_code", "Unknown")
            errors = response.get("body", {}).get("errors", [])
            if errors:
                error_msg = "; ".join(e.get("message", str(e)) for e in errors)
                self.last_error = f"HTTP {status_code} - {error_msg}"
            else:
                self.last_error = f"HTTP {status_code} - {response.get('body', {})}"

            logger.warning(f"CrowdStrike API authentication failed: {self.last_error}")
            return False

        except Exception as e:
            self.last_error = str(e)
            logger.warning(f"CrowdStrike API authentication failed: {self.last_error}")
            return False

    def get_device_ids_batch(self, hostnames, batch_size=100):
        """Get device IDs for multiple hostnames in batches"""
        results = {}
        for i in range(0, len(hostnames), batch_size):
            batch = hostnames[i:i + batch_size]
            host_filter = f"hostname:['{'', ''.join(batch)}']"

            response = self.hosts_client.query_devices_by_filter(
                filter=host_filter,
                limit=len(batch)
            )

            if response.get("status_code") == 200:
                device_ids = response["body"].get("resources", [])
                if device_ids:
                    details = self.hosts_client.get_device_details(ids=device_ids)
                    if details.get("status_code") == 200:
                        for device in details["body"].get("resources", []):
                            hostname = device.get("hostname")
                            device_id = device.get("device_id")
                            if hostname and device_id:
                                results[hostname] = device_id

        return results

    def get_device_id(self, hostname: str) -> Optional[str]:
        """Retrieve the device ID for a given hostname"""
        host_filter = f"hostname:'{hostname}'"
        response = self.hosts_client.query_devices_by_filter(
            filter=host_filter,
            sort='last_seen.desc',
            limit=1
        )

        if response.get("status_code") == 200:
            devices = response["body"].get("resources", [])
            return devices[0] if devices else None

        return None

    def get_device_details(self, device_id: str) -> Dict[str, Any]:
        """Retrieve details for a specific device"""
        response = self.hosts_client.get_device_details_v2(ids=device_id)
        if response.get("status_code") == 200:
            resources = response["body"].get("resources", [])
            return resources[0] if resources else {}

        return {}

    def get_device_containment_status(self, hostname: str) -> Optional[str]:
        """Get containment status for a device using hostname"""
        device_id = self.get_device_id(hostname)
        if not device_id:
            return 'Host not found in CS console or an error occurred.'

        device_details = self.get_device_details(device_id)
        return device_details.get("status")

    def fetch_all_hosts_and_write_to_xlsx(self, xlsx_filename: str = "all_cs_hosts.xlsx") -> None:
        """Fetch all hosts from CrowdStrike Falcon using multithreading.

        Raises:
            ConnectionError: If authentication fails or no hosts could be retrieved,
                           includes the actual error message from the API.
        """
        import logging
        logger = logging.getLogger(__name__)

        # Validate authentication first
        if not self.validate_auth():
            raise ConnectionError(f"CrowdStrike API authentication failed: {self.last_error}")

        all_host_data = []
        unique_device_ids = set()
        offset = None
        limit = 5000
        batch_count = 0
        start_time = time.time()
        api_error = None  # Track API errors during fetch

        def process_host_details(host_ids_batch: List[str]) -> None:
            """Thread worker to process a batch of host IDs"""
            details_response = self.hosts_client.get_device_details(ids=host_ids_batch)
            if details_response["status_code"] != 200:
                return

            host_details = details_response["body"].get("resources", [])
            for host in host_details:
                device_id = host.get("device_id")
                if not device_id or device_id in unique_device_ids:
                    continue

                unique_device_ids.add(device_id)
                host_data = {
                    "hostname": host.get("hostname"),
                    "host_id": device_id,
                    "current_tags": ", ".join(host.get("tags", [])),
                    "last_seen": host.get("last_seen"),
                    "status": host.get("status"),
                    "cs_host_category": host.get("product_type_desc"),
                    "chassis_type_desc": host.get("chassis_type_desc"),
                }
                all_host_data.append(host_data)

        logger.info(f"Starting fetch_all_hosts_and_write_to_xlsx with max_workers={self.max_workers}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            while True:
                # Refresh auth token every 10 batches
                if batch_count > 0 and batch_count % 10 == 0:
                    self.auth = self._create_auth()
                    self.hosts_client = Hosts(auth_object=self.auth, timeout=30)

                response = self.hosts_client.query_devices_by_filter_scroll(
                    limit=limit, offset=offset
                )

                if response["status_code"] != 200:
                    # Capture the error details for better reporting
                    status_code = response.get("status_code", "Unknown")
                    errors = response.get("body", {}).get("errors", [])
                    if errors:
                        error_msg = "; ".join(e.get("message", str(e)) for e in errors)
                        api_error = f"HTTP {status_code} - {error_msg}"
                    else:
                        api_error = f"HTTP {status_code} - {response.get('body', {})}"
                    logger.error(f"CrowdStrike API error during host fetch: {api_error}")
                    self.last_error = api_error
                    break

                host_ids = response["body"].get("resources", [])
                if not host_ids:
                    break

                # Process in batches of 1000
                host_id_batches = [host_ids[i:i + 1000] for i in range(0, len(host_ids), 1000)]

                # Log for VM/non-interactive sessions
                logger.info(f"Processing batch {batch_count + 1}: {len(host_ids)} host IDs in {len(host_id_batches)} sub-batches")

                # Process with tqdm (shows progress bar locally, silent on VM)
                futures = [
                    executor.submit(process_host_details, id_batch)
                    for id_batch in tqdm.tqdm(host_id_batches, desc=f"Batch {batch_count + 1}", disable=not sys.stdout.isatty())
                ]
                concurrent.futures.wait(futures)

                batch_count += 1
                # Log completion for VM/non-interactive sessions
                logger.info(f"Completed batch {batch_count}, total hosts fetched so far: {len(all_host_data)}")
                offset = response["body"].get("meta", {}).get("pagination", {}).get("offset")
                if not offset:
                    break

                time.sleep(0.5)

        elapsed = time.time() - start_time
        logger.info(f"Completed fetch_all_hosts_and_write_to_xlsx in {elapsed:.2f} seconds. Total hosts: {len(all_host_data)}")

        # If no hosts were retrieved, and we had an API error, raise with details
        if not all_host_data and api_error:
            raise ConnectionError(f"No hosts retrieved from CrowdStrike. {api_error}")

        # Write to Excel
        today_date = datetime.now().strftime('%m-%d-%Y')
        output_path = DATA_DIR / today_date
        output_path.mkdir(parents=True, exist_ok=True)

        df = pd.DataFrame(all_host_data)
        excel_file_path = output_path / xlsx_filename
        df.to_excel(excel_file_path, index=False, engine='openpyxl')

        # Apply professional formatting
        from src.utils.excel_formatting import apply_professional_formatting
        apply_professional_formatting(excel_file_path)

    def update_device_tags(self, action_name: str, ids: list, tags: list) -> dict:
        """Update device tags (add/remove) for a list of device IDs."""
        return self.hosts_client.update_device_tags(
            action_name=action_name,
            ids=ids,
            tags=tags
        )

    def get_device_online_state(self, hostname: str) -> Optional[str]:
        """Get the online state for a single hostname."""
        device_id = self.get_device_id(hostname)
        if not device_id:
            return None
        response = self.hosts_client.get_online_state(ids=[device_id])
        if response.get("status_code") == 200:
            resources = response['body'].get('resources', [])
            if resources:
                return resources[0].get('state')
        return None

    def get_detections(
        self,
        limit: int = 20,
        filter_query: Optional[str] = None,
        sort: str = "created_timestamp|desc"
    ) -> Dict[str, Any]:
        """Query CrowdStrike alerts/detections using the new Alerts API.

        Args:
            limit: Maximum number of alerts to return
            filter_query: FQL filter string (e.g., "status:'new'" or "device.hostname:'WORKSTATION01'")
            sort: Sort order (default: most recent first)

        Returns:
            Dict containing alert details or error info
        """
        try:
            # Query alert IDs using the new Alerts API
            query_params = {"limit": limit, "sort": sort}
            if filter_query:
                query_params["filter"] = filter_query

            response = self.alerts_client.query_alerts_v2(**query_params)

            if response.get("status_code") != 200:
                error_msg = response.get("body", {}).get("errors", [{}])
                return {"error": f"Failed to query alerts: {error_msg}"}

            alert_ids = response.get("body", {}).get("resources", [])

            if not alert_ids:
                return {"results": [], "total": 0}

            # Get alert details using composite IDs
            details_response = self.alerts_client.get_alerts_v2(composite_ids=alert_ids)

            if details_response.get("status_code") != 200:
                return {"error": "Failed to retrieve alert details"}

            alerts = details_response.get("body", {}).get("resources", [])
            return {"results": alerts, "total": len(alerts)}

        except Exception as e:
            logger.error(f"Error querying CrowdStrike alerts: {e}")
            return {"error": str(e)}

    def get_detection_by_id(self, detection_id: str) -> Dict[str, Any]:
        """Get detailed information for a specific alert/detection.

        Args:
            detection_id: The alert composite ID

        Returns:
            Dict containing alert details or error info
        """
        try:
            response = self.alerts_client.get_alerts_v2(composite_ids=[detection_id])

            if response.get("status_code") != 200:
                return {"error": f"Failed to get alert {detection_id}"}

            resources = response.get("body", {}).get("resources", [])
            if not resources:
                return {"error": f"Alert {detection_id} not found"}

            return resources[0]

        except Exception as e:
            logger.error(f"Error getting CrowdStrike alert {detection_id}: {e}")
            return {"error": str(e)}

    def get_detections_by_hostname(self, hostname: str, limit: int = 20) -> Dict[str, Any]:
        """Get alerts/detections for a specific hostname.

        Args:
            hostname: The hostname to search for
            limit: Maximum number of alerts to return

        Returns:
            Dict containing alert details or error info
        """
        filter_query = f"device.hostname:'{hostname}'"
        return self.get_detections(limit=limit, filter_query=filter_query)

    def get_incidents(
        self,
        limit: int = 20,
        filter_query: Optional[str] = None,
        sort: str = "start|desc"
    ) -> Dict[str, Any]:
        """Query CrowdStrike incidents.

        Args:
            limit: Maximum number of incidents to return
            filter_query: FQL filter string (e.g., "status:'20'" for new incidents)
            sort: Sort order (default: most recent first)

        Returns:
            Dict containing incident details or error info
        """
        try:
            # Query incident IDs
            query_params = {"limit": limit, "sort": sort}
            if filter_query:
                query_params["filter"] = filter_query

            response = self.incidents_client.query_incidents(**query_params)

            if response.get("status_code") != 200:
                error_msg = response.get("body", {}).get("errors", [{}])
                return {"error": f"Failed to query incidents: {error_msg}"}

            incident_ids = response.get("body", {}).get("resources", [])

            if not incident_ids:
                return {"results": [], "total": 0}

            # Get incident details
            details_response = self.incidents_client.get_incidents(ids=incident_ids)

            if details_response.get("status_code") != 200:
                return {"error": "Failed to retrieve incident details"}

            incidents = details_response.get("body", {}).get("resources", [])
            return {"results": incidents, "total": len(incidents)}

        except Exception as e:
            logger.error(f"Error querying CrowdStrike incidents: {e}")
            return {"error": str(e)}

    def get_incident_by_id(self, incident_id: str) -> Dict[str, Any]:
        """Get detailed information for a specific incident.

        Args:
            incident_id: The incident ID

        Returns:
            Dict containing incident details or error info
        """
        try:
            response = self.incidents_client.get_incidents(ids=[incident_id])

            if response.get("status_code") != 200:
                return {"error": f"Failed to get incident {incident_id}"}

            resources = response.get("body", {}).get("resources", [])
            if not resources:
                return {"error": f"Incident {incident_id} not found"}

            return resources[0]

        except Exception as e:
            logger.error(f"Error getting CrowdStrike incident {incident_id}: {e}")
            return {"error": str(e)}

    # ==================== IOC Search Methods ====================

    def search_ioc_by_value(self, ioc_value: str, ioc_type: str = None) -> Dict[str, Any]:
        """Search for a custom IOC in CrowdStrike.

        Args:
            ioc_value: The IOC value (IP, domain, hash, etc.)
            ioc_type: Optional IOC type filter (ipv4, domain, md5, sha256)

        Returns:
            Dict with IOC details or error
        """
        try:
            ioc_client = IOC(auth_object=self.auth, timeout=30)

            # Build filter
            filter_str = f"value:'{ioc_value}'"
            if ioc_type:
                filter_str += f"+type:'{ioc_type}'"

            response = ioc_client.indicator_combined_v1(filter=filter_str, limit=100)

            if response.get("status_code") != 200:
                error_msg = response.get("body", {}).get("errors", [])
                return {"error": f"IOC search failed: {error_msg}"}

            resources = response.get("body", {}).get("resources", [])
            return {
                "count": len(resources),
                "indicators": resources
            }

        except Exception as e:
            logger.error(f"Error searching IOC {ioc_value}: {e}")
            return {"error": str(e)}

    def search_detections_by_ip(self, ip: str, hours: int = 168) -> Dict[str, Any]:
        """Search for detections involving an IP address.

        Args:
            ip: The IP address to search for
            hours: Hours to look back

        Returns:
            Dict with detection results or error
        """
        from datetime import timedelta, timezone

        try:
            start_date = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

            # Search in local_ip and external_ip fields
            filter_str = f"(device.local_ip:'{ip}'+device.external_ip:'{ip}')+created_timestamp:>='{start_date}'"

            response = self.detects_client.query_detects(filter=filter_str, limit=100)

            if response.get("status_code") != 200:
                error_msg = response.get("body", {}).get("errors", [])
                return {"error": f"Detection search failed: {error_msg}"}

            detection_ids = response.get("body", {}).get("resources", [])

            if not detection_ids:
                return {"count": 0, "detections": [], "fql_query": filter_str}

            # Get detection details
            details_resp = self.detects_client.get_detect_summaries(ids=detection_ids[:20])
            if details_resp.get("status_code") == 200:
                detections = details_resp.get("body", {}).get("resources", [])
                return {
                    "count": len(detection_ids),
                    "detections": detections,
                    "fql_query": filter_str
                }

            return {"count": len(detection_ids), "detections": [], "fql_query": filter_str}

        except Exception as e:
            logger.error(f"Error searching detections by IP {ip}: {e}")
            return {"error": str(e)}

    def search_detections_by_hash(self, file_hash: str, hours: int = 168) -> Dict[str, Any]:
        """Search for detections involving a file hash.

        Args:
            file_hash: The MD5 or SHA256 hash to search for
            hours: Hours to look back

        Returns:
            Dict with detection results or error
        """
        from datetime import timedelta, timezone

        try:
            start_date = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

            # Determine hash type and build filter
            if len(file_hash) == 32:
                filter_str = f"md5:'{file_hash}'"
            else:
                filter_str = f"sha256:'{file_hash}'"

            filter_str += f"+created_timestamp:>='{start_date}'"

            response = self.detects_client.query_detects(filter=filter_str, limit=100)

            if response.get("status_code") != 200:
                error_msg = response.get("body", {}).get("errors", [])
                return {"error": f"Detection search failed: {error_msg}"}

            detection_ids = response.get("body", {}).get("resources", [])

            if not detection_ids:
                return {"count": 0, "detections": [], "fql_query": filter_str}

            # Get detection details
            details_resp = self.detects_client.get_detect_summaries(ids=detection_ids[:20])
            if details_resp.get("status_code") == 200:
                detections = details_resp.get("body", {}).get("resources", [])
                return {
                    "count": len(detection_ids),
                    "detections": detections,
                    "fql_query": filter_str
                }

            return {"count": len(detection_ids), "detections": [], "fql_query": filter_str}

        except Exception as e:
            logger.error(f"Error searching detections by hash {file_hash[:16]}...: {e}")
            return {"error": str(e)}

    def search_detections_by_filename(self, filename: str, hours: int = 168) -> Dict[str, Any]:
        """Search for detections involving a specific filename.

        Useful for hunting malicious scripts like install.ps1, install.sh, etc.

        Args:
            filename: The filename to search for (e.g., "install.ps1")
            hours: Hours to look back

        Returns:
            Dict with detection results or error
        """
        from datetime import timedelta, timezone

        try:
            start_date = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

            # Search in behaviors.filename field
            # Use wildcard to match the filename anywhere in the path
            filter_str = f"behaviors.filename:*'{filename}'"
            filter_str += f"+created_timestamp:>='{start_date}'"

            response = self.detects_client.query_detects(filter=filter_str, limit=100)

            if response.get("status_code") != 200:
                error_msg = response.get("body", {}).get("errors", [])
                return {"error": f"Detection search failed: {error_msg}"}

            detection_ids = response.get("body", {}).get("resources", [])

            if not detection_ids:
                return {"count": 0, "detections": [], "fql_query": filter_str}

            # Get detection details
            details_resp = self.detects_client.get_detect_summaries(ids=detection_ids[:20])
            if details_resp.get("status_code") == 200:
                detections = details_resp.get("body", {}).get("resources", [])
                return {
                    "count": len(detection_ids),
                    "detections": detections,
                    "fql_query": filter_str
                }

            return {"count": len(detection_ids), "detections": [], "fql_query": filter_str}

        except Exception as e:
            logger.error(f"Error searching detections by filename {filename}: {e}")
            return {"error": str(e)}

    def lookup_intel_indicator(self, indicator: str) -> Dict[str, Any]:
        """Lookup threat intelligence for an indicator (Falcon X).

        Args:
            indicator: The indicator value (IP, domain, hash, URL)

        Returns:
            Dict with intel results or error
        """
        try:
            intel_client = Intel(auth_object=self.auth, timeout=30)

            filter_str = f"indicator:'{indicator}'"
            response = intel_client.query_indicator_entities(
                filter=filter_str,
                limit=10
            )

            if response.get("status_code") != 200:
                error_msg = response.get("body", {}).get("errors", [])
                return {"error": f"Intel lookup failed: {error_msg}"}

            resources = response.get("body", {}).get("resources", [])
            return {
                "count": len(resources),
                "indicators": resources,
                "fql_query": filter_str
            }

        except Exception as e:
            logger.error(f"Error looking up intel for {indicator}: {e}")
            return {"error": str(e)}

    def search_threatgraph_domain(self, domain: str) -> Dict[str, Any]:
        """Search ThreatGraph for hosts that connected to a domain.

        Uses CrowdStrike's ThreatGraph API to find hosts that have
        DNS requests or network connections to the specified domain.

        Args:
            domain: The domain to search for

        Returns:
            Dict with vertex/edge results or error
        """
        try:
            from falconpy import ThreatGraph

            tg_client = ThreatGraph(auth_object=self.auth, timeout=30)

            # Build the query description for analysts
            query_str = f"ThreatGraph.combined_summary_get(ids=['{domain}'], vertex_types=['domain', 'host'], edge_types=['dns_request', 'communicates_with'])"

            # Search for domain indicator and get related hosts
            response = tg_client.combined_summary_get(
                ids=[domain],
                vertex_types=["domain", "host"],
                edge_types=["dns_request", "communicates_with"]
            )

            if response.get("status_code") != 200:
                error_msg = response.get("body", {}).get("errors", [])
                return {"error": f"ThreatGraph search failed: {error_msg}"}

            resources = response.get("body", {}).get("resources", [])
            # Extract affected hosts from the graph
            hosts = []
            for resource in resources:
                vertices = resource.get("vertices", {})
                for vertex_id, vertex in vertices.items():
                    if vertex.get("vertex_type") == "host":
                        hostname = vertex.get("properties", {}).get("hostname", "")
                        if hostname:
                            hosts.append(hostname)

            return {
                "count": len(hosts),
                "hosts": list(set(hosts))[:20],
                "raw": resources,
                "api_call": query_str
            }

        except Exception as e:
            logger.error(f"Error searching ThreatGraph for domain {domain}: {e}")
            return {"error": str(e)}

    def search_dns_requests(self, domain: str, hours: int = 168) -> Dict[str, Any]:
        """Search for DNS requests to a domain using detections/alerts.

        Searches for detections and alerts where the domain appears in
        network/DNS fields.

        Args:
            domain: The domain to search for
            hours: Hours to look back

        Returns:
            Dict with detection results or error
        """
        from datetime import timedelta, timezone

        try:
            start_date = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

            # Search detections for domain in network fields
            # behaviors.network_accesses contains domain info
            filter_str = f"behaviors.dns_requests.domain:*'{domain}'"
            filter_str += f"+created_timestamp:>='{start_date}'"

            response = self.detects_client.query_detects(filter=filter_str, limit=100)

            if response.get("status_code") != 200:
                # Fallback: try without the dns_requests filter (older API)
                filter_str = f"created_timestamp:>='{start_date}'"
                response = self.detects_client.query_detects(filter=filter_str, limit=100)

            detection_ids = response.get("body", {}).get("resources", [])

            if not detection_ids:
                return {"count": 0, "detections": [], "hosts": []}

            # Get detection details and filter for domain
            details_resp = self.detects_client.get_detect_summaries(ids=detection_ids[:50])
            matching_detections = []
            hosts = set()

            if details_resp.get("status_code") == 200:
                for det in details_resp.get("body", {}).get("resources", []):
                    # Check behaviors for domain references
                    for behavior in det.get("behaviors", []):
                        dns_requests = behavior.get("dns_requests", [])
                        network = behavior.get("network_accesses", [])

                        domain_found = False
                        for dns in dns_requests:
                            if domain.lower() in str(dns).lower():
                                domain_found = True
                                break
                        for net in network:
                            if domain.lower() in str(net).lower():
                                domain_found = True
                                break

                        if domain_found:
                            matching_detections.append(det)
                            hostname = det.get("device", {}).get("hostname")
                            if hostname:
                                hosts.add(hostname)
                            break

            return {
                "count": len(matching_detections),
                "detections": matching_detections[:10],
                "hosts": list(hosts)[:20]
            }

        except Exception as e:
            logger.error(f"Error searching DNS requests for {domain}: {e}")
            return {"error": str(e)}

    def search_alerts_by_ip(self, ip: str, hours: int = 168) -> Dict[str, Any]:
        """Search for alerts involving an IP address.

        Args:
            ip: The IP address to search for
            hours: Hours to look back

        Returns:
            Dict with alert results or error
        """
        from datetime import timedelta, timezone

        try:
            start_date = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

            filter_str = f"(device.local_ip:'{ip}',device.external_ip:'{ip}')+created_timestamp:>='{start_date}'"

            response = self.alerts_client.query_alerts_v1(filter=filter_str, limit=100)

            if response.get("status_code") != 200:
                error_msg = response.get("body", {}).get("errors", [])
                return {"error": f"Alert search failed: {error_msg}"}

            alert_ids = response.get("body", {}).get("resources", [])

            if not alert_ids:
                return {"count": 0, "alerts": [], "fql_query": filter_str}

            # Get alert details
            details_resp = self.alerts_client.get_alerts_v1(ids=alert_ids[:20])
            if details_resp.get("status_code") == 200:
                alerts = details_resp.get("body", {}).get("resources", [])
                return {
                    "count": len(alert_ids),
                    "alerts": alerts,
                    "fql_query": filter_str
                }

            return {"count": len(alert_ids), "alerts": [], "fql_query": filter_str}

        except Exception as e:
            logger.error(f"Error searching alerts by IP {ip}: {e}")
            return {"error": str(e)}

    # ==================== Detection Rules Catalog Methods ====================

    def list_custom_ioa_rule_groups(self) -> Dict[str, Any]:
        """List all custom IOA rule groups with their rules.

        Returns:
            Dict with rule_groups list or error
        """
        try:
            from falconpy import CustomIOA
            ioa_client = CustomIOA(auth_object=self.auth, timeout=30)

            # Query all rule group IDs
            query_resp = ioa_client.query_rule_groupsMixin0(limit=500)
            if query_resp.get("status_code") != 200:
                error_msg = query_resp.get("body", {}).get("errors", [])
                return {"error": f"IOA rule group query failed: {error_msg}"}

            group_ids = query_resp.get("body", {}).get("resources", [])
            if not group_ids:
                return {"rule_groups": [], "count": 0}

            # Get full details for each group (includes rules within)
            details_resp = ioa_client.get_rule_groupsMixin0(ids=group_ids)
            if details_resp.get("status_code") != 200:
                error_msg = details_resp.get("body", {}).get("errors", [])
                return {"error": f"IOA rule group details failed: {error_msg}"}

            groups = details_resp.get("body", {}).get("resources", [])
            return {"rule_groups": groups, "count": len(groups)}

        except Exception as e:
            logger.error(f"Error listing custom IOA rule groups: {e}")
            return {"error": str(e)}

    def list_ioc_indicators(self, limit: int = 500) -> Dict[str, Any]:
        """List custom IOC indicators from CrowdStrike.

        Args:
            limit: Maximum number of indicators to return

        Returns:
            Dict with indicators list or error
        """
        try:
            ioc_client = IOC(auth_object=self.auth, timeout=30)
            response = ioc_client.indicator_combined_v1(limit=limit)

            if response.get("status_code") != 200:
                error_msg = response.get("body", {}).get("errors", [])
                return {"error": f"IOC indicator list failed: {error_msg}"}

            resources = response.get("body", {}).get("resources", [])
            return {"indicators": resources, "count": len(resources)}

        except Exception as e:
            logger.error(f"Error listing IOC indicators: {e}")
            return {"error": str(e)}


def process_unique_hosts(df: pd.DataFrame) -> pd.DataFrame:
    """Process dataframe to get unique hosts with latest last_seen"""
    df["last_seen"] = pd.to_datetime(df["last_seen"], errors='coerce', utc=True).dt.tz_convert(None)  # type: ignore[union-attr]
    return df.loc[df.groupby("hostname")["last_seen"].idxmax()]


def update_unique_hosts_from_cs() -> None:
    """Group hosts by hostname and get the record with the latest last_seen for each"""
    cs_client = CrowdStrikeClient()
    cs_client.fetch_all_hosts_and_write_to_xlsx()

    # Read and process the file
    today_date = datetime.now().strftime('%m-%d-%Y')
    hosts_file = DATA_DIR / today_date / "all_cs_hosts.xlsx"
    df = pd.read_excel(hosts_file, engine="openpyxl")

    unique_hosts = process_unique_hosts(df)

    unique_hosts_file = DATA_DIR / today_date / "unique_cs_hosts.xlsx"
    unique_hosts_file.parent.mkdir(parents=True, exist_ok=True)
    unique_hosts.to_excel(unique_hosts_file, index=False, engine="openpyxl")

    # Apply professional formatting
    from src.utils.excel_formatting import apply_professional_formatting
    apply_professional_formatting(unique_hosts_file)


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="CrowdStrike API test utility")
    parser.add_argument("--test", type=int, choices=[1, 2, 3, 4, 5, 6], default=1,
                        help="Test to run: 1=basic, 2=detection_by_ip, 3=detection_by_hash, "
                             "4=ioc_search, 5=intel_lookup, 6=alerts_by_ip")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    client = CrowdStrikeClient()

    # Test token
    token = client.get_access_token()
    if not token:
        logger.error("Failed to obtain access token")
        return
    logger.info("Access token obtained successfully")

    if args.test == 1:
        # Test 1: Basic device queries
        logger.info("=== Test 1: Basic device queries ===")
        host_name_cs = 'uscku1metu03c7l'
        device_id = client.get_device_id(host_name_cs)
        if device_id:
            logger.info(f"Device ID: {device_id}")
            logger.info(client.get_device_details(device_id))

        containment_status = client.get_device_containment_status(host_name_cs)
        logger.info(f"Containment status: {containment_status}")

        online_status = client.get_device_online_state(host_name_cs)
        logger.info(f"Online status: {online_status}")

    elif args.test == 2:
        # Test 2: Search detections by IP
        logger.info("=== Test 2: Search detections by IP ===")
        test_ip = "10.0.0.1"  # Example internal IP
        result = client.search_detections_by_ip(test_ip, hours=168)
        if "error" in result:
            logger.error(f"Error: {result['error']}")
        else:
            logger.info(f"Found {result['count']} detections for IP {test_ip}")
            for d in result.get('detections', [])[:3]:
                logger.info(f"  - {d.get('detection_id')}: {d.get('detect_description', 'N/A')}")

    elif args.test == 3:
        # Test 3: Search detections by hash
        logger.info("=== Test 3: Search detections by hash ===")
        # Example SHA256 (Mimikatz)
        test_hash = "e930b05efe23891d19bc354a4209be3e113e2b8a1a5c19c5d1c5a5e5a5e5a5e5"
        result = client.search_detections_by_hash(test_hash, hours=720)
        if "error" in result:
            logger.error(f"Error: {result['error']}")
        else:
            logger.info(f"Found {result['count']} detections for hash {test_hash[:16]}...")
            for d in result.get('detections', [])[:3]:
                hostname = d.get('device', {}).get('hostname', 'Unknown')
                logger.info(f"  - Host: {hostname}, Detection: {d.get('detect_description', 'N/A')}")

    elif args.test == 4:
        # Test 4: Search custom IOCs
        logger.info("=== Test 4: Search custom IOCs ===")
        test_ioc = "8.8.8.8"  # Example IOC
        result = client.search_ioc_by_value(test_ioc)
        if "error" in result:
            logger.error(f"Error: {result['error']}")
        else:
            logger.info(f"Found {result['count']} custom IOCs matching {test_ioc}")
            for ioc in result.get('indicators', [])[:3]:
                logger.info(f"  - Type: {ioc.get('type')}, Value: {ioc.get('value')}")

    elif args.test == 5:
        # Test 5: Falcon X intel lookup
        logger.info("=== Test 5: Falcon X intel lookup ===")
        test_indicator = "evil.com"  # Example domain
        result = client.lookup_intel_indicator(test_indicator)
        if "error" in result:
            logger.error(f"Error: {result['error']}")
        else:
            logger.info(f"Found {result['count']} intel records for {test_indicator}")
            for ind in result.get('indicators', [])[:3]:
                logger.info(f"  - Type: {ind.get('type')}, Malicious: {ind.get('malicious_confidence')}")

    elif args.test == 6:
        # Test 6: Search alerts by IP
        logger.info("=== Test 6: Search alerts by IP ===")
        test_ip = "10.0.0.1"
        result = client.search_alerts_by_ip(test_ip, hours=168)
        if "error" in result:
            logger.error(f"Error: {result['error']}")
        else:
            logger.info(f"Found {result['count']} alerts for IP {test_ip}")
            for a in result.get('alerts', [])[:3]:
                logger.info(f"  - Alert: {a.get('name', 'N/A')}")


if __name__ == "__main__":
    main()
