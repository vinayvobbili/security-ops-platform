import urllib3
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)

import concurrent.futures
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Any, List

import pandas as pd
import requests
import tqdm

from falconpy import Hosts, OAuth2
from config import get_config
from src.utils.http_utils import get_session

DATA_DIR = Path(__file__).parent.parent / "data" / "transient" / "epp_device_tagging"
SHOULD_USE_PROXY = True
CS_FETCH_MAX_WORKERS = 10

# Get robust HTTP session instance
http_session = get_session()


class CrowdStrikeClient:
    """Client for interacting with the CrowdStrike Falcon API."""

    def __init__(self, use_host_write_creds: bool = False, max_workers: Optional[int] = None):
        self.config = get_config()
        self.base_url = "api.us-2.crowdstrike.com"
        self.proxies = self._setup_proxy()
        if self.proxies:
            print(f"[CrowdStrikeClient] Proxy enabled: {self.proxies}")
        else:
            print("[CrowdStrikeClient] Proxy not enabled.")
        self.use_host_write_creds = use_host_write_creds
        self.auth = self._create_auth()
        self.hosts_client = Hosts(auth_object=self.auth)
        # Allow thread pool size to be set via env or parameter
        self.max_workers = max_workers or CS_FETCH_MAX_WORKERS

    def _get_client_id_secret(self):
        if self.use_host_write_creds:
            return self.config.cs_host_write_client_id, self.config.cs_host_write_client_secret
        return self.config.cs_ro_client_id, self.config.cs_ro_client_secret

    def _setup_proxy(self):
        """Setup proxy configuration if enabled"""
        if not SHOULD_USE_PROXY:
            return None

        proxy_url = f"http://{self.config.jump_server_host}:8080"
        return {"http": proxy_url, "https": proxy_url}

    def _create_auth(self):
        client_id, client_secret = self._get_client_id_secret()
        """Create OAuth2 authentication object"""
        return OAuth2(
            client_id=client_id,
            client_secret=client_secret,
            base_url=self.base_url,
            ssl_verify=False,
            proxy=self.proxies
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
            return 'Host not found in CS'

        device_details = self.get_device_details(device_id)
        return device_details.get("status")

    def fetch_all_hosts_and_write_to_xlsx(self, xlsx_filename: str = "all_cs_hosts.xlsx") -> None:
        """Fetch all hosts from CrowdStrike Falcon using multithreading"""
        import logging
        logger = logging.getLogger(__name__)
        all_host_data = []
        unique_device_ids = set()
        offset = None
        limit = 5000
        batch_count = 0
        start_time = time.time()

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
                    self.hosts_client = Hosts(auth_object=self.auth)

                response = self.hosts_client.query_devices_by_filter_scroll(
                    limit=limit, offset=offset
                )

                if response["status_code"] != 200:
                    break

                host_ids = response["body"].get("resources", [])
                if not host_ids:
                    break

                # Process in batches of 1000
                host_id_batches = [host_ids[i:i + 1000] for i in range(0, len(host_ids), 1000)]

                futures = [
                    executor.submit(process_host_details, id_batch)
                    for id_batch in tqdm.tqdm(host_id_batches, desc="Processing host batches")
                ]
                concurrent.futures.wait(futures)

                batch_count += 1
                offset = response["body"].get("meta", {}).get("pagination", {}).get("offset")
                if not offset:
                    break

                time.sleep(0.5)

        elapsed = time.time() - start_time
        logger.info(f"Completed fetch_all_hosts_and_write_to_xlsx in {elapsed:.2f} seconds. Total hosts: {len(all_host_data)}")

        # Write to Excel
        today_date = datetime.now().strftime('%m-%d-%Y')
        output_path = DATA_DIR / today_date
        output_path.mkdir(parents=True, exist_ok=True)

        df = pd.DataFrame(all_host_data)
        df.to_excel(output_path / xlsx_filename, index=False, engine='openpyxl')

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


def process_unique_hosts(df: pd.DataFrame) -> pd.DataFrame:
    """Process dataframe to get unique hosts with latest last_seen"""
    df["last_seen"] = pd.to_datetime(df["last_seen"], errors='coerce').dt.tz_localize(None)
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


def main() -> None:
    client = CrowdStrikeClient()

    # Test token
    token = client.get_access_token()
    if not token:
        print("Failed to obtain access token")
        return

    # Test API
    host_name_cs = 'Y54G91YXRY'
    device_id = client.get_device_id(host_name_cs)
    if device_id:
        print(f"Device ID: {device_id}")
        print(client.get_device_details(device_id))

    containment_status = client.get_device_containment_status(host_name_cs)
    print(f"Containment status: {containment_status}")

    online_status = client.get_device_online_state(host_name_cs)
    print(f"Online status: {online_status}")


if __name__ == "__main__":
    main()
