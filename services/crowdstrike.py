import concurrent.futures
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Any
from typing import List

import pandas as pd
import requests
from falconpy import Hosts
from falconpy import OAuth2

from config import get_config

ROOT_DIRECTORY = Path(__file__).parent.parent


class CrowdStrikeClient:
    """Client for interacting with the CrowdStrike Falcon API."""

    def __init__(self):
        self.config = get_config()
        self.base_url = "api.us-2.crowdstrike.com"
        self.output_dir = ROOT_DIRECTORY / "data" / "transient" / "epp_device_tagging"

        # Initialize authentication
        self.auth = OAuth2(
            client_id=self.config.cs_ro_client_id,
            client_secret=self.config.cs_ro_client_secret,
            base_url=self.base_url,
            ssl_verify=False,
        )
        self.hosts_client = Hosts(auth_object=self.auth)

    def get_access_token(self) -> str:
        """Get CrowdStrike access token using direct API call."""
        url = f'https://{self.base_url}/oauth2/token'
        body = {
            'client_id': self.config.cs_ro_client_id,
            'client_secret': self.config.cs_ro_client_secret
        }
        try:
            print(f"Requesting token from: {url}")
            print(f"Using client_id: {self.config.cs_ro_client_id[:5]}...")  # Print first 5 chars for security
            response = requests.post(url, data=body)
            print(f"Token response status: {response.status_code}")
            if response.status_code != 200:
                print(f"Error response: {response.text}")
            response.raise_for_status()
            token = response.json()['access_token']
            print(f"Token acquired successfully: {token[:5]}...")
            return token
        except Exception as e:
            print(f"Error getting access token: {e}")
            return ""

    def get_device_ids_batch(self, hostnames, batch_size=100):
        """
        Get device IDs for multiple hostnames in batches to reduce API calls.

        Args:
            hostnames: List of hostnames to query
            batch_size: Number of hostnames to include in each API call

        Returns:
            Dictionary mapping hostnames to their device IDs
        """
        results = {}
        for i in range(0, len(hostnames), batch_size):
            batch = hostnames[i:i + batch_size]
            # Create filter with all hostnames in this batch
            host_filter = f"hostname:['{'', ''.join(batch)}']"

            try:
                response = self.hosts_client.query_devices_by_filter(
                    filter=host_filter,
                    limit=len(batch)
                )

                if response.get("status_code") == 200:
                    device_ids = response["body"].get("resources", [])

                    # Get full details to map IDs to hostnames
                    if device_ids:
                        details = self.hosts_client.get_device_details(ids=device_ids)
                        if details.get("status_code") == 200:
                            for device in details["body"].get("resources", []):
                                hostname = device.get("hostname")
                                device_id = device.get("device_id")
                                if hostname and device_id:
                                    results[hostname] = device_id
                else:
                    print(f"Error in batch query: {response.get('body', {}).get('errors')}")
            except Exception as e:
                print(f"Exception in batch query: {e}")

        return results

    def get_device_id(self, hostname: str) -> Optional[str]:
        """
        Retrieve the device ID for a given hostname.

        Args:
            hostname: The hostname to search for

        Returns:
            The device ID if found, None otherwise
        """
        host_filter = f"hostname:'{hostname}'"
        try:
            response = self.hosts_client.query_devices_by_filter(
                filter=host_filter,
                sort='last_seen.desc',
                limit=1
            )

            if response.get("status_code") == 200:
                devices = response["body"].get("resources", [])
                if devices:
                    return devices[0]  # Return the first matching device ID
                print(f"No devices found for hostname: {hostname}")
            else:
                print(
                    f"Error getting device ID: {response.get('status_code')}, {response.get('body', {}).get('errors')}")
        except Exception as e:
            print(f"Exception when getting device ID: {e}")

        return None

    def get_device_details(self, device_id: str) -> Dict[str, Any]:
        """
        Retrieve details for a specific device.

        Args:
            device_id: The CrowdStrike device ID

        Returns:
            Dictionary with device details or empty dict if not found
        """
        try:
            response = self.hosts_client.get_device_details_v2(ids=device_id)
            if response.get("status_code") == 200:
                resources = response["body"].get("resources", [])
                if resources:
                    return resources[0]
                print(f"No details found for device ID: {device_id}")
            else:
                print(
                    f"Error getting device details: {response.get('status_code')}, {response.get('body', {}).get('errors')}")
        except Exception as e:
            print(f"Exception when getting device details: {e}")

        return {}

    def get_device_containment_status(self, hostname: str) -> Optional[str]:
        """
        Get containment status for a device using hostname.

        Args:
            hostname: The hostname to get status for

        Returns:
            Device status or None if not found
        """
        device_id = self.get_device_id(hostname)
        if not device_id:
            return None

        device_details = self.get_device_details(device_id)
        return device_details.get("status")

    def fetch_all_hosts_and_write_to_xlsx(self, xlsx_filename: str = "all_cs_hosts.xlsx") -> None:
        """
        Fetches all hosts from CrowdStrike Falcon using multithreading for details fetching.
        """
        all_host_data = []
        unique_device_ids = set()
        data_lock = threading.Lock()  # For thread-safe access to shared data
        offset = None
        limit = 5000

        print("Fetching ALL host data with multithreading...")
        start_time = time.time()
        total_fetched = 0
        batch_count = 0

        def process_host_details(host_ids_batch: List[str]) -> None:
            """Thread worker to process a batch of host IDs"""
            try:
                details_response = self.hosts_client.get_device_details(ids=host_ids_batch)
                if details_response["status_code"] != 200:
                    print(f"Error retrieving details for host IDs batch: {details_response}")
                    return

                host_details = details_response["body"].get("resources", [])
                new_hosts_data = []
                new_hosts = 0

                for host in host_details:
                    device_id = host.get("device_id")
                    if not device_id:
                        continue

                    # Prepare data for this host
                    host_data = {
                        "hostname": host.get("hostname"),
                        "host_id": device_id,
                        "current_tags": ", ".join(host.get("tags", [])),
                        "last_seen": host.get("last_seen"),
                        "status": host.get("status"),
                        "cs_host_category": host.get("product_type_desc"),
                        "chassis_type_desc": host.get("chassis_type_desc"),
                    }
                    new_hosts_data.append((device_id, host_data))
                    new_hosts += 1

                # Use lock when accessing shared data structures
                with data_lock:
                    for device_id, host_data in new_hosts_data:
                        if device_id not in unique_device_ids:
                            unique_device_ids.add(device_id)
                            all_host_data.append(host_data)

                # print(f"Processed batch with {new_hosts} hosts")
            except Exception as e:
                print(f"Error in thread processing host details: {e}")

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                while True:
                    # Refresh token periodically
                    if batch_count > 0 and batch_count % 10 == 0:
                        print(f"Refreshing authentication token after {total_fetched} records...")
                        self.auth = OAuth2(
                            client_id=self.config.cs_ro_client_id,
                            client_secret=self.config.cs_ro_client_secret,
                            base_url=self.base_url,
                            ssl_verify=False,
                        )
                        self.hosts_client = Hosts(auth_object=self.auth)

                    # Get batch of host IDs (this remains sequential)
                    response = self.hosts_client.query_devices_by_filter_scroll(
                        limit=limit, offset=offset
                    )

                    if response["status_code"] != 200:
                        print(f"Error retrieving host IDs: {response}")
                        break

                    host_ids = response["body"].get("resources", [])
                    if not host_ids:
                        print("No more hosts to fetch - reached end of data")
                        break

                    # Split host IDs into smaller batches for parallel processing
                    batch_size = min(500, len(host_ids))  # Process in smaller chunks
                    host_id_batches = [host_ids[i:i + batch_size] for i in range(0, len(host_ids), batch_size)]

                    # Submit each batch for parallel processing
                    futures = [executor.submit(process_host_details, id_batch) for id_batch in host_id_batches]
                    concurrent.futures.wait(futures)  # Wait for all batches to complete

                    total_fetched += len(host_ids)
                    batch_count += 1

                    # Get next offset for pagination
                    offset = response["body"].get("meta", {}).get("pagination", {}).get("offset")
                    if not offset:
                        print("No offset returned - reached end of pagination")
                        break

                    time.sleep(0.5)  # Small delay between pagination requests

        except Exception as e:
            print(f"An error occurred fetching host data: {e}")

        # Write results to Excel
        today_date = datetime.now().strftime('%m-%d-%Y')
        output_path = self.output_dir / today_date
        os.makedirs(output_path, exist_ok=True)
        print(f"Writing {len(all_host_data)} host records to {output_path}...")

        try:
            df = pd.DataFrame(all_host_data)
            df.to_excel(output_path / xlsx_filename, index=False, engine='openpyxl')
            print(f"Successfully wrote {len(all_host_data)} host records")
        except Exception as e:
            print(f"Error writing to XLSX: {e}")


def main() -> None:
    client = CrowdStrikeClient()
    # First explicitly get and print the token status
    token = client.get_access_token()
    if not token:
        print("Failed to obtain access token")
        return

    # Continue with your operations
    print("Testing API with obtained token...")
    device_id = client.get_device_id('AUSYD1METV0051')
    if device_id:
        print(f"Successfully retrieved device ID: {device_id}")
        print(client.get_device_details(device_id))
    else:
        print("Failed to retrieve device ID")


if __name__ == "__main__":
    main()
