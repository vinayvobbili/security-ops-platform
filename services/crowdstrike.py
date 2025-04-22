import time
from pathlib import Path
from typing import List, Dict, Optional, Any

import pandas as pd
import requests
from falconpy import Hosts
from falconpy import OAuth2

from config import get_config


class CrowdStrikeClient:
    """Client for interacting with the CrowdStrike Falcon API."""

    def __init__(self):
        self.config = get_config()
        self.base_url = "api.us-2.crowdstrike.com"
        self.output_dir = Path('../data/transient/epp_device_tagging')

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
            response = requests.post(url, data=body)
            response.raise_for_status()
            return response.json()['access_token']
        except Exception as e:
            print(f"Error getting access token: {e}")
            return ""

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
                print(f"Error getting device ID: {response.get('status_code')}, {response.get('body', {}).get('errors')}")
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
            response = self.hosts_client.get_device_details(ids=device_id)
            if response.get("status_code") == 200:
                resources = response["body"].get("resources", [])
                if resources:
                    return resources[0]
                print(f"No details found for device ID: {device_id}")
            else:
                print(f"Error getting device details: {response.get('status_code')}, {response.get('body', {}).get('errors')}")
        except Exception as e:
            print(f"Exception when getting device details: {e}")

        return {}

    def get_device_status(self, hostname: str) -> Optional[str]:
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

        url = f'https://{self.base_url}/devices/entities/devices/v1'
        headers = {
            'content-type': 'application/json',
            'Authorization': f'Bearer {self.get_access_token()}'
        }
        params = {"ids": device_id}

        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json()['resources'][0]['status']
        except Exception as e:
            print(f"Error getting device status: {e}")
            return None

    def fetch_all_hosts_and_write_to_xlsx(self, xlsx_filename: str = "all_cs_hosts.xlsx") -> None:
        """
        Fetches all hosts from CrowdStrike Falcon and writes their details to an XLSX file.
        """
        all_host_data: List[Dict[str, str]] = []
        # Use a set to track unique device IDs
        unique_device_ids = set()
        offset: Optional[str] = None
        limit: int = 5000  # Maximum allowed by the API

        print("Fetching ALL host data...")
        start_time = time.time()
        total_fetched = 0
        batch_count = 0

        try:
            while True:
                # Refresh token periodically without resetting offset
                if batch_count > 0 and batch_count % 10 == 0:
                    print(f"Refreshing authentication token after {total_fetched} records...")
                    self.auth = OAuth2(
                        client_id=self.config.cs_ro_client_id,
                        client_secret=self.config.cs_ro_client_secret,
                        base_url=self.base_url,
                        ssl_verify=False,
                    )
                    self.hosts_client = Hosts(auth_object=self.auth)
                    # Do NOT reset offset here - this keeps pagination going

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

                details_response = self.hosts_client.get_device_details(ids=host_ids)
                if details_response["status_code"] != 200:
                    print(f"Error retrieving details for host IDs: {details_response}")
                    break

                # Count new unique hosts in this batch
                new_hosts = 0
                host_details = details_response["body"].get("resources", [])
                for host in host_details:
                    device_id = host.get("device_id")
                    # Only add if we haven't seen this device before
                    if device_id and device_id not in unique_device_ids:
                        unique_device_ids.add(device_id)
                        new_hosts += 1
                        all_host_data.append({
                            "hostname": host.get("hostname"),
                            "host_id": device_id,
                            "current_tags": ", ".join(host.get("tags", [])),
                            "last_seen": host.get("last_seen"),
                            "status": host.get("status"),
                            "chassis_type_desc": host.get("chassis_type_desc"),
                        })

                batch_size = len(host_ids)
                total_fetched += batch_size
                batch_count += 1

                print(f"Batch {batch_count}: Retrieved {batch_size}, new unique: {new_hosts}, total unique: {len(unique_device_ids)}")

                # Get next offset for pagination
                offset = response["body"].get("meta", {}).get("pagination", {}).get("offset")
                if not offset:
                    print("No offset returned - reached end of pagination")
                    break

                time.sleep(0.5)  # Small delay between requests

        except Exception as e:
            print(f"An error occurred fetching host data: {e}")

        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"Finished fetching host data in {elapsed_time:.2f} seconds.")
        print(f"Total unique hosts retrieved: {len(unique_device_ids)}")

        output_path = self.output_dir / xlsx_filename
        print(f"Writing host data to {output_path}...")

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            df = pd.DataFrame(all_host_data)
            df.to_excel(output_path, index=False, engine='openpyxl')
            print(f"Successfully wrote {len(all_host_data)} unique host records to {xlsx_filename}")
        except Exception as e:
            print(f"An error occurred while writing to XLSX: {e}")


def main() -> None:
    client = CrowdStrikeClient()
    client.fetch_all_hosts_and_write_to_xlsx()


if __name__ == "__main__":
    main()
