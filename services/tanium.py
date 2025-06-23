#!/usr/bin/env python3
"""
Simple Tanium API Client for fetching computers and custom tags from multiple instances

Usage:
    client = TaniumClient()
    filename = client.get_and_export_all_computers()
"""

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
import urllib3

import pandas as pd
import requests
import tqdm

from config import get_config

# Disable SSL warnings for on-prem connections
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG = get_config()
SHOULD_USE_PROXY_FOR_ONPREM = False


@dataclass
class Computer:
    name: str
    id: str
    ip: str
    eidLastSeen: str
    source: str  # Added to track which instance this came from
    custom_tags: List[str] = None

    def __post_init__(self):
        if self.custom_tags is None:
            self.custom_tags = []


class TaniumInstance:
    """Represents a single Tanium instance (cloud or on-prem)"""

    def __init__(self, name: str, server_url: str, token: str, verify_ssl: bool = True, use_proxy: bool = False):
        self.name = name
        self.server_url = server_url.rstrip('/')
        self.token = token
        self.headers = {'session': self.token}
        self.graphql_url = f"{self.server_url}/plugin/products/gateway/graphql"
        self.verify_ssl = verify_ssl
        self.use_proxy = use_proxy
        self.proxies = self._setup_proxy()

    def _setup_proxy(self):
        """Setup proxy configuration if enabled for this instance"""
        if not self.use_proxy:
            return None

        proxy_url = f"http://{CONFIG.jump_server_host}:8080"
        return {"http": proxy_url, "https": proxy_url}

    def query(self, gql: str, variables: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute a GraphQL query"""
        payload = {'query': gql}
        if variables:
            payload['variables'] = variables

        response = requests.post(
            self.graphql_url,
            json=payload,
            headers=self.headers,
            verify=self.verify_ssl,
            proxies=self.proxies
        )
        response.raise_for_status()
        return response.json()

    def get_computers(self, limit: int = None) -> List[Computer]:
        """Fetch all computers with their custom tags"""
        query = """
        query getEndpoints($first: Int, $after: Cursor) {
          endpoints(first: $first, after: $after) {
            pageInfo {
              hasNextPage
              endCursor
            }
            edges {
              node {
                id
                name
                ipAddress
                eidLastSeen
                sensorReadings(sensors: [{name: "Custom Tags"}]) {
                  columns {
                    name
                    values
                  }
                }
              }
            }
          }
        }
        """

        computers = []
        after_cursor = None
        page_size = 5000

        with tqdm.tqdm(desc=f"Fetching computers from {self.name}", unit="host") as pbar:
            while True:
                variables = {'first': page_size}
                if after_cursor:
                    variables['after'] = after_cursor

                try:
                    data = self.query(query, variables)
                    endpoints = data['data']['endpoints']
                    edges = endpoints['edges']

                    if not edges:
                        break

                    for edge in edges:
                        node = edge['node']
                        custom_tags = self._extract_custom_tags(node.get('sensorReadings', {}))
                        computers.append(Computer(
                            name=node.get('name', ''),
                            id=node.get('id', ''),
                            ip=node.get('ipAddress'),
                            eidLastSeen=node.get('eidLastSeen'),
                            source=self.name,
                            custom_tags=custom_tags
                        ))

                    pbar.update(len(edges))

                    if not endpoints['pageInfo']['hasNextPage']:
                        break
                    if limit and len(computers) >= limit:
                        break

                    after_cursor = endpoints['pageInfo']['endCursor']

                except Exception as e:
                    print(f"Error fetching from {self.name}: {e}")
                    break

        return computers[:limit] if limit else computers

    def _extract_custom_tags(self, sensor_readings: Dict) -> List[str]:
        """Extract custom tags from sensor readings"""
        tags = []
        columns = sensor_readings.get('columns', [])
        for column in columns:
            values = column.get('values', [])
            tags.extend([tag for tag in values if tag != '[No Tags]'])
        return tags

    def validate_token(self) -> bool:
        """Validate the API token"""
        try:
            # Try the standard validation endpoint first
            response = requests.post(
                f"{self.server_url}/api/v2/session/validate",
                json={'session': self.token},
                headers=self.headers,
                verify=self.verify_ssl,
                proxies=self.proxies
            )

            print(f"Token validation for {self.name}: Status {response.status_code}")
            if response.status_code != 200:
                print(f"Response body: {response.text}")

                # For on-prem, try alternative validation method
                if self.name == "On-Prem":
                    print(f"Trying alternative validation for {self.name}...")
                    # Try using the session header directly in a simple API call
                    alt_response = requests.get(
                        f"{self.server_url}/api/v2/system_settings",
                        headers=self.headers,
                        verify=self.verify_ssl,
                        proxies=self.proxies
                    )
                    print(f"Alternative validation for {self.name}: Status {alt_response.status_code}")
                    if alt_response.status_code == 200:
                        return True
                    elif alt_response.status_code != 200:
                        print(f"Alternative response body: {alt_response.text}")

            return response.status_code == 200
        except Exception as e:
            print(f"Error validating token for {self.name}: {e}")
            return False


class TaniumClient:
    """Main client for managing multiple Tanium instances"""

    def __init__(self):
        self.instances = []
        self._setup_instances()

    def _setup_instances(self):
        """Initialize cloud and on-prem instances"""
        # Cloud instance (direct connection, verify SSL for cloud)
        if CONFIG.tanium_cloud_api_url and CONFIG.tanium_cloud_api_token:
            cloud_instance = TaniumInstance(
                "Cloud",
                CONFIG.tanium_cloud_api_url,
                CONFIG.tanium_cloud_api_token,
                verify_ssl=True,
                use_proxy=False  # Cloud can connect directly
            )
            self.instances.append(cloud_instance)

        # On-prem instance (use proxy due to IP whitelisting, disable SSL verification)
        if CONFIG.tanium_onprem_api_url and CONFIG.tanium_onprem_api_token:
            onprem_instance = TaniumInstance(
                "On-Prem",
                CONFIG.tanium_onprem_api_url,
                CONFIG.tanium_onprem_api_token,
                verify_ssl=False,  # Disable SSL verification for on-prem
                use_proxy=SHOULD_USE_PROXY_FOR_ONPREM  # Can be toggled via flag
            )
            self.instances.append(onprem_instance)

    def validate_all_tokens(self) -> Dict[str, bool]:
        """Validate tokens for all instances"""
        results = {}
        for instance in self.instances:
            results[instance.name] = instance.validate_token()
        return results

    def get_all_computers(self, limit: int = None) -> Tuple[List[Computer], Dict[str, List[Computer]]]:
        """Get computers from all instances"""
        all_computers = []
        computers_by_instance = {}

        for instance in self.instances:
            if not instance.validate_token():
                print(f"Invalid token for {instance.name}, skipping...")
                continue

            print(f"Fetching computers from {instance.name}...")
            computers = instance.get_computers(limit)
            all_computers.extend(computers)
            computers_by_instance[instance.name] = computers
            print(f"Retrieved {len(computers)} computers from {instance.name}")

        return all_computers, computers_by_instance

    def export_to_excel(self, all_computers: List[Computer], filename: str = None) -> str:
        """Export computers data to Excel file with single sheet"""
        today = datetime.now().strftime('%m-%d-%Y')
        output_dir = Path(__file__).parent.parent / "data" / "transient" / "epp_device_tagging" / today
        output_dir.mkdir(parents=True, exist_ok=True)

        if filename:
            output_path = output_dir / filename
        else:
            output_path = output_dir / "all_tanium_hosts.xlsx"

        data = [{
            'Name': c.name,
            'ID': c.id,
            'IP Address': c.ip,
            'Last Seen': c.eidLastSeen,
            'Source': c.source,
            'Custom Tags': ', '.join(c.custom_tags),
            'Tag Count': len(c.custom_tags),
            'Has EPP Ring Tag': 'Yes' if any(tag.startswith('EPP') and 'Ring' in tag for tag in c.custom_tags) else 'No'
        } for c in all_computers]

        df = pd.DataFrame(data)

        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Computers', index=False)

            # Auto-adjust column widths
            worksheet = writer.sheets['Computers']
            for column in worksheet.columns:
                max_length = max(len(str(cell.value)) for cell in column)
                worksheet.column_dimensions[column[0].column_letter].width = min(max_length + 2, 50)

        return str(output_path)

    def get_and_export_all_computers(self, filename: str = None) -> str:
        """Get all computers from all instances and export to Excel"""
        all_computers, _ = self.get_all_computers()

        if not all_computers:
            print("No computers retrieved from any instance!")
            return None

        return self.export_to_excel(all_computers, filename)

    def get_computer_by_name(self, name: str) -> Optional[Computer]:
        """Get a specific computer by name from any instance"""
        all_computers, _ = self.get_all_computers(limit=500)
        return next((c for c in all_computers if c.name == name), None)


if __name__ == "__main__":
    client = TaniumClient()

    # Validate all tokens first
    token_status = client.validate_all_tokens()
    for instance, is_valid in token_status.items():
        if is_valid:
            print(f"✓ {instance} token is valid")
        else:
            print(f"✗ {instance} token is invalid")

    # Only proceed if at least one token is valid
    if not any(token_status.values()):
        print("No valid tokens found. Exiting.")
        exit(1)

    try:
        filename = client.get_and_export_all_computers()
        if filename:
            print(f"Data exported to: {filename}")
        else:
            print("No data to export")
    except Exception as e:
        print(f"Error during export: {e}")
        exit(1)
