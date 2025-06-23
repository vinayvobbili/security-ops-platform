#!/usr/bin/env python3
"""
Simple Tanium API Client for fetching computers and custom tags

Usage:
    client = TaniumClient("https://tanium-server.com", "api-token")
    computers = client.get_computers()
    filename = client.export_to_excel(computers)
"""

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

import pandas as pd
import requests
import tqdm

from config import get_config

CONFIG = get_config()


@dataclass
class Computer:
    name: str
    id: str
    ip: str
    eidLastSeen: str
    custom_tags: List[str] = None

    def __post_init__(self):
        if self.custom_tags is None:
            self.custom_tags = []


class TaniumClient:
    def __init__(self, server_url: str, token: str = None):
        self.server_url = server_url.rstrip('/')
        self.token = token or CONFIG.tanium_api_token
        self.headers = {'session': self.token}
        self.graphql_url = f"{self.server_url}/plugin/products/gateway/graphql"

    def query(self, gql: str, variables: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute a GraphQL query"""
        payload = {'query': gql}
        if variables:
            payload['variables'] = variables

        response = requests.post(self.graphql_url, json=payload, headers=self.headers)
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

        with tqdm.tqdm(desc="Fetching computers", unit="host") as pbar:
            while True:
                variables = {'first': page_size}
                if after_cursor:
                    variables['after'] = after_cursor

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
                        custom_tags=custom_tags
                    ))

                pbar.update(len(edges))

                if not endpoints['pageInfo']['hasNextPage']:
                    break
                if limit and len(computers) >= limit:
                    break

                after_cursor = endpoints['pageInfo']['endCursor']

        return computers[:limit] if limit else computers

    def _extract_custom_tags(self, sensor_readings: Dict) -> List[str]:
        """Extract custom tags from sensor readings"""
        tags = []
        columns = sensor_readings.get('columns', [])
        for column in columns:
            values = column.get('values', [])
            tags.extend([tag for tag in values if tag != '[No Tags]'])
        return tags

    def get_computer_by_name(self, name: str) -> Optional[Computer]:
        """Get a specific computer by name"""
        computers = self.get_computers(limit=500)
        return next((c for c in computers if c.name == name), None)

    def export_to_excel(self, computers: List[Computer], filename: str = None) -> str:
        """Export computers data to Excel file"""
        today = datetime.now().strftime('%m-%d-%Y')
        output_dir = Path(__file__).parent.parent / "data" / "transient" / "epp_device_tagging" / today
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / "all_tanium_hosts.xlsx"

        data = [{
            'Name': c.name,
            'ID': c.id,
            'IP Address': c.ip,
            'Last Seen': c.eidLastSeen,
            'Custom Tags': ', '.join(c.custom_tags),
            'Tag Count': len(c.custom_tags)
        } for c in computers]

        df = pd.DataFrame(data)

        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Computers', index=False)

            # Auto-adjust column widths
            worksheet = writer.sheets['Computers']
            for column in worksheet.columns:
                max_length = max(len(str(cell.value)) for cell in column)
                worksheet.column_dimensions[column[0].column_letter].width = min(max_length + 2, 50)

        return str(output_path)

    def get_and_export_computers(self) -> str:
        """Get all computers and export to Excel"""
        computers = self.get_computers()
        return self.export_to_excel(computers)

    def validate_token(self) -> bool:
        """Validate the API token"""
        response = requests.post(
            f"{self.server_url}/api/v2/session/validate",
            json={'session': self.token},
            headers=self.headers
        )
        return response.status_code == 200


if __name__ == "__main__":
    client = TaniumClient("https://metportal-api.cloud.tanium.com")

    if not client.validate_token():
        print("Invalid token!")
        exit(1)

    filename = client.get_and_export_computers()
    print(f"Data exported to: {filename}")
