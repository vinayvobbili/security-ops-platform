#!/usr/bin/env python3
"""
Simple Tanium API Client for fetching computers and custom tags

Usage:
    client = TaniumClient("https://tanium-server.com", "api-token")
    computers = client.get_computers()
    tags = client.get_custom_tags()
"""

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Dict, Any

import pandas as pd
import requests

from config import get_config

CONFIG = get_config()


@dataclass
class Computer:
    name: str
    id: str
    ip: str
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

    def get_computers_with_custom_tags(self, limit: int = 100) -> List[Computer]:
        """Fetch computers with their custom tags"""
        gql = """
        query getEndpointsWithCustomTags($first: Int) {
            endpoints(first: $first) {
                edges {
                    node {
                        name
                        id
                        ipAddress
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

        variables = {'first': limit}
        data = self.query(gql, variables)

        computers = []
        for edge in data['data']['endpoints']['edges']:
            node = edge['node']

            # Extract custom tags
            custom_tags = []
            sensor_readings = node.get('sensorReadings', {})

            # sensorReadings is a single dict, not a list
            if isinstance(sensor_readings, dict) and 'columns' in sensor_readings:
                for column in sensor_readings['columns']:
                    if column.get('values'):
                        # Filter out "[No Tags]" entries
                        for tag in column['values']:
                            if tag != '[No Tags]':
                                custom_tags.append(tag)

            computers.append(Computer(
                name=node.get('name', ''),
                id=node.get('id', ''),
                ip=node.get('ipAddress'),
                custom_tags=custom_tags
            ))

        return computers

    def get_computer_by_name(self, name: str) -> Optional[Computer]:
        """Get a specific computer by name"""
        computers = self.get_computers_with_custom_tags(limit=500)
        return next((c for c in computers if c.name == name), None)

    def get_custom_tags_for_host(self, host_name: str) -> List[str]:
        """Get custom tags for a specific host"""
        computer = self.get_computer_by_name(host_name)
        return computer.custom_tags if computer else []

    def export_to_excel(self, computers: List[Computer], filename: str = None) -> str:
        """Export computers data to Excel file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"tanium_computers_{timestamp}.xlsx"

        # Convert to DataFrame
        data = []
        for computer in computers:
            data.append({
                'Computer Name': computer.name,
                'ID': computer.id,
                'IP Address': computer.ip,
                'Custom Tags': ', '.join(computer.custom_tags) if computer.custom_tags else '',
                'Tag Count': len(computer.custom_tags)
            })

        df = pd.DataFrame(data)

        # Write to Excel with formatting
        with pd.ExcelWriter(filename, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Computers', index=False)

            # Auto-adjust column widths
            worksheet = writer.sheets['Computers']
            for column in worksheet.columns:
                max_length = 0
                column_letter = column[0].column_letter
                for cell in column:
                    try:
                        if len(str(cell.value)) > max_length:
                            max_length = len(str(cell.value))
                    except:
                        pass
                adjusted_width = min(max_length + 2, 50)
                worksheet.column_dimensions[column_letter].width = adjusted_width

        print(f"Data exported to: {filename}")
        return filename

    def get_and_export_computers(self, limit: int = 100, filename: str = None) -> str:
        """Get computers and export directly to Excel"""
        try:
            computers = self.get_computers_with_custom_tags(limit)
            return self.export_to_excel(computers, filename)
        except Exception as e:
            print(f"Error fetching and exporting computers: {e}")
            raise

    def validate_token(self) -> bool:
        """Validate the API token"""
        try:
            response = requests.post(
                f"{self.server_url}/api/v2/session/validate",
                json={'session': self.token},
                headers=self.headers
            )
            return response.status_code == 200
        except requests.RequestException:
            return False


# Example usage
if __name__ == "__main__":
    client = TaniumClient("https://metportal-api.cloud.tanium.com")

    # Validate token
    if not client.validate_token():
        print("Invalid token!")
        exit(1)

    # Get computers and export to Excel
    print("Fetching computers and exporting to Excel...")
    filename = client.get_and_export_computers(limit=100)

    # Optional: Also print to console
    computers = client.get_computers_with_custom_tags(limit=5)  # Just first 5 for console
    print(f"\nFirst {len(computers)} computers:")
    for computer in computers:
        print(f"  {computer.name} | {computer.ip} | Tags: {len(computer.custom_tags)}")

    print(f"\nFull data exported to: {filename}")
