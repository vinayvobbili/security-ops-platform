#!/usr/bin/env python3
"""
Simple Tanium API Client for fetching computers and custom tags

Usage:
    client = TaniumClient("https://tanium-server.com", "api-token")
    computers = client.get_computers()
    tags = client.get_custom_tags()
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
            payload['variables'] = variables  # type: ignore
        response = ''
        try:
            response = requests.post(self.graphql_url, json=payload, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            # Try to get more detailed error information from the response
            error_detail = ""
            try:
                error_json = response.json()
                if 'errors' in error_json:
                    error_detail = ": " + str(error_json['errors'])
            except:
                pass
            print(f"HTTP Error: {e}{error_detail}")
            print(f"Query: {gql}")
            print(f"Variables: {variables}")
            raise
        except Exception as e:
            print(f"Error in query: {e}")
            raise

    def get_computers_with_custom_tags(self, limit: int = None) -> List[Computer]:
        """Fetch all computers with their custom tags (no limit if limit=None)"""
        query_gql = """
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
        total_fetched = 0
        page_size = 2000  # Increased from 500 to 2000 for faster fetching

        # Set up progress bar
        with tqdm.tqdm(desc="Fetching Tanium computers", unit="host") as progress_bar:
            try:
                # Pagination variables
                after_cursor = None
                page_count = 0
                has_more = True

                while has_more:
                    page_count += 1

                    # Prepare variables for this batch
                    variables = {'first': page_size}
                    if after_cursor:
                        variables['after'] = after_cursor

                    print(f"Fetching batch {page_count} of Tanium computers (batch size: {page_size})...")
                    data = self.query(query_gql, variables)

                    # Process this batch of computers
                    endpoints = data['data']['endpoints']
                    edges = endpoints['edges']
                    batch_size = len(edges)

                    if batch_size == 0:
                        break

                    # Update progress tracking
                    total_fetched += batch_size
                    progress_bar.update(batch_size)

                    # Process each computer in this batch
                    for edge in edges:
                        node = edge['node']
                        custom_tags = self._extract_custom_tags(node.get('sensorReadings', {}))
                        computers.append(Computer(
                            name=node.get('name', ''),
                            id=node.get('id', ''),
                            ip=node.get('ipAddress'),
                            custom_tags=custom_tags
                        ))

                    # Check if there are more pages to fetch
                    has_more = endpoints['pageInfo']['hasNextPage']
                    after_cursor = endpoints['pageInfo']['endCursor']

                    # Apply optional limit (for testing or console display)
                    if limit and total_fetched >= limit:
                        print(f"Reached specified limit of {limit} computers")
                        break

                print(f"Successfully fetched {total_fetched} computers from {page_count} pages")
                return computers

            except Exception as e:
                print(f"Error fetching computers: {e}")
                raise

    def _extract_custom_tags(self, sensor_readings: Dict) -> List[str]:
        """Helper method to extract custom tags from sensor readings"""
        custom_tags = []
        if isinstance(sensor_readings, dict) and 'columns' in sensor_readings:
            for column in sensor_readings['columns']:
                if column.get('values'):
                    for tag in column['values']:
                        if tag != '[No Tags]':
                            custom_tags.append(tag)
        return custom_tags

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
        # Always write to a dated folder under epp_device_tagging
        today_date = datetime.now().strftime('%m-%d-%Y')
        base_dir = Path(__file__).parent.parent / "data" / "transient" / "epp_device_tagging" / today_date
        os.makedirs(base_dir, exist_ok=True)
        output_path = base_dir / "all_tanium_hosts.xlsx"

        # Convert to DataFrame
        data = []
        for computer in computers:
            data.append({
                'Name': computer.name,
                'ID': computer.id,
                'IP Address': computer.ip,
                'Custom Tags': ', '.join(computer.custom_tags) if computer.custom_tags else '',
                'Tag Count': len(computer.custom_tags)
            })

        df = pd.DataFrame(data)

        # Write to Excel with formatting
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
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

        print(f"Data exported to: {output_path}")
        return str(output_path)

    def get_and_export_computers(self) -> str:
        """Get computers and export directly to Excel"""
        try:
            computers = self.get_computers_with_custom_tags()
            return self.export_to_excel(computers)
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

    # Get computers and export to Excel - no limit for the fetch
    print("Fetching computers and exporting to Excel...")
    filename = client.get_and_export_computers()  # No limit, fetch all computers

    # Optional: Still just print first 5 to console for brevity
    computers = client.get_computers_with_custom_tags(limit=5)  # Just first 5 for console
    print(f"\nFirst {len(computers)} computers:")
    for computer in computers[:5]:  # Use slice notation to get first 5
        print(f"  {computer.name} | {computer.ip} | Tags: {len(computer.custom_tags)}")

    print(f"\nFull data exported to: {filename}")
