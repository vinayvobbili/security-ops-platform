#!/usr/bin/env python3
"""
Simple Tanium API Client for fetching computers and custom tags from multiple instances

Usage:
    client = TaniumClient()
    filename = client.get_and_export_all_computers()
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, Iterator

import pandas as pd
import requests
import tqdm
import urllib3

from config import get_config

# Disable SSL warnings for on-prem connections
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# GraphQL Queries
ENDPOINTS_QUERY = """
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

ADD_TAG_MUTATION = """
mutation addCustomTag($endpointId: String!, $tag: String!) {
  addCustomTag(input: {endpointId: $endpointId, tag: $tag}) {
    success
    message
  }
}
"""

REMOVE_TAG_MUTATION = """
mutation removeCustomTag($endpointId: String!, $tag: String!) {
  removeCustomTag(input: {endpointId: $endpointId, tag: $tag}) {
    success
    message
  }
}
"""


@dataclass
class Computer:
    """Represents a computer/endpoint in Tanium"""
    name: str
    id: str
    ip: str
    eidLastSeen: str
    source: str  # Tracks which instance this came from
    custom_tags: List[str] = None

    def __post_init__(self):
        if self.custom_tags is None:
            self.custom_tags = []

    def has_epp_ring_tag(self) -> bool:
        """Check if computer has an EPP Ring tag"""
        return any(tag.startswith('EPP') and 'Ring' in tag for tag in self.custom_tags)


class TaniumAPIError(Exception):
    """Custom exception for Tanium API errors"""
    pass


class TaniumInstance:
    """Represents a single Tanium instance (cloud or on-prem)"""
    DEFAULT_PAGE_SIZE = 5000
    DEFAULT_SEARCH_LIMIT = 500
    NO_TAGS_PLACEHOLDER = '[No Tags]'

    def __init__(self, name: str, server_url: str, token: str, verify_ssl: bool = True):
        self.name = name
        self.server_url = server_url.rstrip('/')
        self.token = token
        self.headers = {'session': self.token}
        self.graphql_url = f"{self.server_url}/plugin/products/gateway/graphql"
        self.verify_ssl = verify_ssl
        logger.info(f"Initialized Tanium instance: {self.name}")

    def query(self, gql: str, variables: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute a GraphQL query"""
        payload: Dict[str, Any] = {'query': gql}
        if variables:
            payload['variables'] = variables

        logger.debug(f"Querying {self.name} at URL: {self.graphql_url}")

        try:
            headers = self.headers.copy()
            headers['Content-Type'] = 'application/json'

            response = requests.post(
                self.graphql_url,
                json=payload,
                headers=headers,
                verify=self.verify_ssl,
                timeout=30
            )
            response.raise_for_status()

            result = response.json()
            if 'errors' in result:
                raise TaniumAPIError(f"GraphQL errors: {result['errors']}")
            return result

        except requests.RequestException as e:
            logger.error(f"Request failed for {self.name}: {e}")
            raise TaniumAPIError(f"Request failed: {e}")

    def get_computers(self, limit: Optional[int] = None) -> List[Computer]:
        """Fetch all computers with their custom tags"""
        try:
            computers = list(self._paginate_computers(limit))
            logger.info(f"Retrieved {len(computers)} computers from {self.name}")
            return computers
        except Exception as e:
            logger.error(f"Error fetching computers from {self.name}: {e}")
            return []

    def _paginate_computers(self, limit: Optional[int] = None) -> Iterator[Computer]:
        """Handle pagination for computer retrieval"""
        after_cursor = None
        computers_fetched = 0

        with tqdm.tqdm(desc=f"Fetching computers from {self.name}", unit="host") as pbar:
            while True:
                variables = {'first': self.DEFAULT_PAGE_SIZE}
                if after_cursor:
                    variables['after'] = after_cursor

                data = self.query(ENDPOINTS_QUERY, variables)
                endpoints = data['data']['endpoints']
                edges = endpoints['edges']

                if not edges:
                    break

                for edge in edges:
                    if limit and computers_fetched >= limit:
                        return

                    computer = self._extract_computer_from_node(edge['node'])
                    yield computer
                    computers_fetched += 1

                pbar.update(len(edges))

                if not endpoints['pageInfo']['hasNextPage']:
                    break

                after_cursor = endpoints['pageInfo']['endCursor']

    def _extract_computer_from_node(self, node: Dict[str, Any]) -> Computer:
        """Extract computer data from GraphQL node"""
        custom_tags = self._extract_custom_tags(node.get('sensorReadings', {}))
        return Computer(
            name=node.get('name', ''),
            id=node.get('id', ''),
            ip=node.get('ipAddress'),
            eidLastSeen=node.get('eidLastSeen'),
            source=self.name,
            custom_tags=custom_tags
        )

    def _extract_custom_tags(self, sensor_readings: Dict) -> List[str]:
        """Extract custom tags from sensor readings"""
        tags = []
        columns = sensor_readings.get('columns', [])
        for column in columns:
            values = column.get('values', [])
            tags.extend([tag for tag in values if tag != self.NO_TAGS_PLACEHOLDER])
        return tags

    def validate_token(self) -> bool:
        """Validate the API token"""
        try:
            response = requests.post(
                f"{self.server_url}/api/v2/session/validate",
                json={'session': self.token},
                headers=self.headers,
                verify=self.verify_ssl,
                timeout=10
            )

            if response.status_code == 200:
                logger.info(f"✓ {self.name} token is valid")
                return True

            logger.warning(f"Token validation failed for {self.name}: {response.status_code}")
            return False

        except Exception as e:
            logger.error(f"Error validating token for {self.name}: {e}")
            return False

    def add_custom_tag(self, computer_name: str, tag: str) -> bool:
        """Add a custom tag to a computer"""
        try:
            # First, find the computer to get its ID
            computer = self._find_computer_by_name(computer_name)
            if not computer:
                logger.warning(f"Computer '{computer_name}' not found in {self.name}")
                return False

            # Execute the add tag mutation
            variables = {'endpointId': computer.id, 'tag': tag}
            result = self.query(ADD_TAG_MUTATION, variables)

            success = result.get('data', {}).get('addCustomTag', {}).get('success', False)
            if success:
                logger.info(f"Successfully added tag '{tag}' to '{computer_name}' in {self.name}")
            else:
                message = result.get('data', {}).get('addCustomTag', {}).get('message', 'Unknown error')
                logger.error(f"Failed to add tag '{tag}' to '{computer_name}' in {self.name}: {message}")

            return success

        except Exception as e:
            logger.error(f"Error adding tag '{tag}' to '{computer_name}' in {self.name}: {e}")
            return False

    def remove_custom_tag(self, computer_name: str, tag: str) -> bool:
        """Remove a custom tag from a computer"""
        try:
            # First, find the computer to get its ID
            computer = self._find_computer_by_name(computer_name)
            if not computer:
                logger.warning(f"Computer '{computer_name}' not found in {self.name}")
                return False

            # Execute the remove tag mutation
            variables = {'endpointId': computer.id, 'tag': tag}
            result = self.query(REMOVE_TAG_MUTATION, variables)

            success = result.get('data', {}).get('removeCustomTag', {}).get('success', False)
            if success:
                logger.info(f"Successfully removed tag '{tag}' from '{computer_name}' in {self.name}")
            else:
                message = result.get('data', {}).get('removeCustomTag', {}).get('message', 'Unknown error')
                logger.error(f"Failed to remove tag '{tag}' from '{computer_name}' in {self.name}: {message}")

            return success

        except Exception as e:
            logger.error(f"Error removing tag '{tag}' from '{computer_name}' in {self.name}: {e}")
            return False

    def _find_computer_by_name(self, computer_name: str) -> Optional[Computer]:
        """Find a computer by name in this instance"""
        computers = self.get_computers(limit=self.DEFAULT_SEARCH_LIMIT)
        return next((c for c in computers if c.name.lower() == computer_name.lower()), None)


class TaniumClient:
    """Main client for managing multiple Tanium instances"""
    DEFAULT_FILENAME = "all_tanium_hosts.xlsx"

    def __init__(self, config: Any = None):
        self.config = config or get_config()
        self.instances = []
        self._setup_instances()
        logger.info(f"Initialized TaniumClient with {len(self.instances)} instances")

    def _setup_instances(self):
        """Initialize cloud and on-prem instances"""
        # Cloud instance (verify SSL for cloud)
        if hasattr(self.config, 'tanium_cloud_api_url') and self.config.tanium_cloud_api_url and self.config.tanium_cloud_api_token:
            cloud_instance = TaniumInstance(
                "Cloud",
                self.config.tanium_cloud_api_url,
                self.config.tanium_cloud_api_token,
                verify_ssl=True
            )
            self.instances.append(cloud_instance)

        # On-prem instance (disable SSL verification for on-prem)
        if hasattr(self.config, 'tanium_onprem_api_url') and self.config.tanium_onprem_api_url and self.config.tanium_onprem_api_token:
            onprem_instance = TaniumInstance(
                "On-Prem",
                self.config.tanium_onprem_api_url,
                self.config.tanium_onprem_api_token,
                verify_ssl=False
            )
            self.instances.append(onprem_instance)

    def validate_all_tokens(self) -> Dict[str, bool]:
        """Validate tokens for all instances"""
        results = {}
        for instance in self.instances:
            results[instance.name] = instance.validate_token()
        return results

    def _get_all_computers(self, limit: Optional[int] = None) -> List[Computer]:
        """Get computers from all instances (private)."""
        all_computers = []
        for instance in self.instances:
            if not instance.validate_token():
                logger.warning(f"Invalid token for {instance.name}, skipping...")
                continue
            logger.info(f"Fetching computers from {instance.name}...")
            computers = instance.get_computers(limit)
            all_computers.extend(computers)
            logger.info(f"Retrieved {len(computers)} computers from {instance.name}")
        return all_computers

    def _get_output_path(self, filename: Optional[str] = None) -> Path:
        """Get the output path for Excel export"""
        today = datetime.now().strftime('%m-%d-%Y')
        output_dir = Path(__file__).parent.parent / "data" / "transient" / "epp_device_tagging" / today
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir / (filename or self.DEFAULT_FILENAME)

    def export_to_excel(self, all_computers: List[Computer], filename: Optional[str] = None) -> str:
        """Export computers data to Excel file with single sheet"""
        output_path = self._get_output_path(filename)

        data = []
        for computer in all_computers:
            data.append({
                'Hostname': computer.name,
                'ID': computer.id,
                'IP Address': computer.ip,
                'Last Seen': computer.eidLastSeen,
                'Source': computer.source,
                'Current Tags': ', '.join(computer.custom_tags),
            })

        try:
            df = pd.DataFrame(data)
            sheet_name = 'Computers'

            with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name=sheet_name, index=False)

                # Auto-adjust column widths
                worksheet = writer.sheets[sheet_name]
                for column in worksheet.columns:
                    max_length = max(len(str(cell.value)) for cell in column)
                    worksheet.column_dimensions[column[0].column_letter].width = min(max_length + 2, 50)

            logger.info(f"Data exported to: {output_path}")
            return str(output_path)

        except Exception as e:
            logger.error(f"Error exporting to Excel: {e}")
            raise

    def get_and_export_all_computers(self, filename: Optional[str] = None) -> Optional[str]:
        """Get all computers from all instances and export to Excel, using cache if available."""
        # Determine today's output path
        today = datetime.now().strftime('%m-%d-%Y')
        default_filename = filename or 'All Tanium Hosts.xlsx'
        output_path = Path(__file__).parent.parent / "data" / "transient" / "epp_device_tagging" / today / default_filename
        if output_path.exists():
            logger.info(f"Using cached file: {output_path}")
            return str(output_path)
        all_computers = self._get_all_computers()
        if not all_computers:
            logger.warning("No computers retrieved from any instance!")
            return None
        return self.export_to_excel(all_computers, default_filename)

    def get_computer_by_name(self, name: str) -> Optional[Computer]:
        """Get a specific computer by name from any instance"""
        all_computers = self._get_all_computers(limit=TaniumInstance.DEFAULT_SEARCH_LIMIT)
        return next((c for c in all_computers if c.name.lower() == name.lower()), None)

    def add_custom_tag_to_computer(self, computer_name: str, tag: str, instance_name: str) -> bool:
        """Add a custom tag to a computer in a specific instance"""
        instance = self._get_instance_by_name(instance_name)
        if not instance:
            logger.error(f"Instance '{instance_name}' not found")
            return False

        if not instance.validate_token():
            logger.error(f"Invalid token for {instance.name}")
            return False

        return instance.add_custom_tag(computer_name, tag)

    def remove_custom_tag_from_computer(self, computer_name: str, tag: str, instance_name: str) -> bool:
        """Remove a custom tag from a computer in a specific instance"""
        instance = self._get_instance_by_name(instance_name)
        if not instance:
            logger.error(f"Instance '{instance_name}' not found")
            return False

        if not instance.validate_token():
            logger.error(f"Invalid token for {instance.name}")
            return False

        return instance.remove_custom_tag(computer_name, tag)

    def _get_instance_by_name(self, instance_name: str) -> Optional[TaniumInstance]:
        """Get a Tanium instance by name"""
        return next((i for i in self.instances if i.name.lower() == instance_name.lower()), None)

    def list_available_instances(self) -> List[str]:
        """Get list of available instance names"""
        return [instance.name for instance in self.instances]

    def add_custom_tag_to_computer_all_instances(self, computer_name: str, tag: str) -> Dict[str, bool]:
        """Add a custom tag to a computer across all instances"""
        results = {}
        for instance in self.instances:
            if not instance.validate_token():
                logger.warning(f"Invalid token for {instance.name}, skipping...")
                results[instance.name] = False
                continue
            results[instance.name] = instance.add_custom_tag(computer_name, tag)
        return results

    def remove_custom_tag_from_computer_all_instances(self, computer_name: str, tag: str) -> Dict[str, bool]:
        """Remove a custom tag from a computer across all instances"""
        results = {}
        for instance in self.instances:
            if not instance.validate_token():
                logger.warning(f"Invalid token for {instance.name}, skipping...")
                results[instance.name] = False
                continue
            results[instance.name] = instance.remove_custom_tag(computer_name, tag)
        return results


def main():
    """Main function to demonstrate usage"""
    try:
        client = TaniumClient()

        # Validate all tokens first
        token_status = client.validate_all_tokens()

        # Only proceed if at least one token is valid
        if not any(token_status.values()):
            logger.error("No valid tokens found. Exiting.")
            return 1

        # Export all computers
        filename = client.get_and_export_all_computers()
        if filename:
            logger.info(f"Data exported to: {filename}")
        else:
            logger.warning("No data to export")

    except Exception as e:
        logger.error(f"Error during execution: {e}")


if __name__ == "__main__":
    exit(main())
