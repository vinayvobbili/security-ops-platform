#!/usr/bin/env python3
"""
Simple Tanium API Client for fetching computers and custom tags from multiple instances

Usage:
    client = TaniumClient()
    filename = client.get_and_export_all_computers()
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, Iterator, Callable

import pandas as pd
import requests
import tqdm
import urllib3
from urllib3.exceptions import InsecureRequestWarning

from config import get_config

# Disable SSL warnings for on-prem connections
urllib3.disable_warnings(InsecureRequestWarning)

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

    def has_epp_power_mode_tag(self) -> bool:
        """Check if computer has an EPP Power Mode tag EPP_POWERMODE (case-insensitive)"""
        return any(str(tag).upper() == "EPP_POWERMODE" for tag in self.custom_tags)


class TaniumAPIError(Exception):
    """Custom exception for Tanium API errors"""
    pass


class TaniumInstance:
    """Represents a single Tanium instance (cloud or on-prem)"""
    NO_TAGS_PLACEHOLDER = '[No Tags]'

    def __init__(self, name: str, server_url: str, token: str, verify_ssl: bool = True,
                 page_size: int = 5000, search_limit: int = 500):
        self.name = name
        self.server_url = server_url.rstrip('/')
        self.token = token
        self.headers = {'session': self.token}
        self.graphql_url = f"{self.server_url}/plugin/products/gateway/graphql"
        self.verify_ssl = verify_ssl
        self.page_size = page_size
        self.search_limit = search_limit
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

    # Computer Retrieval Operations
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
                variables = {'first': self.page_size}
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

    def find_computer_by_name(self, computer_name: str) -> Optional[Computer]:
        """Find a computer by name in this instance"""
        computers = self.get_computers(limit=self.search_limit)
        return next((c for c in computers if c.name.lower() == computer_name.lower()), None)

    # Tag Operations
    def add_custom_tag(self, computer_name: str, tag: str) -> bool:
        """Add a custom tag to a computer"""
        try:
            computer = self.find_computer_by_name(computer_name)
            if not computer:
                logger.warning(f"Computer '{computer_name}' not found in {self.name}")
                return False

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
            computer = self.find_computer_by_name(computer_name)
            if not computer:
                logger.warning(f"Computer '{computer_name}' not found in {self.name}")
                return False

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


class TaniumClient(ABC):
    """Abstract base client for managing a single Tanium instance"""
    DEFAULT_FILENAME = "all_tanium_hosts.xlsx"

    def __init__(self, config: Any = None):
        self.config = config or get_config()
        self.instance = self._create_instance()
        if self.instance:
            logger.info(f"Initialized {self.__class__.__name__} for instance: {self.instance.name}")
        else:
            logger.warning(f"No instance configured for {self.__class__.__name__}")

    @abstractmethod
    def _create_instance(self) -> Optional[TaniumInstance]:
        """Create the instance for this client type"""
        pass

    def validate_token(self) -> bool:
        """Validate token for this instance"""
        if not self.instance:
            return False
        return self.instance.validate_token()

    # Computer Retrieval Operations
    def get_all_computers(self, limit: Optional[int] = None) -> List[Computer]:
        """Get computers from this instance"""
        if not self.instance or not self.instance.validate_token():
            logger.warning(f"Cannot fetch computers: invalid instance or token")
            return []

        logger.info(f"Fetching computers from {self.instance.name}...")
        computers = self.instance.get_computers(limit)
        logger.info(f"Retrieved {len(computers)} computers from {self.instance.name}")
        return computers

    def get_computer_by_name(self, name: str) -> Optional[Computer]:
        """Get a specific computer by name from this instance"""
        if not self.instance or not self.instance.validate_token():
            return None
        return self.instance.find_computer_by_name(name)

    # Tag Operations
    def add_custom_tag_to_computer(self, computer_name: str, tag: str) -> bool:
        """Add a custom tag to a computer in this instance"""
        if not self.instance:
            logger.error("No instance configured for this client")
            return False

        if not self.instance.validate_token():
            logger.error(f"Invalid token for {self.instance.name}")
            return False

        return self.instance.add_custom_tag(computer_name, tag)

    def remove_custom_tag_from_computer(self, computer_name: str, tag: str) -> bool:
        """Remove a custom tag from a computer in this instance"""
        if not self.instance:
            logger.error("No instance configured for this client")
            return False

        if not self.instance.validate_token():
            logger.error(f"Invalid token for {self.instance.name}")
            return False

        return self.instance.remove_custom_tag(computer_name, tag)

    # Export Operations
    def _get_cached_file_path(self, filename: Optional[str] = None) -> Path:
        """Get path for cached file"""
        today = datetime.now().strftime('%m-%d-%Y')
        default_filename = filename or 'All Tanium Hosts.xlsx'
        return Path(__file__).parent.parent / "data" / "transient" / "epp_device_tagging" / today / default_filename

    def _get_output_path(self, filename: Optional[str] = None) -> Path:
        """Get the output path for Excel export"""
        output_path = self._get_cached_file_path(filename)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        return output_path

    def export_to_excel(self, all_computers: List[Computer], filename: Optional[str] = None,
                        engine: str = 'openpyxl') -> str:
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

            with pd.ExcelWriter(output_path, engine=engine) as writer:
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
        """Get all computers from this instance and export to Excel, using cache if available."""
        cached_path = self._get_cached_file_path(filename)
        if cached_path.exists():
            logger.info(f"Using cached file: {cached_path}")
            return str(cached_path)

        all_computers = self.get_all_computers()
        if not all_computers:
            logger.warning("No computers retrieved from instance!")
            return None

        return self.export_to_excel(all_computers, filename)


class TaniumCloudClient(TaniumClient):
    """Client for managing Tanium Cloud instance"""

    def _create_instance(self) -> Optional[TaniumInstance]:
        """Create cloud instance if configuration is available"""
        if not self._has_cloud_config():
            logger.warning("Cloud configuration not found")
            return None

        return TaniumInstance(
            "Cloud",
            self.config.tanium_cloud_api_url,
            self.config.tanium_cloud_api_token,
            verify_ssl=True,
            page_size=getattr(self.config, 'cloud_page_size', 5000),
            search_limit=getattr(self.config, 'cloud_search_limit', 500)
        )

    def _has_cloud_config(self) -> bool:
        """Check if cloud configuration is available"""
        return (hasattr(self.config, 'tanium_cloud_api_url') and
                self.config.tanium_cloud_api_url and
                self.config.tanium_cloud_api_token)


class TaniumOnPremClient(TaniumClient):
    """Client for managing Tanium On-Prem instance"""

    def _create_instance(self) -> Optional[TaniumInstance]:
        """Create on-prem instance if configuration is available"""
        if not self._has_onprem_config():
            logger.warning("On-Prem configuration not found")
            return None

        return TaniumInstance(
            "On-Prem",
            self.config.tanium_onprem_api_url,
            self.config.tanium_onprem_api_token,
            verify_ssl=False,
            page_size=getattr(self.config, 'onprem_page_size', 5000),
            search_limit=getattr(self.config, 'onprem_search_limit', 500)
        )

    def _has_onprem_config(self) -> bool:
        """Check if on-prem configuration is available"""
        return (hasattr(self.config, 'tanium_onprem_api_url') and
                self.config.tanium_onprem_api_url and
                self.config.tanium_onprem_api_token)


def main():
    """Main function to demonstrate usage"""
    # Test parameters - easy to modify in PyCharm
    computer_name = "SampleHost"
    tag = "TestTag"
    instance_name = 'cloud'  # 'cloud' or 'onprem'

    try:
        # Choose client based on instance_name
        if instance_name.lower() == 'cloud':
            client = TaniumCloudClient()
            logger.info("Using cloud client for testing")
        else:
            client = TaniumOnPremClient()
            logger.info("Using on-prem client for testing")

        # Validate token first
        if not client.validate_token():
            logger.error(f"No valid token found for {instance_name} client. Exiting.")
            return 1

        # Test tag operations
        logger.info(f"Testing operations on '{computer_name}' with tag '{tag}'")

        # Add tag
        result = client.add_custom_tag_to_computer(computer_name, tag)
        if result:
            logger.info(f"Successfully added tag '{tag}' to '{computer_name}'")
        else:
            logger.warning(f"Failed to add tag '{tag}' to '{computer_name}'")

        # Optionally test removal (uncomment to test)
        # remove_result = client.remove_custom_tag_from_computer(computer_name, tag)
        # logger.info(f"Remove operation result: {remove_result}")

        # Optionally test computer lookup (uncomment to test)
        # computer = client.get_computer_by_name(computer_name)
        # if computer:
        #     logger.info(f"Found computer: {computer.name} with tags: {computer.custom_tags}")
        # else:
        #     logger.info(f"Computer '{computer_name}' not found")

        return 0

    except Exception as e:
        logger.error(f"Error during execution: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
