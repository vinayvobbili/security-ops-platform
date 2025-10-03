#!/usr/bin/env python3
"""
Simple Tanium API Client for fetching computers and custom tags from multiple instances

Usage:
    client = TaniumClient()
    filename = client.get_and_export_all_computers()
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any, Iterator

import pandas as pd
import requests
import tqdm
import urllib3
from urllib3.exceptions import InsecureRequestWarning

from my_config import get_config
from src.utils.ssl_config import configure_ssl_for_corporate_proxy

configure_ssl_for_corporate_proxy()

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
        os {
          platform
        }
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

ENDPOINT_BY_NAME_QUERY = """
query getEndpointByName($name: String!) {
  endpoints(first: 1, filter: {path: "name", op: EQ, value: $name}) {
    edges {
      node {
        id
        name
        ipAddress
        eidLastSeen
        os {
          platform
        }
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

ENDPOINTS_SEARCH_QUERY = """
query searchEndpointsByName($searchTerm: String!, $limit: Int!) {
  endpoints(first: $limit, filter: {path: "name", op: CONTAINS, value: $searchTerm}) {
    edges {
      node {
        id
        name
        ipAddress
        eidLastSeen
        os {
          platform
        }
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

UPDATE_TAGS_MUTATION = """
mutation createParamTaniumAction($comment: String, $distributeSeconds: Int, $expireSeconds: Int, $name: String, $tag: String!, $startTime: Time, $packageID: ID, $endpoints: [ID!]!) {
  actionCreate(
    input: {comment: $comment, name: $name, package: {id: $packageID, params: [$tag]}, targets: {endpoints: $endpoints, actionGroup: {id: 4}}, schedule: {distributeSeconds: $distributeSeconds, expireSeconds: $expireSeconds, startTime: $startTime}}
  ) {
    action {
      scheduledAction {
        id
      }
    }
    error {
      message
    }
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
    os_platform: str = ""  # Operating system platform (Windows, Linux, Mac)
    custom_tags: List[str] = None

    def __post_init__(self):
        if self.custom_tags is None:
            self.custom_tags = []

    def has_epp_ring_tag(self) -> bool:
        """Check if computer has an EPP Ring tag (case-insensitive)"""
        return any(str(tag).upper().startswith('EPP') and 'RING' in str(tag).upper() for tag in self.custom_tags)

    def has_epp_power_mode_tag(self) -> bool:
        """Check if computer has an EPP Power Mode tag EPP_POWERMODE (case-insensitive)"""
        return any(str(tag).upper() == "EPP_POWERMODE" for tag in self.custom_tags)


class TaniumAPIError(Exception):
    """Custom exception for Tanium API errors"""
    pass


class TaniumInstance:
    """Represents a single Tanium instance (cloud or on-prem)"""
    DEFAULT_PAGE_SIZE = 5000
    DEFAULT_SEARCH_LIMIT = 500
    NO_TAGS_PLACEHOLDER = ''

    def __init__(self, name: str, server_url: str, token: str, verify_ssl: bool = True):
        self.name = name
        self.server_url = server_url.rstrip('/')
        self.token = token
        self.headers = {'session': self.token}
        self.graphql_url = f"{self.server_url}/plugin/products/gateway/graphql"
        self.verify_ssl = verify_ssl
        logger.info(f"Initialized Tanium instance: {self.name}")

    @staticmethod
    def get_package_id_for_device_type(device_type: str) -> str:
        """Get the appropriate Tanium package ID for the given device type."""
        device_type_lower = device_type.lower()
        if device_type_lower in ["linux", "unix", "macos", "mac"]:
            return "38356"  # Custom Tagging - Add Tags (Non-Windows)
        return "38355"  # Windows

    @staticmethod
    def build_tag_update_variables(tanium_id: str, tags: List[str], package_id: str, action: str) -> dict:
        """Build GraphQL variables for tag update mutation."""
        endpoint_id = int(tanium_id) if tanium_id.isdigit() else tanium_id
        logger.info(f"Building GraphQL variables - tanium_id: {tanium_id}, tags: {tags}, package_id: {package_id}")
        return {
            "name": f"{action} Custom Tags to {tanium_id}",
            "tag": " ".join(tags),
            "packageID": package_id,
            "endpoints": [endpoint_id],
            "distributeSeconds": 60,
            "expireSeconds": 3600,
            "startTime": datetime.now(timezone.utc).isoformat()
        }

    def query(self, gql: str, variables: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute a GraphQL query"""
        payload: Dict[str, Any] = {'query': gql}
        if variables:
            payload['variables'] = variables

        logger.debug(f"Querying {self.name} at URL: {self.graphql_url}")
        logger.debug(f"GraphQL payload: {payload}")

        try:
            headers = self.headers.copy()
            headers['Content-Type'] = 'application/json'

            # Note: verify parameter intentionally omitted to use SSL config defaults
            response = requests.post(
                self.graphql_url,
                json=payload,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()

            result = response.json()
            if 'errors' in result:
                raise TaniumAPIError(f"GraphQL errors: {result['errors']}")
            return result

        except requests.RequestException as e:
            logger.error(f"Request failed for {self.name}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_details = e.response.json()
                    logger.error(f"GraphQL error details: {error_details}")
                except (ValueError, TypeError, AttributeError):
                    logger.error(f"Response text: {e.response.text}")
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

        logger.info(f"Starting pagination for {self.name} with page_size={self.DEFAULT_PAGE_SIZE}, limit={limit}")

        with tqdm.tqdm(desc=f"Fetching computers from {self.name}", unit="host") as pbar:
            page_num = 0
            while True:
                page_num += 1
                variables = {'first': self.DEFAULT_PAGE_SIZE}
                if after_cursor:
                    variables['after'] = after_cursor

                logger.debug(f"Fetching page {page_num} with variables: {variables}")
                data = self.query(ENDPOINTS_QUERY, variables)
                endpoints = data['data']['endpoints']
                edges = endpoints['edges']
                page_info = endpoints['pageInfo']

                logger.info(f"Page {page_num}: received {len(edges)} computers, hasNextPage={page_info['hasNextPage']}")

                if not edges:
                    break

                for edge in edges:
                    if limit and computers_fetched >= limit:
                        logger.info(f"Reached limit of {limit} computers, stopping pagination")
                        return

                    computer = self.extract_computer_from_node(edge['node'])
                    yield computer
                    computers_fetched += 1

                pbar.update(len(edges))

                if not page_info['hasNextPage']:
                    logger.info(f"No more pages available. Total computers fetched: {computers_fetched}")
                    break

                after_cursor = page_info['endCursor']
                logger.debug(f"Moving to next page with cursor: {after_cursor}")

    def extract_computer_from_node(self, node: Dict[str, Any]) -> Computer:
        """Extract computer data from GraphQL node"""
        custom_tags = self._extract_custom_tags(node.get('sensorReadings', {}))
        os_data = node.get('os', {})
        os_platform = os_data.get('platform', '') if os_data else ''

        return Computer(
            name=node.get('name', ''),
            id=node.get('id', ''),
            ip=node.get('ipAddress'),
            eidLastSeen=node.get('eidLastSeen'),
            source=self.name,
            os_platform=os_platform,
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
            # Note: verify parameter intentionally omitted to use SSL config defaults
            response = requests.post(
                f"{self.server_url}/api/v2/session/validate",
                json={'session': self.token},
                headers=self.headers,
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            logger.warning(f"Token validation failed for {self.name}: {e}")
            return False

    def find_computer_by_name(self, computer_name: str) -> Optional[Computer]:
        """Find a computer by exact name in this instance using GraphQL filter"""
        data = self.query(ENDPOINT_BY_NAME_QUERY, {'name': computer_name})
        edges = data.get('data', {}).get('endpoints', {}).get('edges', [])

        if edges:
            return self.extract_computer_from_node(edges[0]['node'])

        logger.debug(f"No computer found with name '{computer_name}' in {self.name}")
        return None

    def add_tag_by_name(self, computer_name: str, tag: str) -> dict:
        """Add a custom tag to a computer by name."""
        computer = self.find_computer_by_name(computer_name)
        if not computer:
            raise TaniumAPIError(f"Computer '{computer_name}' not found")

        updated_tags = computer.custom_tags + [tag]
        device_type = computer.os_platform or "windows"
        package_id = self.get_package_id_for_device_type(device_type)
        variables = self.build_tag_update_variables(computer.id, updated_tags, package_id, action="Add")
        result = self.query(UPDATE_TAGS_MUTATION, variables)

        action_create_result = result.get('data', {}).get('actionCreate', {})
        if error := action_create_result.get('error'):
            raise TaniumAPIError(f"GraphQL error: {error.get('message', 'Unknown error')}")
        if not action_create_result.get('action'):
            raise TaniumAPIError("No action data returned from GraphQL response")

        return action_create_result

    def remove_tag_by_name(self, computer_name: str, tag: str) -> dict:
        """Remove a custom tag from a computer by name."""
        computer = self.find_computer_by_name(computer_name)
        if not computer:
            raise TaniumAPIError(f"Computer '{computer_name}' not found")

        updated_tags = [t for t in computer.custom_tags if t != tag]
        device_type = computer.os_platform or "windows"
        package_id = self.get_package_id_for_device_type(device_type)
        variables = self.build_tag_update_variables(computer.id, updated_tags, package_id, action="Remove")
        result = self.query(UPDATE_TAGS_MUTATION, variables)

        action_create_result = result.get('data', {}).get('actionCreate', {})
        if error := action_create_result.get('error'):
            raise TaniumAPIError(f"GraphQL error: {error.get('message', 'Unknown error')}")
        if not action_create_result.get('action'):
            raise TaniumAPIError("No action data returned from GraphQL response")

        return action_create_result

    def iterate_computers(self, limit: Optional[int] = None) -> Iterator[Computer]:
        """Public method to iterate through computers with pagination"""
        return self._paginate_computers(limit)


class TaniumClient:
    """Main client for managing multiple Tanium instances"""
    DEFAULT_FILENAME = "all_tanium_hosts.xlsx"

    def __init__(self, config: Any = None, instance: Optional[str] = None):
        """
        Initialize TaniumClient.

        Args:
            config: Configuration object
            instance: Instance to connect to - "cloud", "onprem", or None for all instances
        """
        self.config = config or get_config()
        self.instances = []
        self._setup_instances(instance=instance)

    def _setup_instances(self, instance: Optional[str] = None):
        """Initialize cloud and/or on-prem instances based on instance parameter"""
        if instance and instance.lower() not in ["cloud", "onprem"]:
            raise ValueError(f"Invalid instance: {instance}. Must be 'cloud', 'onprem', or None for all.")

        # Cloud instance (verify SSL for cloud)
        if (instance is None or instance.lower() == "cloud") and hasattr(self.config, 'tanium_cloud_api_url') and self.config.tanium_cloud_api_url and self.config.tanium_cloud_api_token:
            cloud_instance = TaniumInstance(
                "Cloud",
                self.config.tanium_cloud_api_url,
                self.config.tanium_cloud_api_token,
                verify_ssl=True
            )
            self.instances.append(cloud_instance)

        # On-prem instance (disable SSL verification for on-prem)
        if (instance is None or instance.lower() == "onprem") and hasattr(self.config, 'tanium_onprem_api_url') and self.config.tanium_onprem_api_url and self.config.tanium_onprem_api_token:
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
        """Get computers from all instances"""
        all_computers = []
        for instance in self.instances:
            if instance.validate_token():
                computers = instance.get_computers(limit)
                all_computers.extend(computers)
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
                'OS Platform': computer.os_platform,
                'Last Seen': computer.eidLastSeen,
                'Source': computer.source,
                'Current Tags': '\n'.join(computer.custom_tags),
            })

        df = pd.DataFrame(data)
        sheet_name = 'Computers'

        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name=sheet_name, index=False)

            # Auto-adjust column widths
            worksheet = writer.sheets[sheet_name]
            for column in worksheet.columns:
                max_length = max(len(str(cell.value)) for cell in column)
                worksheet.column_dimensions[column[0].column_letter].width = min(max_length + 2, 50)

        return str(output_path)

    def get_and_export_all_computers(self, filename: Optional[str] = None) -> Optional[str]:
        """Get all computers from all instances and export to Excel (always fetches fresh data)."""
        default_filename = filename or 'All Tanium Hosts.xlsx'
        all_computers = self._get_all_computers()
        if not all_computers:
            return None
        return self.export_to_excel(all_computers, default_filename)

    def get_computer_by_name(self, name: str, instance_name: str) -> Optional[Computer]:
        """Get a specific computer by name from the specified instance using GraphQL filter"""
        instance = self.get_instance_by_name(instance_name)
        if not instance:
            return None
        return instance.find_computer_by_name(name)

    def search_computers(self, search_term: str, instance_name: str, limit: int = 10) -> List[Computer]:
        """Search for hostnames containing the search term using GraphQL filter"""
        instance = self.get_instance_by_name(instance_name)
        if not instance:
            return []

        data = instance.query(ENDPOINTS_SEARCH_QUERY, {'searchTerm': search_term, 'limit': limit})
        edges = data.get('data', {}).get('endpoints', {}).get('edges', [])

        matches = [instance.extract_computer_from_node(edge['node']) for edge in edges]
        logger.info(f"Found {len(matches)} computers matching '{search_term}' in {instance_name}")
        return matches

    def get_instance_by_name(self, instance_name: str) -> Optional[TaniumInstance]:
        """Get a Tanium instance by name"""
        return next((i for i in self.instances if i.name.lower() == instance_name.lower()), None)

    def list_available_instances(self) -> List[str]:
        """Get list of available instance names"""
        return [instance.name for instance in self.instances]


def main():
    """Main function to demonstrate usage"""
    try:
        client = TaniumClient()

        # Validate all tokens first
        logger.info("Validating tokens...")
        token_status = client.validate_all_tokens()
        for instance_name, is_valid in token_status.items():
            if is_valid:
                logger.info(f"✓ {instance_name} token is valid")
            else:
                logger.warning(f"✗ {instance_name} token is invalid or unreachable")

        # # Export all computers
        # filename = client.get_and_export_all_computers()
        # if filename:
        #     logger.info(f"Data exported to: {filename}")
        # else:
        #     logger.warning("No data to export")

        # Test: Add and Remove tags
        test_hostname = "VV10-MLKH3-042.acme.co.kr"
        test_tag = "TestTag123"
        instance_name = "On-Prem"  # or "On-Prem"
        tag_action = 'add'  # Change to 'remove' to test removal

        instance = client.get_instance_by_name(instance_name)
        if not instance:
            logger.error(f"Instance {instance_name} not found")
            return 1

        # Get computer info first
        computer = instance.find_computer_by_name(test_hostname)
        if not computer:
            logger.error(f"Computer {test_hostname} not found")
            return 1

        logger.info(f"\n=== Testing tag operations on {test_hostname} in {instance_name} ===")
        logger.info(f"Computer ID: {computer.id}")
        logger.info(f"OS Platform: {computer.os_platform}")
        logger.info(f"Current tags: {computer.custom_tags}")

        if tag_action == 'add':
            logger.info(f"\nTesting ADD tag '{test_tag}'...")
            result = instance.add_tag_by_name(test_hostname, test_tag)
            action_id = result.get('action', {}).get('scheduledAction', {}).get('id')
            logger.info(f"✓ Tag add action created successfully")
            logger.info(f"  Action ID: {action_id}")

        elif tag_action == 'remove':
            logger.info(f"\nTesting REMOVE tag '{test_tag}'...")
            result = instance.remove_tag_by_name(test_hostname, test_tag)
            action_id = result.get('action', {}).get('scheduledAction', {}).get('id')
            logger.info(f"✓ Tag remove action created successfully")
            logger.info(f"  Action ID: {action_id}")

    except Exception as e:
        logger.error(f"Error during execution: {e}")


if __name__ == "__main__":
    exit(main())
