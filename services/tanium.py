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


def get_package_id_for_device_type(device_type: str) -> str:
    """Get the appropriate package ID for the given device type."""
    device_type_lower = device_type.lower()
    if device_type_lower == "windows":
        return "38355"  # Acme - Custom Tagging - Add Tags
    elif device_type_lower in ["linux", "unix", "macos", "mac"]:
        return "38356"  # Acme - Custom Tagging - Add Tags (Non-Windows)
    else:
        return "38355"  # Default to Windows


def build_tag_update_variables(tanium_id: str, tags: List[str], package_id: str, action: str) -> dict:
    """Build GraphQL variables for tag update mutation."""
    endpoint_id = int(tanium_id) if tanium_id.isdigit() else tanium_id

    logger.info(f"Building GraphQL variables - tanium_id: {tanium_id}, tags: {tags}, package_id: {package_id}")

    return {
        "name": f"{action} Custom Tags to {tanium_id}",
        "tag": ",".join(tags),
        "packageID": package_id,
        "endpoints": [endpoint_id],
        "distributeSeconds": 600,  # 10 minutes to distribute
        "expireSeconds": 3600,  # 1 hour to expire
        "startTime": datetime.now(timezone.utc).isoformat()  # Start immediately
    }


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

    def query(self, gql: str, variables: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute a GraphQL query"""
        payload: Dict[str, Any] = {'query': gql}
        if variables:
            payload['variables'] = variables

        logger.debug(f"Querying {self.name} at URL: {self.graphql_url}")

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
        # Note: verify parameter intentionally omitted to use SSL config defaults
        response = requests.post(
            f"{self.server_url}/api/v2/session/validate",
            json={'session': self.token},
            headers=self.headers,
            timeout=10
        )
        return response.status_code == 200

    def get_computer_by_id(self, tanium_id: str) -> Optional[Computer]:
        """Get a computer by its Tanium ID"""
        for computer in self._paginate_computers(limit=None):
            if computer.id == tanium_id:
                return computer
        return None

    def find_computer_by_name(self, computer_name: str) -> Optional[Computer]:
        """Find a computer by name in this instance"""
        computers = self.get_computers(limit=self.DEFAULT_SEARCH_LIMIT)
        return next((c for c in computers if c.name.lower() == computer_name.lower()), None)

    def get_tanium_id_by_hostname(self, hostname: str) -> Optional[str]:
        """Get Tanium ID for a computer by hostname"""
        for computer in self._paginate_computers(limit=None):
            if computer.name.lower() == hostname.lower():
                return computer.id
        return None

    def add_tag_by_name(self, computer_name: str, tag: str) -> Optional[dict]:
        """Add a custom tag to a computer by name. Returns action creation result or None if tag already exists."""
        computer = self.find_computer_by_name(computer_name)
        if not computer:
            raise TaniumAPIError(f"Computer '{computer_name}' not found")

        if tag in computer.custom_tags:
            return None  # Tag already exists

        updated_tags = computer.custom_tags + [tag]
        package_id = get_package_id_for_device_type("windows")
        variables = build_tag_update_variables(computer.id, updated_tags, package_id, action="Add")
        result = self.query(UPDATE_TAGS_MUTATION, variables)

        # Extract action creation result from GraphQL response
        action_create_result = result.get('data', {}).get('actionCreate', {})

        if error := action_create_result.get('error'):
            raise TaniumAPIError(f"GraphQL error: {error.get('message', 'Unknown error')}")

        if not action_create_result.get('action'):
            raise TaniumAPIError("No action data returned from GraphQL response")

        return action_create_result

    def remove_tag_by_name(self, computer_name: str, tag: str) -> Optional[dict]:
        """Remove a custom tag from a computer by name. Returns action creation result or None if tag didn't exist."""
        computer = self.find_computer_by_name(computer_name)
        if not computer:
            raise TaniumAPIError(f"Computer '{computer_name}' not found")

        if tag not in computer.custom_tags:
            return None  # Tag didn't exist

        updated_tags = [t for t in computer.custom_tags if t != tag]
        package_id = get_package_id_for_device_type("windows")
        variables = build_tag_update_variables(computer.id, updated_tags, package_id, action="Remove")
        result = self.query(UPDATE_TAGS_MUTATION, variables)

        # Extract action creation result from GraphQL response
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

    def __init__(self, config: Any = None):
        self.config = config or get_config()
        self.instances = []
        self._setup_instances()

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

            # Add Cloud Write instance if write token is available
            if hasattr(self.config, 'tanium_cloud_api_token_write') and self.config.tanium_cloud_api_token_write:
                cloud_write_instance = TaniumInstance(
                    "Cloud-Write",
                    self.config.tanium_cloud_api_url,
                    self.config.tanium_cloud_api_token_write,
                    verify_ssl=True
                )
                self.instances.append(cloud_write_instance)

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
                'Last Seen': computer.eidLastSeen,
                'Source': computer.source,
                'Current Tags': ', '.join(computer.custom_tags),
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
        """Get all computers from all instances and export to Excel, using cache if available."""
        # Determine today's output path
        today = datetime.now().strftime('%m-%d-%Y')
        default_filename = filename or 'All Tanium Hosts.xlsx'
        output_path = Path(__file__).parent.parent / "data" / "transient" / "epp_device_tagging" / today / default_filename
        if output_path.exists():
            return str(output_path)
        all_computers = self._get_all_computers()
        if not all_computers:
            return None
        return self.export_to_excel(all_computers, default_filename)

    def get_computer_by_name(self, name: str) -> Optional[Computer]:
        """Get a specific computer by name from any instance"""
        all_computers = self._get_all_computers(limit=TaniumInstance.DEFAULT_SEARCH_LIMIT)
        return next((c for c in all_computers if c.name.lower() == name.lower()), None)

    def get_tanium_id_by_hostname(self, hostname: str, instance_name: str) -> Optional[str]:
        """Get Tanium ID for a computer by hostname"""
        instance = self.get_instance_by_name(instance_name)
        if not instance:
            return None
        return instance.get_tanium_id_by_hostname(hostname)

    def search_computers(self, search_term: str, instance_name: str, limit: int = 10) -> List[Computer]:
        """Search for hostnames containing the search term"""
        instance = self.get_instance_by_name(instance_name)
        matches = []

        for computer in instance.iterate_computers(limit=None):
            if search_term.lower() in computer.name.lower():
                matches.append(computer)
                if len(matches) >= limit:
                    break

        return matches

    def get_instance_by_name(self, instance_name: str) -> Optional[TaniumInstance]:
        """Get a Tanium instance by name"""
        return next((i for i in self.instances if i.name.lower() == instance_name.lower()), None)

    def list_available_instances(self) -> List[str]:
        """Get list of available instance names"""
        return [instance.name for instance in self.instances]

    def add_tag(self, tanium_id: str, tag: str, instance_name: str, device_type: str) -> Optional[dict]:
        """Add a custom tag to a computer using its Tanium ID. Returns action creation result or None if tag already exists."""
        instance = self.get_instance_by_name(instance_name)
        computer = instance.get_computer_by_id(tanium_id)

        if tag in computer.custom_tags:
            return None  # Tag already exists

        updated_tags = computer.custom_tags + [tag]
        package_id = get_package_id_for_device_type(device_type)
        variables = build_tag_update_variables(tanium_id, updated_tags, package_id, action="Add")

        # Log GraphQL variables for debugging
        logger.info(f"GraphQL variables for tagging {tanium_id}: {variables}")

        result = instance.query(UPDATE_TAGS_MUTATION, variables)

        # Extract action creation result from GraphQL response
        action_create_result = result.get('data', {}).get('actionCreate', {})

        if error := action_create_result.get('error'):
            raise TaniumAPIError(f"GraphQL error: {error.get('message', 'Unknown error')}")

        if not action_create_result.get('action'):
            raise TaniumAPIError("No action data returned from GraphQL response")

        action_id = action_create_result.get('action', {}).get('scheduledAction', {}).get('id')
        logger.info(f"Created scheduled action {action_id} for tagging {tanium_id}")
        return action_create_result

    def remove_tag(self, tanium_id: str, tag: str, instance_name: str, device_type: str) -> Optional[dict]:
        """Remove a custom tag from a computer using its Tanium ID. Returns action creation result or None if tag didn't exist."""
        instance = self.get_instance_by_name(instance_name)
        computer = instance.get_computer_by_id(tanium_id)

        if tag not in computer.custom_tags:
            return None  # Tag didn't exist

        updated_tags = [t for t in computer.custom_tags if t != tag]
        package_id = get_package_id_for_device_type(device_type)
        variables = build_tag_update_variables(tanium_id, updated_tags, package_id, action="Remove")

        # Log GraphQL variables for debugging
        logger.info(f"GraphQL variables for removing tag from {tanium_id}: {variables}")

        result = instance.query(UPDATE_TAGS_MUTATION, variables)

        # Extract action creation result from GraphQL response
        action_create_result = result.get('data', {}).get('actionCreate', {})

        if error := action_create_result.get('error'):
            raise TaniumAPIError(f"GraphQL error: {error.get('message', 'Unknown error')}")

        if not action_create_result.get('action'):
            raise TaniumAPIError("No action data returned from GraphQL response")

        action_id = action_create_result.get('action', {}).get('scheduledAction', {}).get('id')
        logger.info(f"Created scheduled action {action_id} for removing tag from {tanium_id}")
        return action_create_result


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

        # # Export all computers
        # filename = client.get_and_export_all_computers()
        # if filename:
        #     logger.info(f"Data exported to: {filename}")
        # else:
        #     logger.warning("No data to export")

        # Test: Direct tagging with known Tanium ID (no hostname lookup needed)
        test_hostname = "uscku1metu03c7l.METNET.NET"  # Full hostname from Tanium
        test_tanium_id = "621122"  # We already confirmed this ID matches the hostname
        test_tag = "TestTag123"  # Simple test tag
        write_instance = "Cloud-Write"
        tag_action = 'remove'  # or 'remove'

        # First, test if write token can read data
        logger.info("Testing if write token can read computer data...")
        write_instance_obj = client.get_instance_by_name(write_instance)
        if write_instance_obj:
            try:
                test_computer = write_instance_obj.get_computer_by_id(test_tanium_id)
                if test_computer:
                    logger.info(f"✓ Write token CAN read computer data - found: {test_computer.name} with tags: {test_computer.custom_tags}")
                else:
                    logger.warning(f"✗ Write token can't find computer ID {test_tanium_id} - might have limited scope")
            except Exception as e:
                logger.error(f"✗ Write token CANNOT read computer data: {e}")

        # Now test tagging
        if tag_action == 'add':
            logger.info(f"Testing direct tagging for {test_hostname} (ID: {test_tanium_id}) with write token...")
            tag_result = client.add_tag(
                test_tanium_id,
                test_tag,
                write_instance,
                "linux",  # Test with non-Windows to see if package ID 38356 works
            )
            logger.info(f"Tagging result for {test_hostname} (ID: {test_tanium_id}) with tag '{test_tag}' using {write_instance}: {tag_result}")
        elif tag_action == 'remove':
            logger.info(f"Testing direct untagging for {test_hostname} (ID: {test_tanium_id}) with write token...")
            tag_result = client.remove_tag(
                test_tanium_id,
                test_tag,
                write_instance,
                "linux",  # Test with non-Windows to see if package ID 38356 works
            )
            logger.info(f"Tagging result for {test_hostname} (ID: {test_tanium_id}) with tag '{test_tag}' using {write_instance}: {tag_result}")

    except Exception as e:
        logger.error(f"Error during execution: {e}")


if __name__ == "__main__":
    exit(main())
