#!/usr/bin/env python3
"""
Simple Tanium API Client for fetching computers and custom tags from multiple instances

Usage:
    client = TaniumClient()
    filename = client.get_and_export_all_computers()
"""
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any, Iterator

import pandas as pd
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
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

SIGNALS_QUERY = """
query getSignals($first: Int, $after: Cursor) {
  threatResponseSignals(first: $first, after: $after) {
    pageInfo {
      hasNextPage
      endCursor
    }
    edges {
      node {
        id
        name
        description
        severity
        enabled
        mitreTactics
        mitreTechniques
        createdAt
        updatedAt
      }
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
    eid_status: str = ""  # Online/Offline status from Tanium
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


def get_package_id_for_instance(source: str, os_platform: str) -> str:
    """Get the appropriate Tanium package ID based on instance (source) and OS platform.

    Args:
        source: Instance name (e.g., "Cloud", "On-Prem")
        os_platform: Operating system platform (e.g., "Windows", "Linux")

    Returns:
        Package ID string

    Cloud package IDs:
        - 38355: Windows
        - 38356: Non-Windows (Linux, Unix, Mac)

    On-Prem package IDs:
        - 1235: Both Windows and Non-Windows
    """
    os_lower = os_platform.lower() if os_platform else ""
    is_cloud = "cloud" in source.lower() if source else False

    # Check for non-Windows platforms
    is_non_windows = any(platform in os_lower for platform in
                         ["linux", "unix", "mac", "darwin", "aix", "solaris", "freebsd"])

    if is_cloud:
        # Cloud instance package IDs
        if is_non_windows:
            return "38356"  # Custom Tagging - Add Tags (Non-Windows) - Cloud
        return "38355"  # Custom Tagging - Add Tags (Windows) - Cloud
    else:
        # On-Prem instance package ID (same for all platforms)
        return "1235"  # Custom Tagging - Add Tags - On-Prem


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
        self.last_error: str | None = None  # Stores last validation/connection error for better error reporting

        # Create a persistent session with retry logic to prevent broken pipe errors
        self.session = requests.Session()

        # Configure retry strategy for connection errors, timeouts, and server errors
        retry_strategy = Retry(
            total=3,  # Total number of retries
            backoff_factor=1,  # Wait 1s, 2s, 4s between retries
            status_forcelist=[429, 500, 502, 503, 504],  # Retry on these HTTP status codes
            allowed_methods=["POST"],  # Retry POST requests (GraphQL uses POST)
            raise_on_status=False  # Don't raise exception on max retries, let us handle it
        )

        # Mount the retry adapter for both http and https
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,  # Number of connection pools to cache
            pool_maxsize=20,  # Max connections to save in the pool
            pool_block=False  # Don't block when pool is full, create new connection
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Set default headers on the session
        self.session.headers.update(self.headers)

        logger.info(f"Initialized Tanium instance: {self.name} (URL: {self.server_url}) with retry logic")

    def get_package_id_for_device_type(self, device_type: str) -> str:
        """Get the appropriate Tanium package ID for the given device type and instance.

        Uses the shared utility function to determine package ID.
        """
        return get_package_id_for_instance(self.name, device_type)

    @staticmethod
    def build_tag_update_variables(tanium_id: str, tags: List[str], package_id: str, action: str) -> dict:
        """Build GraphQL variables for tag update mutation."""
        endpoint_id = int(tanium_id) if tanium_id.isdigit() else tanium_id
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
        """Execute a GraphQL query using persistent session with retry logic"""
        payload: Dict[str, Any] = {'query': gql}
        if variables:
            payload['variables'] = variables

        logger.debug(f"Querying {self.name} at URL: {self.graphql_url}")
        logger.debug(f"GraphQL payload: {payload}")

        try:
            headers = {'Content-Type': 'application/json'}

            # Use persistent session with retry logic (configured in __init__)
            # Note: verify parameter intentionally omitted to use SSL config defaults
            response = self.session.post(
                self.graphql_url,
                json=payload,
                headers=headers,
                timeout=60  # Increased from 30s to 60s for bulk operations
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

        # Disable tqdm in non-interactive contexts (e.g., when called from bots/services)
        # to prevent broken pipe errors
        import sys
        disable_tqdm = not sys.stdout.isatty()

        with tqdm.tqdm(desc=f"Fetching computers from {self.name}", unit="host", disable=disable_tqdm) as pbar:
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
        sensor_readings = node.get('sensorReadings', {})
        custom_tags = self._extract_custom_tags(sensor_readings)
        eid_last_seen = node.get('eidLastSeen')

        os_data = node.get('os', {})
        os_platform = os_data.get('platform', '') if os_data else ''

        return Computer(
            name=node.get('name', ''),
            id=node.get('id', ''),
            ip=node.get('ipAddress'),
            eidLastSeen=eid_last_seen,
            source=self.name,
            os_platform=os_platform,
            eid_status='',  # Not derived - use eidLastSeen to determine status
            custom_tags=custom_tags
        )

    def _extract_custom_tags(self, sensor_readings: Dict) -> List[str]:
        """Extract custom tags from sensor readings"""
        tags = []
        columns = sensor_readings.get('columns', [])
        for column in columns:
            if column.get('name') == 'Custom Tags':
                values = column.get('values', [])
                tags.extend([tag for tag in values if tag != self.NO_TAGS_PLACEHOLDER])
        return tags

    def validate_token(self) -> bool:
        """Validate the API token"""
        try:
            # Log token being used (masked for security)
            masked_token = f"{self.token[:8]}...{self.token[-4:]}" if len(self.token) > 12 else "***"
            logger.info(f"Validating token for {self.name} (URL: {self.server_url}): {masked_token}")
            logger.debug(f"Full token for {self.name}: {self.token}")

            # Get and log our public IP address
            try:
                ip_response = requests.get("https://api.ipify.org?format=json", timeout=5)
                if ip_response.status_code == 200:
                    public_ip = ip_response.json().get('ip', 'Unknown')
                    logger.info(f"Your public IP address: {public_ip}")
                else:
                    logger.warning(f"Could not determine public IP: HTTP {ip_response.status_code}")
            except Exception as ip_error:
                logger.warning(f"Could not determine public IP: {ip_error}")

            # Use persistent session with retry logic
            # Note: verify parameter intentionally omitted to use SSL config defaults
            response = self.session.post(
                f"{self.server_url}/api/v2/session/validate",
                json={'session': self.token},
                timeout=10
            )
            if response.status_code == 200:
                logger.info(f"Token validation successful for {self.name} (URL: {self.server_url})")
                self.last_error = None
                return True
            else:
                self.last_error = f"HTTP {response.status_code} - {response.text.strip()}"
                logger.warning(f"Token validation failed for {self.name} (URL: {self.server_url}): {self.last_error}")
                return False
        except Exception as e:
            self.last_error = str(e)
            logger.warning(f"Token validation failed for {self.name} (URL: {self.server_url}): {self.last_error}")
            return False

    def find_computer_by_name(self, computer_name: str) -> Optional[Computer]:
        """Find a computer by exact name in this instance using GraphQL filter"""
        data = self.query(ENDPOINT_BY_NAME_QUERY, {'name': computer_name})
        edges = data.get('data', {}).get('endpoints', {}).get('edges', [])

        if edges:
            return self.extract_computer_from_node(edges[0]['node'])

        logger.debug(f"No computer found with name '{computer_name}' in {self.name}")
        return None

    def add_tag_by_name(self, computer_name: str, tag: str, package_id: str = None) -> dict:
        """Add a custom tag to a computer by name.

        Args:
            computer_name: Name of the computer
            tag: Tag to add
            package_id: Optional Tanium package ID. If not provided, will be derived from OS platform.
        """
        computer = self.find_computer_by_name(computer_name)
        if not computer:
            raise TaniumAPIError(f"Computer '{computer_name}' not found")

        updated_tags = computer.custom_tags + [tag]

        # Use provided package_id or derive it from OS platform
        if package_id is None:
            device_type = computer.os_platform or "windows"
            package_id = self.get_package_id_for_device_type(device_type)

        variables = self.build_tag_update_variables(computer.id, updated_tags, package_id, action="Add")
        result = self.query(UPDATE_TAGS_MUTATION, variables)

        action_create_result = result.get('data', {}).get('actionCreate', {})
        if error := action_create_result.get('error'):
            # Log the full error object for debugging
            logger.error(f"Full Tanium error response: {error}")
            raise TaniumAPIError(f"GraphQL error: {error.get('message', 'Unknown error')}. Full error: {error}")
        if not action_create_result.get('action'):
            raise TaniumAPIError(f"No action data returned from GraphQL response. Full response: {action_create_result}")

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
            # Log the full error object for debugging
            logger.error(f"Full Tanium error response: {error}")
            raise TaniumAPIError(f"GraphQL error: {error.get('message', 'Unknown error')}. Full error: {error}")
        if not action_create_result.get('action'):
            raise TaniumAPIError(f"No action data returned from GraphQL response. Full response: {action_create_result}")

        return action_create_result

    def bulk_add_tags(self, hosts: List[Dict[str, Any]], tag: str, package_id: str) -> dict:
        """Add a tag to multiple hosts in a single API call.

        Args:
            hosts: List of host dictionaries with keys 'tanium_id' and 'current_tags'
            tag: Tag to add to all hosts
            package_id: Tanium package ID to use

        Returns:
            dict: Action result from GraphQL API with action ID

        Example:
            hosts = [
                {'tanium_id': '123', 'current_tags': ['tag1']},
                {'tanium_id': '456', 'current_tags': ['tag2']}
            ]
            result = instance.bulk_add_tags(hosts, 'EPP_RING_0', '1235')
        """
        if not hosts:
            raise TaniumAPIError("No hosts provided for bulk tagging")

        # Convert tanium_ids to integers and collect all unique endpoint IDs
        endpoint_ids = []
        for host in hosts:
            tanium_id = str(host['tanium_id'])
            endpoint_id = int(tanium_id) if tanium_id.isdigit() else tanium_id
            endpoint_ids.append(endpoint_id)

        # For bulk operations, we need to combine all existing tags from all hosts plus the new tag
        # However, since each host may have different tags, we'll use a simplified approach:
        # We just add the new tag to each host individually via the mutation
        # Note: The mutation expects the FULL tag list for each endpoint
        # For true bulk tagging, we need one tag string that applies to all
        # So we'll just pass the new tag as the parameter

        variables = {
            "name": f"Bulk Add Custom Tag to {len(endpoint_ids)} endpoints",
            "tag": tag,  # Just the new tag to add
            "packageID": package_id,
            "endpoints": endpoint_ids,
            "distributeSeconds": 60,
            "expireSeconds": 3600,
            "startTime": datetime.now(timezone.utc).isoformat()
        }

        logger.info(f"Bulk tagging {len(endpoint_ids)} hosts in {self.name} with tag '{tag}' using package {package_id}")
        result = self.query(UPDATE_TAGS_MUTATION, variables)

        action_create_result = result.get('data', {}).get('actionCreate', {})
        if error := action_create_result.get('error'):
            logger.error(f"Full Tanium error response: {error}")
            raise TaniumAPIError(f"GraphQL error: {error.get('message', 'Unknown error')}. Full error: {error}")
        if not action_create_result.get('action'):
            raise TaniumAPIError(f"No action data returned from GraphQL response. Full response: {action_create_result}")

        return action_create_result

    def iterate_computers(self, limit: Optional[int] = None) -> Iterator[Computer]:
        """Public method to iterate through computers with pagination"""
        return self._paginate_computers(limit)

    # ==================== Detection Rules Catalog Methods ====================

    def list_signals(self) -> Dict[str, Any]:
        """List Threat Response signals (detection rules) from this instance.

        Returns:
            Dict with signals list or error
        """
        signals = []
        cursor = None
        page_size = 100

        try:
            while True:
                variables = {"first": page_size}
                if cursor:
                    variables["after"] = cursor

                result = self.query(SIGNALS_QUERY, variables)
                data = result.get("data", {}).get("threatResponseSignals", {})
                edges = data.get("edges", [])

                for edge in edges:
                    node = edge.get("node", {})
                    if node:
                        signals.append(node)

                page_info = data.get("pageInfo", {})
                if page_info.get("hasNextPage"):
                    cursor = page_info.get("endCursor")
                else:
                    break

            return {"signals": signals, "count": len(signals)}

        except TaniumAPIError as e:
            logger.error(f"Error listing signals from {self.name}: {e}")
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"Unexpected error listing signals from {self.name}: {e}")
            return {"error": str(e)}


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
            # Validate token before adding to ensure instance is accessible
            if cloud_instance.validate_token():
                self.instances.append(cloud_instance)
            else:
                logger.warning(f"⚠️  Cloud instance configured but unreachable - skipping")

        # On-prem instance (disable SSL verification for on-prem)
        if (instance is None or instance.lower() == "onprem") and hasattr(self.config, 'tanium_onprem_api_url') and self.config.tanium_onprem_api_url and self.config.tanium_onprem_api_token:
            onprem_instance = TaniumInstance(
                "On-Prem",
                self.config.tanium_onprem_api_url,
                self.config.tanium_onprem_api_token,
                verify_ssl=False
            )
            # Validate token before adding to ensure instance is accessible
            if onprem_instance.validate_token():
                self.instances.append(onprem_instance)
            else:
                logger.warning(f"⚠️  On-Prem instance configured but unreachable - skipping")

    def validate_all_tokens(self) -> Dict[str, bool]:
        """Validate tokens for all instances"""
        results = {}
        for instance in self.instances:
            results[instance.name] = instance.validate_token()
        return results

    def _get_all_computers(self, limit: Optional[int] = None) -> List[Computer]:
        """Get computers from all instances.

        Raises:
            ConnectionError: If no computers could be retrieved and all instances failed,
                           includes the actual error messages from each failed instance.
        """
        all_computers = []
        instance_errors = {}

        for instance in self.instances:
            if instance.validate_token():
                computers = instance.get_computers(limit)
                all_computers.extend(computers)
            else:
                instance_errors[instance.name] = instance.last_error or "Unknown error"
                logger.warning(f"⚠️  {instance.name} instance configured but unreachable - skipping")
                print(f"⚠️  WARNING: Skipping {instance.name} instance due to connection or authentication issues")

        # If no computers retrieved and we had errors, raise with details
        if not all_computers and instance_errors:
            error_details = "; ".join(f"{name}: {error}" for name, error in instance_errors.items())
            raise ConnectionError(f"No computers retrieved from any instance. {error_details}")

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

    def list_all_signals(self) -> Dict[str, Any]:
        """List Threat Response signals from all available instances.

        Returns:
            Dict with combined signals list or error
        """
        all_signals = []
        errors = []

        for instance in self.instances:
            result = instance.list_signals()
            if "error" in result:
                errors.append(f"{instance.name}: {result['error']}")
            else:
                all_signals.extend(result.get("signals", []))

        if not all_signals and errors:
            return {"error": "; ".join(errors)}

        return {"signals": all_signals, "count": len(all_signals), "errors": errors}


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

        # # Test: Add and Remove tags
        # test_hostname = "VV10-MLKR-029.company.co.kr"
        # test_tag = "TestTag123"
        # instance_name = "On-Prem"  # or "On-Prem"
        # tag_action = 'add'  # Change to 'remove' to test removal
        #
        # instance = client.get_instance_by_name(instance_name)
        # if not instance:
        #     logger.error(f"Instance {instance_name} not found")
        #     return 1
        #
        # # Get computer info first
        # computer = instance.find_computer_by_name(test_hostname)
        # if not computer:
        #     logger.error(f"Computer {test_hostname} not found")
        #     return 1
        #
        # logger.info(f"\n=== Testing tag operations on {test_hostname} in {instance_name} ===")
        # logger.info(f"Computer ID: {computer.id}")
        # logger.info(f"OS Platform: {computer.os_platform}")
        # logger.info(f"Current tags: {computer.custom_tags}")
        #
        # if tag_action == 'add':
        #     logger.info(f"\nTesting ADD tag '{test_tag}'...")
        #     result = instance.add_tag_by_name(test_hostname, test_tag)
        #     action_id = result.get('action', {}).get('scheduledAction', {}).get('id')
        #     logger.info(f"✓ Tag add action created successfully")
        #     logger.info(f"  Action ID: {action_id}")
        #
        # elif tag_action == 'remove':
        #     logger.info(f"\nTesting REMOVE tag '{test_tag}'...")
        #     result = instance.remove_tag_by_name(test_hostname, test_tag)
        #     action_id = result.get('action', {}).get('scheduledAction', {}).get('id')
        #     logger.info(f"✓ Tag remove action created successfully")
        #     logger.info(f"  Action ID: {action_id}")

        # Test searching for computers
        test_computers = [
            {"name": "HOST001.INTERNAL.EXAMPLE.COM", "instance": "Cloud"},
            {"name": "VV10-MLKR-029.company.co.kr", "instance": "On-Prem"},
        ]
        for computer in test_computers:
            search_term = computer["name"]
            instance_name = computer["instance"]
            instance = client.get_instance_by_name(instance_name)
            url_info = f" (URL: {instance.server_url})" if instance else ""
            logger.info(f"\nSearching for computers containing '{search_term}' in {instance_name}{url_info}...")
            matches = client.search_computers(search_term, instance_name, limit=5)

            # Convert Computer objects to dictionaries for JSON serialization
            matches_dict = [
                {
                    'name': comp.name,
                    'id': comp.id,
                    'ip': comp.ip,
                    'eidLastSeen': comp.eidLastSeen,
                    'source': comp.source,
                    'os_platform': comp.os_platform,
                    'eid_status': comp.eid_status,
                    'custom_tags': comp.custom_tags
                }
                for comp in matches
            ]
            print(json.dumps(matches_dict, indent=2))

            for comp in matches:
                logger.info(f" - {comp.name} (ID: {comp.id}, Last Seen: {comp.eidLastSeen}, Tags: {comp.custom_tags})")

    except Exception as e:
        logger.error(f"Error during execution: {e}")


if __name__ == "__main__":
    exit(main())
