import base64
import logging
import threading
import time
from datetime import datetime

import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ServiceNowTokenManager:
    def __init__(self, instance_url, username, password, client_id, refresh_interval=3540):
        """
        Manage ServiceNow OAuth tokens with automatic refresh using custom authentication

        Args:
            instance_url (str): ServiceNow instance URL
            username (str): ServiceNow functional account username
            password (str): ServiceNow functional account password
            client_id (str): Client ID for authentication
            refresh_interval (int): Seconds between token refreshes (default: 3540 - 59 minutes)
        """
        # Ensure the instance URL doesn't end with a slash
        if instance_url.endswith('/'):
            instance_url = instance_url[:-1]

        self.instance_url = instance_url
        self.username = username
        self.password = password
        self.client_id = client_id
        self.refresh_interval = refresh_interval

        # Token storage
        self.access_token = None
        self.refresh_token = None
        self.token_expiry = None
        self.token_lock = threading.Lock()

        # Thread for token refresh
        self.refresh_thread = None
        self.stop_refresh = threading.Event()

        # Get initial token
        self.get_initial_token()

    def get_initial_token(self):
        """Get the initial token using custom authentication method"""
        token_url = f"{self.instance_url}/authorization/token"

        credentials = f"{self.username}:{self.password}"
        encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")

        headers = {
            'Authorization': f'Basic {encoded_credentials}',
            'Content-Type': 'application/json',
            'X-IBM-Client-Id': self.client_id
        }

        try:
            response = requests.get(token_url, headers=headers, auth=(self.username, self.password))
            response.raise_for_status()

            token_data = response.json()
            # Store token data
            self._update_token_data({
                'access_token': token_data['access_token'],
                'refresh_token': token_data.get('refresh_token'),
                'expires_in': token_data.get('expires_in', 3600)
            })

            logger.info("Initial token obtained successfully")

            # Start the refresh thread if refresh_token is available
            if self.refresh_token:
                self.start_refresh_thread()
            else:
                logger.info("No refresh token provided - will re-authenticate when token expires")
                self.start_refresh_thread()  # Will use credentials to get new token

        except requests.exceptions.RequestException as e:
            logger.error(f"Error obtaining initial token: {e}")
            if hasattr(e, 'response') and e.response:
                logger.error(f"Response content: {e.response.text}")
            raise

    def refresh_token_request(self):
        """
        Refresh the token or get a new one if refresh token isn't available
        """
        if self.refresh_token:
            # If we have a refresh token, use it
            try:
                # Your refresh token endpoint and method might differ
                # This is a placeholder - adjust according to your ServiceNow implementation
                token_url = f"{self.instance_url}/authorization/token/refresh"

                headers = {
                    'Content-Type': 'application/json',
                    'X-IBM-Client-Id': self.client_id
                }

                data = {
                    'refresh_token': self.refresh_token
                }

                response = requests.post(token_url, headers=headers, json=data)
                response.raise_for_status()

                token_data = response.json()
                self._update_token_data({
                    'access_token': token_data['access_token'],
                    'refresh_token': token_data.get('refresh_token', self.refresh_token),
                    'expires_in': token_data.get('expires_in', 3600)
                })

                logger.info("Token refreshed successfully")
                return

            except requests.exceptions.RequestException as e:
                logger.error(f"Error refreshing token: {e}")
                if hasattr(e, 'response') and e.response:
                    logger.error(f"Response content: {e.response.text}")

                logger.info("Falling back to getting new token with credentials")

        # If we don't have a refresh token or refresh failed, get a new token
        self.get_initial_token()

    def _update_token_data(self, token_response):
        """Update token data with thread safety"""
        with self.token_lock:
            self.access_token = token_response.get('access_token')
            self.refresh_token = token_response.get('refresh_token')

            # Calculate expiry time
            expires_in = token_response.get('expires_in', 1800)  # Default to 30 minutes if not provided
            self.token_expiry = time.time() + expires_in

    def get_access_token(self):
        """Get the current access token with thread safety"""
        with self.token_lock:
            return self.access_token

    def start_refresh_thread(self):
        """Start the token refresh thread"""
        if self.refresh_thread and self.refresh_thread.is_alive():
            return

        self.stop_refresh.clear()
        self.refresh_thread = threading.Thread(target=self._refresh_loop)
        self.refresh_thread.daemon = True
        self.refresh_thread.start()
        logger.info("Token refresh thread started")

    def _refresh_loop(self):
        """Background thread to refresh the token periodically"""
        while not self.stop_refresh.is_set():
            # Sleep for the refresh interval
            self.stop_refresh.wait(self.refresh_interval)

            if not self.stop_refresh.is_set():
                logger.info(f"Scheduled token refresh at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                self.refresh_token_request()

    def stop(self):
        """Stop the token refresh thread"""
        self.stop_refresh.set()
        if self.refresh_thread:
            self.refresh_thread.join(timeout=1.0)
        logger.info("Token refresh thread stopped")

    def get_auth_header(self):
        """Get Authorization header for API requests"""
        return {'Authorization': f"Bearer {self.get_access_token()}"}

    def __enter__(self):
        """Support for 'with' statement"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Cleanup when exiting 'with' block"""
        self.stop()


class ServiceNowComputeAPI:
    def __init__(self, token_manager, instance_url):
        """
        ServiceNow Compute API client

        Args:
            token_manager: ServiceNowTokenManager instance
            instance_url (str): ServiceNow instance URL
        """
        self.token_manager = token_manager

        # Ensure the instance URL doesn't end with a slash
        if instance_url.endswith('/'):
            instance_url = instance_url[:-1]

        self.instance_url = instance_url
        self.api_base = f"{instance_url}/api/now"
        self.cmdb_base = f"{self.api_base}/cmdb"
        self.compute_base = f"{self.api_base}/table/cmdb_ci_computer"

    def get_host_by_name(self, hostname):
        """
        Get host details by hostname

        Args:
            hostname (str): Name of the host to search for

        Returns:
            dict: Host details if found, None if not found
        """
        query_params = {
            'sysparm_query': f'name={hostname}',
            'sysparm_display_value': 'true',
            'sysparm_exclude_reference_link': 'true',
            'sysparm_fields': 'name,sys_id,ip_address,os,os_version,ram,disk_space,cpu_count,cpu_core_count,cpu_type,location,assigned_to,company,manufacturer,model_number,serial_number,asset_tag,install_date,last_discovered,sys_updated_on,operational_status,status,u_environment'
        }

        return self._make_get_request(self.compute_base, query_params)

    def get_host_by_ip(self, ip_address):
        """
        Get host details by IP address

        Args:
            ip_address (str): IP address of the host to search for

        Returns:
            dict: Host details if found, None if not found
        """
        query_params = {
            'sysparm_query': f'ip_address={ip_address}',
            'sysparm_display_value': 'true',
            'sysparm_exclude_reference_link': 'true',
            'sysparm_fields': 'name,sys_id,ip_address,os,os_version,ram,disk_space,cpu_count,cpu_core_count,cpu_type,location,assigned_to,company,manufacturer,model_number,serial_number,asset_tag,install_date,last_discovered,sys_updated_on,operational_status,status,u_environment'
        }

        return self._make_get_request(self.compute_base, query_params)

    def get_host_by_sys_id(self, sys_id):
        """
        Get host details by sys_id

        Args:
            sys_id (str): ServiceNow sys_id of the host

        Returns:
            dict: Host details if found, None if not found
        """
        endpoint = f"{self.compute_base}/{sys_id}"
        query_params = {
            'sysparm_display_value': 'true',
            'sysparm_exclude_reference_link': 'true'
        }

        return self._make_get_request(endpoint, query_params)

    def get_host_relationships(self, sys_id):
        """
        Get relationships for a host by sys_id

        Args:
            sys_id (str): ServiceNow sys_id of the host

        Returns:
            dict: Relationship details
        """
        endpoint = f"{self.cmdb_base}/relationship/{sys_id}"
        query_params = {
            'sysparm_display_value': 'true',
            'sysparm_exclude_reference_link': 'true'
        }

        return self._make_get_request(endpoint, query_params)

    def search_hosts(self, query_string, limit=100):
        """
        Search for hosts with a custom query string

        Args:
            query_string (str): ServiceNow encoded query string
            limit (int): Maximum number of results to return

        Returns:
            list: List of host records matching the query
        """
        query_params = {
            'sysparm_query': query_string,
            'sysparm_limit': limit,
            'sysparm_display_value': 'true',
            'sysparm_exclude_reference_link': 'true',
            'sysparm_fields': 'name,sys_id,ip_address,os,os_version,ram,disk_space,operational_status,status,u_environment'
        }

        return self._make_get_request(self.compute_base, query_params)

    def get_hosts_by_os(self, os_name, limit=100):
        """
        Get hosts by operating system

        Args:
            os_name (str): Operating system name (e.g., 'Linux', 'Windows')
            limit (int): Maximum number of results to return

        Returns:
            list: List of host records with the specified OS
        """
        query_string = f'os.nameSTARTSWITH{os_name}'
        return self.search_hosts(query_string, limit)

    def get_hosts_by_status(self, status, limit=100):
        """
        Get hosts by operational status

        Args:
            status (str): Status to filter by (e.g., 'Operational', 'Non-operational')
            limit (int): Maximum number of results to return

        Returns:
            list: List of host records with the specified status
        """
        query_string = f'operational_status={status}'
        return self.search_hosts(query_string, limit)

    def get_hosts_by_environment(self, environment, limit=100):
        """
        Get hosts by environment

        Args:
            environment (str): Environment to filter by (e.g., 'Production', 'Development')
            limit (int): Maximum number of results to return

        Returns:
            list: List of host records in the specified environment
        """
        query_string = f'u_environment={environment}'
        return self.search_hosts(query_string, limit)

    def _make_get_request(self, endpoint, params=None):
        """
        Make a GET request to the ServiceNow API

        Args:
            endpoint (str): API endpoint
            params (dict): Query parameters

        Returns:
            dict or list: API response data
        """
        headers = self.token_manager.get_auth_header()
        headers['Accept'] = 'application/json'
        headers['X-IBM-Client-Id'] = self.token_manager.client_id  # Add the client ID header

        try:
            response = requests.get(endpoint, headers=headers, params=params)
            response.raise_for_status()

            data = response.json()

            # Handle different response formats
            if 'result' in data:
                if isinstance(data['result'], list):
                    return data['result']
                else:
                    return data['result']

            return data

        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            if hasattr(e, 'response') and e.response:
                logger.error(f"Response status: {e.response.status_code}")
                logger.error(f"Response content: {e.response.text}")
            return None


class ServiceNowClient:
    def __init__(self, base_url, user_name, password, client_id):
        """
        Initialize the ServiceNow client

        Args:
            base_url (str): ServiceNow base URL
            user_name (str): ServiceNow functional account username
            password (str): ServiceNow functional account password
            client_id (str): ServiceNow client ID
        """
        self.token_manager = ServiceNowTokenManager(
            instance_url=base_url,
            username=user_name,
            password=password,
            client_id=client_id
        )

        self.compute_api = ServiceNowComputeAPI(
            token_manager=self.token_manager,
            instance_url=base_url
        )

    def get_token(self):
        """
        Get the current access token

        Returns:
            str: The current access token
        """
        return self.token_manager.get_access_token()

    def get_host_details(self, hostname=None, ip_address=None, sys_id=None):
        """
        Get host details by hostname, IP address, or sys_id

        Args:
            hostname (str, optional): Host name to search for
            ip_address (str, optional): IP address to search for
            sys_id (str, optional): ServiceNow sys_id to search for

        Returns:
            dict: Host details if found, None if not found
        """
        if hostname:
            return self.compute_api.get_host_by_name(hostname)
        elif ip_address:
            return self.compute_api.get_host_by_ip(ip_address)
        elif sys_id:
            return self.compute_api.get_host_by_sys_id(sys_id)
        else:
            raise ValueError("One of hostname, ip_address, or sys_id must be provided")

    def search_hosts(self, query_string, limit=100):
        """
        Search for hosts with a custom query

        Args:
            query_string (str): ServiceNow encoded query string
            limit (int): Maximum number of results to return

        Returns:
            list: List of host records matching the query
        """
        return self.compute_api.search_hosts(query_string, limit)

    def get_hosts_by_os(self, os_name, limit=100):
        """
        Get hosts by operating system

        Args:
            os_name (str): Operating system name (e.g., 'Linux', 'Windows')
            limit (int): Maximum number of results to return

        Returns:
            list: List of host records with the specified OS
        """
        return self.compute_api.get_hosts_by_os(os_name, limit)

    def get_hosts_by_environment(self, environment, limit=100):
        """
        Get hosts by environment

        Args:
            environment (str): Environment to filter by (e.g., 'Production', 'Development')
            limit (int): Maximum number of results to return

        Returns:
            list: List of host records in the specified environment
        """
        return self.compute_api.get_hosts_by_environment(environment, limit)

    def get_host_relationships(self, sys_id):
        """
        Get relationships for a host by sys_id

        Args:
            sys_id (str): ServiceNow sys_id of the host

        Returns:
            dict: Relationship details
        """
        return self.compute_api.get_host_relationships(sys_id)

    def cleanup(self):
        """
        Clean up resources (stop token refresh thread)
        """
        self.token_manager.stop()

    def __enter__(self):
        """Support for 'with' statement"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Cleanup when exiting 'with' block"""
        self.cleanup()


# Example usage
if __name__ == "__main__":
    # Load config from your config module
    try:
        from config import get_config

        config = get_config()

        snow_base_url = config.snow_base_url
        client_id = config.snow_client_key
        user_name = config.snow_functional_account_id
        password = config.snow_functional_account_password
    except ImportError:
        # If config module is not available, use placeholder values
        snow_base_url = "https://your-instance.service-now.com"
        client_id = "your-client-id"
        user_name = "your-username"
        password = "your-password"

    try:
        # Create a client instance
        with ServiceNowClient(snow_base_url, user_name, password, client_id) as client:
            # Example 1: Get token
            token = client.get_token()
            logger.info(f"Access token: {token[:10]}...")

            # Example 2: Get host by name
            hostname = "webserver01"
            logger.info(f"Looking up host by name: {hostname}")
            host = client.get_host_details(hostname=hostname)

            if host:
                if isinstance(host, list):
                    logger.info(f"Found {len(host)} hosts matching name: {hostname}")
                    for h in host:
                        logger.info(f"Host: {h['name']}, IP: {h.get('ip_address', 'N/A')}, OS: {h.get('os', 'N/A')}")
                else:
                    logger.info(f"Found host: {host['name']}, IP: {host.get('ip_address', 'N/A')}, OS: {host.get('os', 'N/A')}")

                    # Get relationships if host was found
                    if 'sys_id' in host:
                        logger.info(f"Getting relationships for host: {host['name']}")
                        relationships = client.get_host_relationships(host['sys_id'])
                        if relationships:
                            logger.info(f"Found {len(relationships)} relationships")
                            for rel in relationships[:3]:  # Show first 3 relationships
                                logger.info(f"Relationship: {rel.get('type', {}).get('display_value', 'N/A')}")
            else:
                logger.info(f"No host found with name: {hostname}")

            # Example 3: Get Linux hosts
            logger.info("Looking up Linux hosts")
            linux_hosts = client.get_hosts_by_os("Linux", limit=5)
            logger.info(f"Found {len(linux_hosts)} Linux hosts (limited to 5)")

            # Example 4: Get hosts by environment
            env = "Production"
            logger.info(f"Looking up hosts in {env} environment")
            prod_hosts = client.get_hosts_by_environment(env, limit=5)
            logger.info(f"Found {len(prod_hosts)} hosts in {env} environment (limited to 5)")

    except Exception as e:
        logger.error(f"Error: {e}")
