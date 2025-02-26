import base64
import logging
import threading
import time
from datetime import datetime

import requests

from config import get_config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load config from your config module
config = get_config()


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
    def __init__(self, token_manager, base_url):
        """
        ServiceNow Compute API client

        Args:
            token_manager: ServiceNowTokenManager instance
            base_url (str): ServiceNow instance URL
        """
        self.token_manager = token_manager

        # Ensure the base URL doesn't end with a slash
        if base_url.endswith('/'):
            base_url = base_url[:-1]

        self.compute_url = f"{base_url}/itsm-compute/compute/instances"

    def get_host_by_name(self, hostname):
        """
        Get host details by hostname

        Args:
            hostname (str): Name of the host to search for

        Returns:
            dict: Host details if found, None if not found
        """
        return self._make_get_request(self.compute_url, {'name': hostname})

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
            print(response.text)
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
            base_url=base_url
        )

    def get_token(self):
        """
        Get the current access token

        Returns:
            str: The current access token
        """
        return self.token_manager.get_access_token()

    def get_host_details(self, hostname):
        """
        Get host details by hostname

        Args:
            hostname (str, mandatory): Host name to search for


        Returns:
            dict: Host details if found, None if not found
        """
        if hostname:
            return self.compute_api.get_host_by_name(hostname)
        else:
            raise ValueError("Hostname must be provided")

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

    try:
        # Create a client instance
        with ServiceNowClient(config.snow_base_url, config.snow_functional_account_id, config.snow_functional_account_password, config.snow_client_key) as client:
            # Example 1: Get token
            token = client.get_token()
            logger.info(f"Access token: {token[:10]}...")

            # Example 2: Get host by name
            hostname = "C02G7C6VMD6R"
            logger.info(f"Looking up host by name: {hostname}")
            host = client.get_host_details(hostname=hostname)

            if host:
                if isinstance(host, list):
                    logger.info(f"Found {len(host)} hosts matching name: {hostname}")
                    for h in host:
                        logger.info(f"Host: {h['name']}, IP: {h.get('ip_address', 'N/A')}, OS: {h.get('os', 'N/A')}")
                else:
                    logger.info(f"Found host: {host['name']}, IP: {host.get('ip_address', 'N/A')}, OS: {host.get('os', 'N/A')}")
            else:
                logger.info(f"No host found with name: {hostname}")


    except Exception as e:
        logger.error(f"Error: {e}")
