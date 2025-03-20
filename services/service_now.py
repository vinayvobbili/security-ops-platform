import base64
import json
import logging
import os
import time

import requests

from config import get_config

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

config = get_config()

SNOW_ACCESS_TOKEN_FILE = os.path.join(os.path.dirname(__file__), '../data/transient/service_now_access_token.json')


class ServiceNowTokenManager:
    def __init__(self, instance_url, username, password, client_id):
        self.instance_url = instance_url.rstrip('/')
        self.username = username
        self.password = password
        self.client_id = client_id
        self.access_token = None
        self.refresh_token = None
        self.token_expiry = None
        self.load_token_from_file()

    def load_token_from_file(self):
        if os.path.exists(SNOW_ACCESS_TOKEN_FILE):
            with open(SNOW_ACCESS_TOKEN_FILE, 'r') as file:
                token_data = json.load(file)
                self.access_token = token_data.get('access_token')
                self.refresh_token = token_data.get('refresh_token')
                self.token_expiry = token_data.get('token_expiry')
                if not self.token_expiry or time.time() >= self.token_expiry:
                    self.get_initial_token()
        else:
            self.get_initial_token()

    def save_token_to_file(self):
        token_data = {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'token_expiry': self.token_expiry
        }
        with open(SNOW_ACCESS_TOKEN_FILE, 'w') as file:
            json.dump(token_data, file)
        logger.info("Token saved to file")

    def get_initial_token(self):
        token_url = f"{self.instance_url}/authorization/token"
        encoded_credentials = base64.b64encode(f"{self.username}:{self.password}".encode("utf-8")).decode("utf-8")
        headers = {
            'Authorization': f'Basic {encoded_credentials}',
            'Content-Type': 'application/json',
            'X-IBM-Client-Id': self.client_id
        }
        try:
            response = requests.get(token_url, headers=headers, auth=(self.username, self.password))
            response.raise_for_status()
            self._update_token_data(response.json())
            logger.info("Initial token obtained successfully")
            self.save_token_to_file()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error obtaining initial token: {e}")
            if e.response:
                logger.error(f"Response content: {e.response.text}")
            raise

    def refresh_token_request(self):
        if self.refresh_token:
            token_url = f"{self.instance_url}/authorization/token/refresh"
            headers = {'Content-Type': 'application/json', 'X-IBM-Client-Id': self.client_id}
            data = {'refresh_token': self.refresh_token}
            try:
                response = requests.post(token_url, headers=headers, json=data)
                response.raise_for_status()
                self._update_token_data(response.json())
                logger.info("Token refreshed successfully")
                self.save_token_to_file()
                return
            except requests.exceptions.RequestException as e:
                logger.error(f"Error refreshing token: {e}")
                if e.response:
                    logger.error(f"Response content: {e.response.text}")
        self.get_initial_token()

    def _update_token_data(self, token_response):
        self.access_token = token_response.get('access_token')
        self.refresh_token = token_response.get('refresh_token')
        self.token_expiry = time.time() + token_response.get('expires_in', 1800)

    def get_access_token(self):
        if not self.token_expiry or time.time() >= self.token_expiry:
            self.refresh_token_request()
        return self.access_token

    def get_auth_header(self):
        return {'Authorization': f"Bearer {self.get_access_token()}"}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


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

        self.server_compute_url = f"{base_url}/itsm-compute/compute/instances"
        self.workstation_compute_url = f"{base_url}/itsm-compute/compute/computers"

    def get_host_details_by_name(self, hostname):
        """
        Get host details by hostname

        Args:
            hostname (str): Name of the host to search for

        Returns:
            dict: Host details if found, None if not found
        """
        response = self._make_get_request(self.server_compute_url, {'name': hostname})
        # TODO What if SNOW returns multiple results? Use the first one for now
        host_details = response[0] if response else None
        if host_details:
            host_details['category'] = 'server'
            return host_details
        else:
            response = self._make_get_request(self.workstation_compute_url, {'name': hostname})
            # TODO What if SNOW returns multiple results? Use the first one for now
            host_details = response[0] if response else None
            if host_details:
                host_details['category'] = 'workstation'
                return host_details

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

            return response.json()['items']

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
            # if hostname ustry1metv0ae6l.internal.company.com, make hostname = ustry1metv0ae6l
            hostname = hostname.split('.')[0]
            return self.compute_api.get_host_details_by_name(hostname)
        else:
            raise ValueError("Hostname must be provided")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


if __name__ == "__main__":

    try:
        # Create a client instance
        with ServiceNowClient(config.snow_base_url, config.snow_functional_account_id, config.snow_functional_account_password, config.snow_client_key) as client:

            # Example 2: Get host by name
            hostname = "CLAZEMETU0008"
            logger.info(f"Looking up host {hostname} in CMDB...")
            host_details = client.get_host_details(hostname)
            logger.info(f"Host details: {host_details}")

            # print host details as a table
            if host_details:
                for host in host_details:
                    print(f"Host Name: {host['name']}")
                    print(f"Host IP: {host['ipAddress']}")
                    print(f"Host Category: {host['ciClass']}")
                    print(f"Host OS: {host['operatingSystem']}")
                    print(f"Host Country: {host['country']}")
                    print(f"Host Status: {host['state']}")
                    print("-" * 20)
            else:
                print(f"Host {hostname} not found.")

    except Exception as e:
        logger.error(f"Error: {e}")
