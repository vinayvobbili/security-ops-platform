import base64
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
import requests
from tqdm import tqdm

from config import get_config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

config = get_config()
TOKEN_FILE = Path(__file__).parent.parent / "data/transient/service_now_access_token.json"
DATA_DIR = Path(__file__).parent.parent / "data/transient/epp_device_tagging"


class ServiceNowTokenManager:
    def __init__(self, instance_url, username, password, client_id):
        self.instance_url = instance_url.rstrip('/')
        self.username = username
        self.password = password
        self.client_id = client_id
        self.access_token = None
        self.refresh_token = None
        self.token_expiry = None
        self._load_token()

    def _load_token(self):
        if TOKEN_FILE.exists():
            with open(TOKEN_FILE) as f:
                data = json.load(f)
                self.access_token = data.get('access_token')
                self.refresh_token = data.get('refresh_token')
                self.token_expiry = data.get('token_expiry')

        if not self.access_token or (self.token_expiry and time.time() >= self.token_expiry):
            self._get_new_token()

    def _save_token(self):
        TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'token_expiry': self.token_expiry
        }
        with open(TOKEN_FILE, 'w') as f:
            json.dump(data, f, indent=2)

    def _get_new_token(self):
        url = f"{self.instance_url}/authorization/token"
        auth = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        headers = {
            'Authorization': f'Basic {auth}',
            'Content-Type': 'application/json',
            'X-IBM-Client-Id': self.client_id
        }

        response = requests.get(url, headers=headers, auth=(self.username, self.password))
        response.raise_for_status()
        self._update_token(response.json())
        self._save_token()

    def _refresh_token(self):
        if not self.refresh_token:
            self._get_new_token()
            return

        url = f"{self.instance_url}/authorization/token/refresh"
        headers = {'Content-Type': 'application/json', 'X-IBM-Client-Id': self.client_id}
        data = {'refresh_token': self.refresh_token}

        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            self._update_token(response.json())
            self._save_token()
        else:
            self._get_new_token()

    def _update_token(self, token_data):
        self.access_token = token_data.get('access_token')
        self.refresh_token = token_data.get('refresh_token')
        self.token_expiry = time.time() + token_data.get('expires_in', 1800)

    def get_auth_headers(self):
        if not self.token_expiry or time.time() >= self.token_expiry:
            self._refresh_token()

        return {
            'Authorization': f"Bearer {self.access_token}",
            'Accept': 'application/json',
            'X-IBM-Client-Id': self.client_id
        }


class ServiceNowClient:
    def __init__(self):
        self.token_manager = ServiceNowTokenManager(
            instance_url=config.snow_base_url,
            username=config.snow_functional_account_id,
            password=config.snow_functional_account_password,
            client_id=config.snow_client_key
        )
        base_url = config.snow_base_url.rstrip('/')
        self.server_url = f"{base_url}/itsm-compute/compute/instances"
        self.workstation_url = f"{base_url}/itsm-compute/compute/computers"

    def get_host_details(self, hostname):
        """Get host details by hostname, checking servers first then workstations."""
        hostname = hostname.split('.')[0]  # Remove domain

        # Try servers first
        host_details = self._search_endpoint(self.server_url, hostname)
        if host_details:
            host_details['category'] = 'server'
            return host_details

        # Try workstations
        host_details = self._search_endpoint(self.workstation_url, hostname)
        if host_details:
            host_details['category'] = 'workstation'
            return host_details

        return None

    def _search_endpoint(self, endpoint, hostname):
        """Search a specific endpoint for hostname."""
        headers = self.token_manager.get_auth_headers()
        params = {'name': hostname}

        response = requests.get(endpoint, headers=headers, params=params)
        response.raise_for_status()

        data = response.json()
        items = data.get('items', data) if isinstance(data, dict) else data

        if not items:
            return None

        # Return most recently discovered item
        if len(items) > 1:
            items = sorted(items, key=self._parse_discovery_date, reverse=True)

        return items[0]

    def _parse_discovery_date(self, item):
        """Parse discovery date, return epoch if invalid."""
        date_str = item.get('mostRecentDiscovery')
        if not date_str:
            return datetime(1970, 1, 1)

        try:
            return datetime.strptime(date_str, '%m-%d-%Y %I:%M %p')
        except (ValueError, TypeError):
            return datetime(1970, 1, 1)


def enrich_host_report(input_file, chunk_size=1000, max_workers=50):
    """Enrich host data with ServiceNow details."""
    today = datetime.now().strftime('%m-%d-%Y')
    input_name = Path(input_file).name
    output_file = DATA_DIR / today / f"enriched_{input_name}"

    if output_file.exists():
        logger.info(f"Enriched file already exists: {output_file}")
        return output_file

    # Read input data
    df = pd.read_excel(input_file, engine="openpyxl")
    hostnames = df['hostname'].tolist()

    # Get ServiceNow details for all hosts
    client = ServiceNowClient()
    all_details = []

    for i in range(0, len(hostnames), chunk_size):
        chunk = hostnames[i:i + chunk_size]

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_hostname = {
                executor.submit(client.get_host_details, hostname): hostname
                for hostname in chunk
            }

            for future in tqdm(as_completed(future_to_hostname),
                               total=len(chunk),
                               desc=f"Processing chunk {i // chunk_size + 1}"):
                hostname = future_to_hostname[future]
                result = future.result()
                all_details.append(result or {"name": hostname.split('.')[0]})

    # Merge data
    details_df = pd.json_normalize(all_details)
    df['hostname_short'] = df['hostname'].str.split('.').str[0]

    merged_df = pd.merge(
        df, details_df,
        left_on=df['hostname_short'].str.lower(),
        right_on=details_df['name'].str.lower(),
        how='left'
    ).drop('hostname_short', axis=1)

    # Save results
    output_file.parent.mkdir(parents=True, exist_ok=True)
    merged_df.to_excel(output_file, index=False, engine="openpyxl")

    logger.info(f"Enriched {len(all_details)} hosts, saved to {output_file}")
    return output_file


if __name__ == "__main__":
    client = ServiceNowClient()

    hostname = "vm11923e1dv0004"
    logger.info(f"Looking up {hostname}...")

    details = client.get_host_details(hostname)
    if details:
        print(f"Name: {details.get('name')}")
        print(f"IP: {details.get('ipAddress')}")
        print(f"Category: {details.get('category')}")
        print(f"OS: {details.get('operatingSystem')}")
        print(f"Country: {details.get('country')}")
        print(f"Status: {details.get('state')}")
        print(f"Domain: {details.get('osDomain')}")
        print(f"Environment: {details.get('environment')}")
    else:
        print("Host not found")
