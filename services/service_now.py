import base64
import json
import logging
import time
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

import pandas as pd
import requests
from tqdm import tqdm
import concurrent.futures
from filelock import FileLock
import urllib3

from my_config import get_config

# Disable InsecureRequestWarning for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
            logger.info(f"Loading token from {TOKEN_FILE}")
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
        lock_path = str(TOKEN_FILE) + '.lock'
        temp_path = str(TOKEN_FILE) + '.tmp'
        logger.info(f"Saving token to {TOKEN_FILE} (using lock {lock_path})")
        with FileLock(lock_path):
            with open(temp_path, 'w') as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, TOKEN_FILE)
        logger.info(f"Token saved to {TOKEN_FILE}")

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


def _parse_discovery_date(item):
    """Parse discovery date, return epoch if invalid."""
    date_str = item.get('mostRecentDiscovery')
    if not date_str:
        return datetime(1970, 1, 1)

    try:
        return datetime.strptime(date_str, '%m-%d-%Y %I:%M %p')
    except (ValueError, TypeError):
        return datetime(1970, 1, 1)


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
        # Safely handle hostname that might be None or not a string
        if not hostname or not isinstance(hostname, str):
            logger.warning(f"Invalid hostname provided: {hostname}")
            return {"name": str(hostname) if hostname is not None else "unknown", "status": "Invalid Hostname"}

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

        return {"name": hostname, "status": "Not Found"}

    def _search_endpoint(self, endpoint, hostname):
        """Search a specific endpoint for hostname."""
        headers = self.token_manager.get_auth_headers()
        params = {'name': hostname}

        try:
            response = requests.get(endpoint, headers=headers, params=params, timeout=2, verify=False)
            response.raise_for_status()

            data = response.json()
            items = data.get('items', data) if isinstance(data, dict) else data

            if not items:
                return None

            # Return most recently discovered item
            if len(items) > 1:
                items = sorted(items, key=_parse_discovery_date, reverse=True)

            return items[0]
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching details for {hostname}: {str(e)}")
            return {"name": hostname, "error": str(e), "status": "ServiceNow API Error", "category": ""}

    def get_process_changes(self, params=None):
        """Get process changes from ServiceNow custom endpoint."""
        base_url = config.snow_base_url.rstrip('/')
        endpoint = f"{base_url}/api/x_metli_acme_it/process/changes"
        # endpoint = 'https://acmeprod.service-now.com/api/x_metli_acme_it/process/changes'
        headers = self.token_manager.get_auth_headers()
        try:
            response = requests.get(endpoint, headers=headers, params=params, timeout=10, verify=False)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching process changes: {str(e)}")
            return {"error": str(e), "status": "ServiceNow API Error"}


class AsyncServiceNowClient:
    def __init__(self, token_manager=None):
        if token_manager is None:
            token_manager = ServiceNowTokenManager(
                instance_url=config.snow_base_url,
                username=config.snow_functional_account_id,
                password=config.snow_functional_account_password,
                client_id=config.snow_client_key
            )
        self.token_manager = token_manager
        base_url = config.snow_base_url.rstrip('/')
        self.server_url = f"{base_url}/itsm-compute/compute/instances"
        self.workstation_url = f"{base_url}/itsm-compute/compute/computers"

    async def get_host_details(self, session, hostname):
        if not hostname or not isinstance(hostname, str):
            return {"name": str(hostname) if hostname is not None else "unknown", "status": "Invalid Hostname"}
        hostname_short = hostname.split('.')[0]
        # Try servers first
        result = await self._search_endpoint(session, self.server_url, hostname_short)
        if result:
            result['category'] = 'server'
            return result
        # Try workstations
        result = await self._search_endpoint(session, self.workstation_url, hostname_short)
        if result:
            result['category'] = 'workstation'
            return result
        return {"name": hostname_short, "status": "Not Found"}

    async def _search_endpoint(self, session, endpoint, hostname):
        headers = self.token_manager.get_auth_headers()
        params = {'name': hostname}
        try:
            async with session.get(endpoint, headers=headers, params=params, timeout=10, verify_ssl=False) as response:
                if response.status == 429:
                    # Explicitly capture HTTP 429 Too Many Requests
                    return {"name": hostname, "error": "HTTP 429 Too Many Requests", "status": "ServiceNow API Error", "category": ""}
                if response.status != 200:
                    return None
                data = await response.json()
                items = data.get('items', data) if isinstance(data, dict) else data
                if not items:
                    return None
                if len(items) > 1:
                    items = sorted(items, key=_parse_discovery_date, reverse=True)
                return items[0]
        except Exception as e:
            return {"name": hostname, "error": str(e), "status": "ServiceNow API Error", "category": ""}


def enrich_host_report(input_file):
    """Enrich host data with ServiceNow details (synchronous version)."""
    today = datetime.now().strftime('%m-%d-%Y')
    input_name = Path(input_file).name
    output_file = DATA_DIR / today / f"Enriched {input_name}"

    if output_file.exists():
        logger.info(f"Enriched file already exists: {output_file}")
        return output_file

    # Read input data
    logger.info(f"Reading input file: {input_file}")
    df = pd.read_excel(input_file, engine="openpyxl")

    # Detect hostname column
    hostname_col = None
    for col in df.columns:
        if 'hostname' in str(col).lower():
            hostname_col = col
            break

    if not hostname_col:
        logger.error("Could not find hostname column in the input file")
        return input_file

    logger.info(f"Using column '{hostname_col}' for hostnames")

    # Clean the dataframe: remove rows with empty hostnames
    df = df.dropna(subset=[hostname_col])

    # Extract hostnames and filter out any None or empty values
    hostnames = [h for h in df[hostname_col].tolist() if h and isinstance(h, str)]
    logger.info(f"Processing {len(hostnames)} valid hostnames from {input_file}")

    client = ServiceNowClient()
    snow_data = {}
    errors_occurred = False

    def enrich_single_host(hostname):
        details = client.get_host_details(hostname)
        short_hostname = str(hostname).split('.')[0].lower() if hostname and isinstance(hostname, str) else ""
        return short_hostname, details

    max_workers = 30  # Safe parallelism, tune as needed
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(enrich_single_host, hostname): hostname for hostname in hostnames}
        for idx, future in enumerate(tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Enriching hosts with ServiceNow"), 1):
            short_hostname, details = future.result()
            if details:
                snow_data[short_hostname] = details
            if details and 'error' in details:
                errors_occurred = True
            if idx % 100 == 0 or idx == len(futures):
                logger.info(f"Enriched {idx}/{len(futures)} hosts with ServiceNow data...")

    if not snow_data:
        logger.error("No ServiceNow data collected, cannot enrich report")
        return input_file

    # Add ServiceNow data to the original dataframe
    logger.info(f"Retrieved data for {len(snow_data)} hosts from ServiceNow")

    # Create new columns for ServiceNow data
    snow_columns = ['id', 'ciClass', 'environment', 'lifecycleStatus', 'country',
                    'supportedCountry', 'operatingSystem', 'category', 'status', 'error']

    for col in snow_columns:
        df[f'SNOW_{col}'] = ''

    # For each row in the dataframe, add the ServiceNow data
    for idx, row in df.iterrows():
        hostname = row[hostname_col]
        if not isinstance(hostname, str):
            hostname = str(hostname)
        short_hostname = hostname.split('.')[0].lower() if hostname else ""
        if short_hostname in snow_data:
            result = snow_data[short_hostname]
            # If there is an error, always set category to empty string
            if result.get('status') == 'ServiceNow API Error':
                df.at[idx, 'SNOW_category'] = ''
            for col in snow_columns:
                if col in result and not (col == 'category' and result.get('status') == 'ServiceNow API Error'):
                    df.at[idx, f'SNOW_{col}'] = result[col]

    # Save results with adjusted column widths
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with pd.ExcelWriter(output_file, engine="openpyxl") as writer:
        df.to_excel(writer, index=False)

        # Auto-adjust column widths for better readability
        worksheet = writer.sheets['Sheet1']
        for i, column in enumerate(df.columns):
            # Set column width based on content
            max_length = max(
                df[column].astype(str).apply(len).max(),
                len(str(column))
            ) + 2  # add a little extra space

            # Cap the width at a reasonable maximum to prevent overly wide columns
            column_width = min(max_length, 30)

            # Convert to Excel's character width
            worksheet.column_dimensions[worksheet.cell(row=1, column=i + 1).column_letter].width = column_width

    if errors_occurred:
        logger.warning(f"Enriched report saved with some errors to {output_file}")
    else:
        logger.info(f"Successfully enriched report saved to {output_file}")

    return output_file


if __name__ == "__main__":
    client = ServiceNowClient()

    hostname = "axscgpar6301"
    logger.info(f"Looking up in SNOW: {hostname}...")

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
        if 'status' in details:
            print(f"SNOW Status: {details.get('status')}")
        if 'error' in details:
            print(f"SNOW Error: {details.get('error')}")
    else:
        print("Host not found")

    changes = client.get_process_changes()
    print(changes)
