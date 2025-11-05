import base64
import concurrent.futures
import json
import logging
import os
import threading
import time
from datetime import datetime
from pathlib import Path

import pandas as pd
import requests
import urllib3
from filelock import FileLock
from requests.adapters import HTTPAdapter
from tqdm import tqdm

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
        self._refresh_lock = threading.Lock()  # Thread-safe token refresh
        self._load_token()

    def _load_token(self):
        if TOKEN_FILE.exists():
            logger.info(f"Loading cached token from {TOKEN_FILE}")
            with open(TOKEN_FILE) as f:
                data = json.load(f)
                self.access_token = data.get('access_token')
                self.refresh_token = data.get('refresh_token')
                self.token_expiry = data.get('token_expiry')

            # Check if loaded token is still valid
            if self.token_expiry:
                time_remaining = self.token_expiry - time.time()
                if time_remaining > 0:
                    logger.info(f"✓ Loaded valid cached token, expires in {time_remaining / 60:.1f} minutes")
                else:
                    logger.info(f"⚠ Cached token expired {-time_remaining / 60:.1f} minutes ago, fetching new token")

        if not self.access_token or (self.token_expiry and time.time() >= self.token_expiry):
            logger.info("No valid cached token available, requesting new token")
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

        logger.info(f"Requesting new ServiceNow token from {url}")
        response = requests.get(url, headers=headers, auth=(self.username, self.password))
        response.raise_for_status()
        logger.info("✓ Successfully obtained new ServiceNow token")
        self._update_token(response.json())
        self._save_token()

    def _refresh_token(self):
        if not self.refresh_token:
            logger.info("No refresh token available, requesting new token")
            self._get_new_token()
            return

        url = f"{self.instance_url}/authorization/token/refresh"
        headers = {'Content-Type': 'application/json', 'X-IBM-Client-Id': self.client_id}
        data = {'refresh_token': self.refresh_token}

        logger.info("Attempting to refresh ServiceNow token")
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            logger.info("✓ Successfully refreshed ServiceNow token")
            self._update_token(response.json())
            self._save_token()
        else:
            logger.warning(f"Token refresh failed with status {response.status_code}, requesting new token")
            self._get_new_token()

    def _update_token(self, token_data):
        self.access_token = token_data.get('access_token')
        self.refresh_token = token_data.get('refresh_token')

        if 'expires_in' not in token_data:
            logger.warning("⚠ API response missing 'expires_in', using default 59 minutes")

        expires_in = token_data.get('expires_in', 3540)  # 59 minutes default (ServiceNow tokens valid for 60 min)
        self.token_expiry = time.time() + expires_in
        logger.info(f"✓ Token updated, expires in {expires_in}s ({expires_in / 60:.1f} minutes)")

    def get_auth_headers(self):
        # Check if token needs refresh (refresh 2 min before expiry to avoid mid-batch expiration)
        if not self.token_expiry or time.time() >= self.token_expiry - 120:
            # Use lock to ensure only one thread refreshes at a time
            with self._refresh_lock:
                # Double-check after acquiring lock (another thread may have refreshed)
                if not self.token_expiry or time.time() >= self.token_expiry - 120:
                    logger.info("Token expired or expiring soon, refreshing...")
                    self._refresh_token()
                else:
                    logger.debug("Token already refreshed by another thread, skipping")

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
    def __init__(self, requests_per_second=10):
        logger.debug("Initializing ServiceNowClient")
        self.token_manager = ServiceNowTokenManager(
            instance_url=config.snow_base_url,
            username=config.snow_functional_account_id,
            password=config.snow_functional_account_password,
            client_id=config.snow_client_key
        )
        base_url = config.snow_base_url.rstrip('/')
        self.server_url = f"{base_url}/itsm-compute/compute/instances"
        self.workstation_url = f"{base_url}/itsm-compute/compute/computers"

        # Create persistent session with connection pooling
        logger.info("Creating HTTP session with connection pooling (pool_size=60, max_retries=3)")
        self.session = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=60,
            pool_maxsize=60,
            max_retries=3,
            pool_block=False
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        # Rate limiting
        self.requests_per_second = requests_per_second
        self.min_request_interval = 1.0 / requests_per_second
        self.last_request_time = 0
        self.rate_limit_lock = threading.Lock()
        logger.info(f"Rate limiting enabled: {requests_per_second} requests/second (min {self.min_request_interval * 1000:.0f}ms between requests)")
        logger.debug("ServiceNowClient initialized successfully")

    def _wait_for_rate_limit(self):
        """Enforce rate limiting by waiting if necessary."""
        with self.rate_limit_lock:
            current_time = time.time()
            time_since_last_request = current_time - self.last_request_time
            if time_since_last_request < self.min_request_interval:
                sleep_time = self.min_request_interval - time_since_last_request
                time.sleep(sleep_time)
            self.last_request_time = time.time()

    def get_host_details(self, hostname):
        """Get host details by hostname, checking servers first then workstations."""
        # Safely handle hostname that might be None or not a string
        if not hostname or not isinstance(hostname, str):
            logger.warning(f"Invalid hostname provided: {hostname}")
            return {"name": str(hostname) if hostname is not None else "unknown", "status": "Invalid Hostname"}

        hostname = hostname.split('.')[0]  # Remove domain

        # Try workstations
        host_details = self._search_endpoint(self.workstation_url, hostname)
        if host_details:
            host_details['category'] = 'workstation'
            return host_details

        # Try servers first
        host_details = self._search_endpoint(self.server_url, hostname)
        if host_details:
            host_details['category'] = 'server'
            return host_details

        return {"name": hostname, "status": "Not Found"}

    def _search_endpoint(self, endpoint, hostname, max_retries=3):
        """Search a specific endpoint for hostname with retry logic for rate limiting."""
        params = {'name': hostname}

        for attempt in range(max_retries):
            try:
                # Enforce rate limiting before making request
                self._wait_for_rate_limit()

                headers = self.token_manager.get_auth_headers()
                logger.debug(f"Querying {endpoint} for hostname: {hostname} (attempt {attempt + 1}/{max_retries})")
                start_time = time.time()
                response = self.session.get(endpoint, headers=headers, params=params, timeout=10, verify=False)
                elapsed_ms = (time.time() - start_time) * 1000
                logger.debug(f"ServiceNow API response for {hostname}: {response.status_code} in {elapsed_ms:.0f}ms")

                # Handle rate limiting with exponential backoff
                if response.status_code == 429:
                    if attempt < max_retries - 1:
                        # Exponential backoff: 2s, 4s, 8s
                        wait_time = 2 ** (attempt + 1)
                        logger.warning(f"Rate limited (429) for {hostname}, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})")
                        time.sleep(wait_time)
                        continue
                    else:
                        logger.error(f"Rate limited (429) for {hostname} after {max_retries} attempts")
                        return {"name": hostname, "error": "HTTP 429 Too Many Requests", "status": "ServiceNow API Error", "category": ""}

                response.raise_for_status()

                # Check if response has content before trying to parse JSON
                if not response.text or response.text.strip() == '':
                    logger.debug(f"Empty response body for {hostname}, treating as 'not found'")
                    return None

                # Try to parse JSON with better error handling
                try:
                    data = response.json()
                except ValueError as json_error:
                    logger.debug(f"Invalid JSON in response for {hostname}: {json_error}. Response body: {response.text[:200]}")
                    return None

                items = data.get('items', data) if isinstance(data, dict) else data

                if not items:
                    logger.debug(f"No items found for {hostname}")
                    return None

                # Return most recently discovered item
                if len(items) > 1:
                    logger.debug(f"Multiple items found for {hostname}, selecting most recent")
                    items = sorted(items, key=_parse_discovery_date, reverse=True)

                logger.debug(f"Successfully retrieved details for {hostname}")
                return items[0]

            except requests.exceptions.RequestException as e:
                # For network errors, retry with exponential backoff
                if attempt < max_retries - 1 and any(err in str(e).lower() for err in ['timeout', 'connection', 'network']):
                    wait_time = 2 ** (attempt + 1)
                    logger.warning(f"Network error for {hostname}: {e}, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error(f"Error fetching details for {hostname}: {str(e)}")
                    return {"name": hostname, "error": str(e), "status": "ServiceNow API Error", "category": ""}

        # Should not reach here, but handle gracefully
        return {"name": hostname, "error": "Max retries exceeded", "status": "ServiceNow API Error", "category": ""}

    def get_process_changes(self, params=None):
        """Get process changes from ServiceNow custom endpoint."""
        base_url = config.snow_base_url.rstrip('/')
        endpoint = f"{base_url}/api/x_metli_metlife_it/process/changes"
        # endpoint = 'https://metlifeprod.service-now.com/api/x_metli_metlife_it/process/changes'
        headers = self.token_manager.get_auth_headers()
        try:
            response = self.session.get(endpoint, headers=headers, params=params, timeout=10, verify=False)
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

    logger.info(f"Starting new enrichment process for {input_file}")
    logger.debug(f"Output will be saved to: {output_file}")

    # Read input data
    logger.info(f"Reading input file: {input_file}")
    df = pd.read_excel(input_file, engine="openpyxl")
    logger.debug(f"Loaded {len(df)} rows, {len(df.columns)} columns from Excel")

    # Detect hostname column
    hostname_col = None
    for col in df.columns:
        if 'hostname' in str(col).lower():
            hostname_col = col
            break

    if not hostname_col:
        logger.error("Could not find hostname column in the input file")
        logger.debug(f"Available columns: {list(df.columns)}")
        return input_file

    logger.info(f"Using column '{hostname_col}' for hostnames")

    # Clean the dataframe: remove rows with empty hostnames
    original_count = len(df)
    df = df.dropna(subset=[hostname_col])
    if original_count != len(df):
        logger.debug(f"Removed {original_count - len(df)} rows with empty hostnames")

    # Extract hostnames and filter out any None or empty values
    hostnames = [h for h in df[hostname_col].tolist() if h and isinstance(h, str)]
    logger.info(f"Processing {len(hostnames)} valid hostnames from {input_file}")

    # Create client with rate limiting (10 requests/second to avoid HTTP 429)
    # NOTE: To improve throughput, try increasing to 20-50 req/s and monitor for HTTP 429 errors in logs
    # Suggested progression: 20 → 30 → 50 req/s (code handles retries automatically)
    client = ServiceNowClient(requests_per_second=20)
    snow_data = {}
    errors_occurred = False
    error_count = 0
    success_count = 0

    def enrich_single_host(hostname):
        details = client.get_host_details(hostname)
        short_hostname = str(hostname).split('.')[0].lower() if hostname and isinstance(hostname, str) else ""
        return short_hostname, details

    max_workers = 50  # Balanced parallelism with rate limiting to avoid ServiceNow API rate limiting (HTTP 429)
    logger.info(f"Starting parallel enrichment with {max_workers} workers for {len(hostnames)} hosts")

    start_time = time.time()
    last_log_time = start_time

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(enrich_single_host, hostname): hostname for hostname in hostnames}
        logger.info(f"Submitted {len(futures)} tasks to thread pool")

        for idx, future in enumerate(tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Enriching hosts with ServiceNow"), 1):
            short_hostname, details = future.result()
            if details:
                snow_data[short_hostname] = details
                if 'error' in details:
                    errors_occurred = True
                    error_count += 1
                else:
                    success_count += 1

            # Log throughput every 100 hosts
            if idx % 100 == 0 or idx == len(futures):
                elapsed = time.time() - start_time
                throughput = idx / elapsed if elapsed > 0 else 0
                recent_elapsed = time.time() - last_log_time
                recent_throughput = 100 / recent_elapsed if recent_elapsed > 0 and idx % 100 == 0 else throughput
                logger.info(f"Progress: {idx}/{len(futures)} hosts | Overall: {throughput:.1f} hosts/s | Recent: {recent_throughput:.1f} hosts/s | Success: {success_count} | Errors: {error_count}")
                last_log_time = time.time()

    total_elapsed = time.time() - start_time
    avg_throughput = len(hostnames) / total_elapsed if total_elapsed > 0 else 0
    logger.info(f"Enrichment complete: {len(hostnames)} hosts in {total_elapsed:.1f}s ({avg_throughput:.1f} hosts/s) | Success: {success_count} | Errors: {error_count}")

    if not snow_data:
        logger.error("No ServiceNow data collected, cannot enrich report")
        return input_file

    # Add ServiceNow data to the original dataframe
    logger.info(f"Retrieved data for {len(snow_data)} hosts from ServiceNow")
    logger.info("Merging ServiceNow data into dataframe...")

    # Create new columns for ServiceNow data
    snow_columns = ['id', 'ciClass', 'environment', 'lifecycleStatus', 'country',
                    'supportedCountry', 'operatingSystem', 'category', 'status', 'error']

    for col in snow_columns:
        df[f'SNOW_{col}'] = ''

    # For each row in the dataframe, add the ServiceNow data
    logger.debug(f"Processing {len(df)} rows to add ServiceNow enrichment")
    merge_start = time.time()
    for idx, row in df.iterrows():
        hostname = row[hostname_col]
        if not isinstance(hostname, str):
            hostname = str(hostname)
        short_hostname = hostname.split('.')[0].lower() if hostname else ""
        if short_hostname in snow_data:
            result = snow_data[short_hostname]
            # If there is an error, always set category to empty string
            if result.get('status') == 'ServiceNow API Error':
                df.loc[idx, 'SNOW_category'] = ''  # type: ignore[call-overload]
            for col in snow_columns:
                if col in result and not (col == 'category' and result.get('status') == 'ServiceNow API Error'):
                    df.loc[idx, f'SNOW_{col}'] = result[col]  # type: ignore[call-overload]

    merge_elapsed = time.time() - merge_start
    logger.info(f"Merged ServiceNow data into dataframe in {merge_elapsed:.1f}s")

    # Save results with adjusted column widths
    logger.info("Saving enriched data to Excel file...")
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Save Excel file
    df.to_excel(output_file, index=False, engine="openpyxl")
    logger.debug(f"Excel file written to {output_file}")

    # Apply professional formatting
    logger.debug("Applying professional formatting to Excel file")
    from src.utils.excel_formatting import apply_professional_formatting
    apply_professional_formatting(output_file)

    if errors_occurred:
        logger.warning(f"⚠ Enriched report saved with {error_count} errors to {output_file}")
    else:
        logger.info(f"✓ Successfully enriched report saved to {output_file}")

    return output_file


if __name__ == "__main__":
    client = ServiceNowClient()

    hostname = "USHZK3C64.internal.company.com"
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

    # changes = client.get_process_changes()
    # print(changes)
