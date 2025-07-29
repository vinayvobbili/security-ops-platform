import base64
import json
import logging
import logging.config
import time
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from functools import wraps

import pandas as pd
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from tqdm import tqdm
import concurrent.futures
from filelock import FileLock
import urllib3

from config import get_config

# Disable InsecureRequestWarning for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup enhanced logging
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'detailed': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        },
        'simple': {
            'format': '%(levelname)s - %(message)s'
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'INFO',
            'formatter': 'simple'
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'DEBUG',
            'formatter': 'detailed',
            'filename': 'servicenow_client.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 5,
            'encoding': 'utf-8'
        }
    },
    'loggers': {
        '': {  # root logger
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': False
        }
    }
}

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger(__name__)

config = get_config()
TOKEN_FILE = Path(__file__).parent.parent / "data/transient/service_now_access_token.json"
DATA_DIR = Path(__file__).parent.parent / "data/transient/epp_device_tagging"


def rate_limit(calls_per_second=5):
    """Rate limiting decorator to prevent API throttling."""
    min_interval = 1.0 / calls_per_second
    last_called = [0.0]
    lock = threading.Lock()

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            with lock:
                elapsed = time.time() - last_called[0]
                left_to_wait = min_interval - elapsed
                if left_to_wait > 0:
                    time.sleep(left_to_wait)
                ret = func(*args, **kwargs)
                last_called[0] = time.time()
                return ret

        return wrapper

    return decorator


def validate_config():
    """Validate that all required configuration is present."""
    required_fields = ['snow_base_url', 'snow_functional_account_id', 'snow_functional_account_password', 'snow_client_key']
    missing = []

    for field in required_fields:
        if not hasattr(config, field) or not getattr(config, field):
            missing.append(field)

    if missing:
        raise ValueError(f"Missing required configuration: {', '.join(missing)}")

    logger.info("ServiceNow configuration validation passed")


class ServiceNowTokenManager:
    def __init__(self, instance_url, username, password, client_id):
        self.instance_url = instance_url.rstrip('/')
        self.username = username
        self.password = password
        self.client_id = client_id
        self.access_token = None
        self.refresh_token = None
        self.token_expiry = None
        self._lock = threading.Lock()
        self._load_token()

    def _load_token(self):
        """Load token from file if it exists and is valid."""
        if TOKEN_FILE.exists():
            logger.info(f"Loading token from {TOKEN_FILE}")
            try:
                with open(TOKEN_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.access_token = data.get('access_token')
                    self.refresh_token = data.get('refresh_token')
                    self.token_expiry = data.get('token_expiry')

                    if self.token_expiry and time.time() < (self.token_expiry - 60):  # Valid for at least 1 minute
                        logger.info("Loaded valid token from file")
                        return
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Could not load token from file: {e}")

        # Token doesn't exist, is invalid, or expired
        self._get_new_token()

    def _save_token(self):
        """Save token to file with proper locking."""
        TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'token_expiry': self.token_expiry
        }
        lock_path = str(TOKEN_FILE) + '.lock'
        temp_path = str(TOKEN_FILE) + '.tmp'

        logger.info(f"Saving token to {TOKEN_FILE}")
        try:
            with FileLock(lock_path, timeout=30):
                with open(temp_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(temp_path, TOKEN_FILE)
            logger.info(f"Token saved successfully to {TOKEN_FILE}")
        except Exception as e:
            logger.error(f"Failed to save token: {e}")
            # Clean up temp file if it exists
            if Path(temp_path).exists():
                try:
                    Path(temp_path).unlink()
                except:
                    pass

    def _get_new_token(self):
        """Get a new token from ServiceNow."""
        url = f"{self.instance_url}/authorization/token"
        auth = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        headers = {
            'Authorization': f'Basic {auth}',
            'Content-Type': 'application/json',
            'X-IBM-Client-Id': self.client_id
        }

        try:
            logger.info("Requesting new token from ServiceNow")
            response = requests.get(url, headers=headers, auth=(self.username, self.password), timeout=30, verify=False)
            response.raise_for_status()
            self._update_token(response.json())
            self._save_token()
            logger.info("Successfully obtained new token")
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get new token: {e}")
            raise

    def _refresh_token(self):
        """Refresh the current token or get a new one."""
        if not self.refresh_token:
            logger.info("No refresh token available, getting new token")
            self._get_new_token()
            return

        url = f"{self.instance_url}/authorization/token/refresh"
        headers = {'Content-Type': 'application/json', 'X-IBM-Client-Id': self.client_id}
        data = {'refresh_token': self.refresh_token}

        try:
            logger.info("Refreshing token")
            response = requests.post(url, headers=headers, json=data, timeout=30, verify=False)
            if response.status_code == 200:
                self._update_token(response.json())
                self._save_token()
                logger.info("Successfully refreshed token")
            else:
                logger.warning(f"Token refresh failed with status {response.status_code}, getting new token")
                self._get_new_token()
        except requests.exceptions.RequestException as e:
            logger.warning(f"Token refresh failed: {e}, getting new token")
            self._get_new_token()

    def _update_token(self, token_data):
        """Update token data from API response."""
        self.access_token = token_data.get('access_token')
        self.refresh_token = token_data.get('refresh_token')
        expires_in = token_data.get('expires_in', 1800)  # Default 30 minutes
        self.token_expiry = time.time() + expires_in
        logger.debug(f"Token updated, expires in {expires_in} seconds")

    def get_auth_headers(self):
        """Get authentication headers, refreshing token if necessary."""
        with self._lock:
            # Refresh token if it expires within 1 minute
            if not self.token_expiry or time.time() >= (self.token_expiry - 60):
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
        try:
            # Try alternative format
            return datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError):
            logger.debug(f"Could not parse discovery date: {date_str}")
            return datetime(1970, 1, 1)


class ServiceNowClient:
    def __init__(self):
        validate_config()
        self.token_manager = ServiceNowTokenManager(
            instance_url=config.snow_base_url,
            username=config.snow_functional_account_id,
            password=config.snow_functional_account_password,
            client_id=config.snow_client_key
        )
        base_url = config.snow_base_url.rstrip('/')
        self.server_url = f"{base_url}/itsm-compute/compute/instances"
        self.workstation_url = f"{base_url}/itsm-compute/compute/computers"

        # Setup session with connection pooling and retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=20)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def get_host_details(self, hostname):
        """Get host details by hostname, checking servers first then workstations."""
        # Safely handle hostname that might be None or not a string
        if not hostname or not isinstance(hostname, str):
            logger.warning(f"Invalid hostname provided: {hostname}")
            return {"name": str(hostname) if hostname is not None else "unknown", "status": "Invalid Hostname"}

        hostname = hostname.split('.')[0]  # Remove domain

        # Try servers first
        host_details = self._search_endpoint(self.server_url, hostname)
        if host_details and 'error' not in host_details:
            host_details['category'] = 'server'
            return host_details

        # Try workstations
        host_details = self._search_endpoint(self.workstation_url, hostname)
        if host_details and 'error' not in host_details:
            host_details['category'] = 'workstation'
            return host_details

        return {"name": hostname, "status": "Not Found"}

    @rate_limit(calls_per_second=10)  # Adjust based on API limits
    def _search_endpoint(self, endpoint, hostname):
        """Search a specific endpoint for hostname."""
        headers = self.token_manager.get_auth_headers()
        params = {'name': hostname}

        try:
            response = self.session.get(endpoint, headers=headers, params=params, timeout=30, verify=False)

            # Handle different HTTP status codes
            if response.status_code == 401:
                logger.warning(f"Authentication error for {hostname}")
                return {"name": hostname, "status": "Authentication Error", "category": "", "error": "HTTP 401"}
            elif response.status_code == 403:
                logger.warning(f"Authorization error for {hostname}")
                return {"name": hostname, "status": "Authorization Error", "category": "", "error": "HTTP 403"}
            elif response.status_code == 429:
                logger.warning(f"Rate limited for {hostname}")
                return {"name": hostname, "status": "Rate Limited", "category": "", "error": "HTTP 429"}
            elif response.status_code >= 500:
                logger.warning(f"Server error for {hostname}: {response.status_code}")
                return {"name": hostname, "status": "Server Error", "category": "", "error": f"HTTP {response.status_code}"}
            elif response.status_code != 200:
                logger.warning(f"Unexpected status code for {hostname}: {response.status_code}")
                return {"name": hostname, "status": f"HTTP {response.status_code}", "category": "", "error": f"HTTP {response.status_code}"}

            data = response.json()
            items = data.get('items', data) if isinstance(data, dict) else data

            if not items:
                return None

            # Return most recently discovered item
            if len(items) > 1:
                items = sorted(items, key=_parse_discovery_date, reverse=True)
                logger.debug(f"Multiple items found for {hostname}, using most recent")

            return items[0]

        except requests.exceptions.Timeout:
            logger.error(f"Timeout fetching details for {hostname}")
            return {"name": hostname, "error": "Request timeout", "status": "ServiceNow API Error", "category": ""}
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error fetching details for {hostname}")
            return {"name": hostname, "error": "Connection error", "status": "ServiceNow API Error", "category": ""}
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching details for {hostname}: {str(e)}")
            return {"name": hostname, "error": str(e), "status": "ServiceNow API Error", "category": ""}
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error for {hostname}: {str(e)}")
            return {"name": hostname, "error": "Invalid JSON response", "status": "ServiceNow API Error", "category": ""}

    def get_process_changes(self, params=None):
        """Get process changes from ServiceNow custom endpoint."""
        base_url = config.snow_base_url.rstrip('/')
        endpoint = f"{base_url}/api/x_metli_acme_it/process/changes"
        headers = self.token_manager.get_auth_headers()

        try:
            response = self.session.get(endpoint, headers=headers, params=params, timeout=30, verify=False)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching process changes: {str(e)}")
            return {"error": str(e), "status": "ServiceNow API Error"}


class AsyncServiceNowClient:
    def __init__(self, token_manager=None):
        if token_manager is None:
            validate_config()
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
        if result and 'error' not in result:
            result['category'] = 'server'
            return result
        # Try workstations
        result = await self._search_endpoint(session, self.workstation_url, hostname_short)
        if result and 'error' not in result:
            result['category'] = 'workstation'
            return result
        return {"name": hostname_short, "status": "Not Found"}

    async def _search_endpoint(self, session, endpoint, hostname):
        headers = self.token_manager.get_auth_headers()
        params = {'name': hostname}
        try:
            async with session.get(endpoint, headers=headers, params=params, timeout=30, verify_ssl=False) as response:
                if response.status == 429:
                    return {"name": hostname, "error": "HTTP 429 Too Many Requests", "status": "ServiceNow API Error", "category": ""}
                if response.status == 401:
                    return {"name": hostname, "error": "HTTP 401 Unauthorized", "status": "ServiceNow API Error", "category": ""}
                if response.status == 403:
                    return {"name": hostname, "error": "HTTP 403 Forbidden", "status": "ServiceNow API Error", "category": ""}
                if response.status >= 500:
                    return {"name": hostname, "error": f"HTTP {response.status} Server Error", "status": "ServiceNow API Error", "category": ""}
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
            logger.error(f"Async error for {hostname}: {str(e)}")
            return {"name": hostname, "error": str(e), "status": "ServiceNow API Error", "category": ""}


def process_in_batches(items, batch_size=100):
    """Process items in batches to manage memory usage."""
    for i in range(0, len(items), batch_size):
        yield items[i:i + batch_size]


def validate_input_file(filepath):
    """Validate input file before processing."""
    file_path = Path(filepath)

    if not file_path.exists():
        raise FileNotFoundError(f"Input file not found: {filepath}")

    if not str(filepath).lower().endswith(('.xlsx', '.xls')):
        raise ValueError("Input file must be an Excel file (.xlsx or .xls)")

    # Check if file is readable
    try:
        df = pd.read_excel(filepath, nrows=1, engine='openpyxl')
        if df.empty:
            raise ValueError("Input file appears to be empty")
    except Exception as e:
        raise ValueError(f"Cannot read input file: {e}")

    logger.info(f"Input file validation passed: {filepath}")
    return True


def enrich_host_report(input_file):
    """Enrich host data with ServiceNow details (synchronous version)."""
    try:
        # Validate input file
        validate_input_file(input_file)

        today = datetime.now().strftime('%m-%d-%Y')
        input_name = Path(input_file).name
        output_file = DATA_DIR / today / f"Enriched {input_name}"

        if output_file.exists():
            logger.info(f"Enriched file already exists: {output_file}")
            return output_file

        # Read input data - force all columns to be strings to prevent type issues
        logger.info(f"Reading input file: {input_file}")
        df = pd.read_excel(input_file, engine="openpyxl", dtype=str)

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
        initial_count = len(df)
        df = df.dropna(subset=[hostname_col])
        df = df[df[hostname_col].str.strip() != '']
        logger.info(f"Removed {initial_count - len(df)} rows with empty hostnames")

        # Extract hostnames and filter out any None or empty values
        hostnames = []
        for h in df[hostname_col].tolist():
            if h is not None and str(h).strip() not in ['nan', 'NaN', 'none', 'None', 'null', 'NULL', '']:
                hostname_str = str(h).strip()
                hostnames.append(hostname_str)

        logger.info(f"Processing {len(hostnames)} valid hostnames from {input_file}")

        if not hostnames:
            logger.warning("No valid hostnames found in input file")
            return input_file

        client = ServiceNowClient()
        snow_data = {}
        errors_occurred = False

        def enrich_single_host(hostname):
            try:
                details = client.get_host_details(hostname)
                short_hostname = hostname.split('.')[0].lower()
                return short_hostname, details
            except Exception as e:
                logger.error(f"Error enriching host {hostname}: {e}")
                return hostname.split('.')[0].lower(), {"name": hostname, "error": str(e), "status": "Processing Error", "category": ""}

        # Process in batches to manage memory and API load
        batch_size = 50  # Adjust based on API limits and performance
        max_workers = min(10, len(hostnames))  # Don't create more threads than needed

        for batch_num, batch in enumerate(process_in_batches(hostnames, batch_size), 1):
            logger.info(f"Processing batch {batch_num}/{(len(hostnames) + batch_size - 1) // batch_size}")

            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(enrich_single_host, hostname): hostname for hostname in batch}

                for future in tqdm(concurrent.futures.as_completed(futures),
                                   total=len(futures),
                                   desc=f"Enriching batch {batch_num}"):
                    try:
                        short_hostname, details = future.result(timeout=60)  # 60 second timeout
                        if details:
                            snow_data[short_hostname] = details
                        if details and 'error' in details:
                            errors_occurred = True
                    except concurrent.futures.TimeoutError:
                        hostname = futures[future]
                        logger.error(f"Timeout processing host {hostname}")
                        short_hostname = hostname.split('.')[0].lower()
                        snow_data[short_hostname] = {"name": hostname, "error": "Processing timeout", "status": "Processing Error", "category": ""}
                        errors_occurred = True
                    except Exception as e:
                        hostname = futures[future]
                        logger.error(f"Exception processing host {hostname}: {e}")
                        short_hostname = hostname.split('.')[0].lower()
                        snow_data[short_hostname] = {"name": hostname, "error": str(e), "status": "Processing Error", "category": ""}
                        errors_occurred = True

        if not snow_data:
            logger.error("No ServiceNow data collected, cannot enrich report")
            return input_file

        # Add ServiceNow data to the original dataframe
        logger.info(f"Retrieved data for {len(snow_data)} hosts from ServiceNow")

        # Create new columns for ServiceNow data
        snow_columns = ['id', 'ciClass', 'environment', 'lifecycleStatus', 'country',
                        'supportedCountry', 'operatingSystem', 'category', 'status', 'error']

        for col in snow_columns:
            df[f'SNOW_{col}'] = None

        # For each row in the dataframe, add the ServiceNow data
        for idx, row in df.iterrows():
            hostname = row[hostname_col]
            # Since we read with dtype=str, hostname should already be a string
            if hostname and str(hostname).strip() not in ['nan', 'NaN', 'none', 'None', 'null', 'NULL', '']:
                short_hostname = hostname.split('.')[0].lower()
            else:
                short_hostname = ""

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
                column_width = min(max_length, 50)

                # Convert to Excel's character width
                worksheet.column_dimensions[worksheet.cell(row=1, column=i + 1).column_letter].width = column_width

        success_count = len([v for v in snow_data.values() if v.get('status') != 'ServiceNow API Error'])
        error_count = len(snow_data) - success_count

        if errors_occurred:
            logger.warning(f"Enriched report saved with {error_count} errors to {output_file}")
        else:
            logger.info(f"Successfully enriched report saved to {output_file}")

        logger.info(f"Enrichment summary: {success_count} successful, {error_count} errors out of {len(snow_data)} total")
        return output_file

    except Exception as e:
        logger.error(f"Error in enrich_host_report: {e}")
        raise


if __name__ == "__main__":
    try:
        client = ServiceNowClient()

        hostname = "JP2NKTQL3.alico.corp"
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
            if 'status' in details:
                print(f"SNOW Status: {details.get('status')}")
            if 'error' in details:
                print(f"SNOW Error: {details.get('error')}")
        else:
            print("Host not found")

        changes = client.get_process_changes()
        print(changes)

    except Exception as e:
        logger.error(f"Error in main: {e}")
        raise
