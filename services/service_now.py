import base64
import concurrent.futures
import json
import logging
import os
import sqlite3
import sys
import threading
import time
from datetime import UTC, datetime
from typing import List
from pathlib import Path

import pandas as pd
import requests
import urllib3
from filelock import FileLock
from requests.adapters import HTTPAdapter
from rich.progress import track

from my_config import get_config

# Disable InsecureRequestWarning for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

config = get_config()
TOKEN_FILE = Path(__file__).parent.parent / "data/transient/service_now_access_token.json"
DATA_DIR = Path(__file__).parent.parent / "data/transient/epp_device_tagging"
SNOW_HOST_CACHE_DB = Path(__file__).parent.parent / "data/transient/snow_host_cache.db"
SNOW_CACHE_TTL_HOURS = 168  # 7 days — env/country rarely change; long TTL lets on-demand reports hit warm cache


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

        # Host details cache (SQLite)
        self._init_host_cache()
        logger.debug("ServiceNowClient initialized successfully")

    def _init_host_cache(self):
        """Initialize SQLite cache for host details using per-thread connections."""
        SNOW_HOST_CACHE_DB.parent.mkdir(parents=True, exist_ok=True)
        self._cache_local = threading.local()

        # Create table and purge expired entries using a temporary connection
        conn = sqlite3.connect(str(SNOW_HOST_CACHE_DB))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS host_cache (
                hostname TEXT PRIMARY KEY,
                response_json TEXT NOT NULL,
                cached_at REAL NOT NULL
            )
        """)
        conn.commit()

        # Purge expired entries on init
        cutoff = time.time() - (SNOW_CACHE_TTL_HOURS * 3600)
        deleted = conn.execute("DELETE FROM host_cache WHERE cached_at < ?", (cutoff,)).rowcount
        if deleted:
            conn.commit()
            logger.info(f"Purged {deleted} expired entries from SNOW host cache")
        conn.close()

    def _get_cache_conn(self):
        """Get a per-thread SQLite connection for the host cache."""
        if not hasattr(self._cache_local, 'conn') or self._cache_local.conn is None:
            self._cache_local.conn = sqlite3.connect(str(SNOW_HOST_CACHE_DB))
            self._cache_local.conn.execute("PRAGMA journal_mode=WAL")
            self._cache_local.conn.execute("PRAGMA busy_timeout=5000")
        return self._cache_local.conn

    def _get_cached_host(self, hostname):
        """Return cached host details if within TTL, else None."""
        conn = self._get_cache_conn()
        row = conn.execute(
            "SELECT response_json, cached_at FROM host_cache WHERE hostname = ?",
            (hostname.lower(),)
        ).fetchone()
        if row:
            age_hours = (time.time() - row[1]) / 3600
            if age_hours < SNOW_CACHE_TTL_HOURS:
                return json.loads(row[0])
        return None

    def _cache_host(self, hostname, details):
        """Cache host details. Skip transient API errors."""
        if not details or details.get('status') == 'ServiceNow API Error':
            return
        conn = self._get_cache_conn()
        conn.execute(
            "INSERT OR REPLACE INTO host_cache (hostname, response_json, cached_at) VALUES (?, ?, ?)",
            (hostname.lower(), json.dumps(details), time.time())
        )
        conn.commit()

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
        """Get host details by hostname, with SQLite caching."""
        if not hostname or not isinstance(hostname, str):
            logger.warning(f"Invalid hostname provided: {hostname}")
            return {"name": str(hostname) if hostname is not None else "unknown", "status": "Invalid Hostname"}

        hostname = hostname.split('.')[0]  # Remove domain

        # Check cache first
        cached = self._get_cached_host(hostname)
        if cached is not None:
            return cached

        # Fetch from API
        result = self._fetch_host_details_from_api(hostname)

        # Cache the result (skips transient API errors)
        self._cache_host(hostname, result)

        return result

    def _fetch_host_details_from_api(self, hostname):
        """Fetch host details from ServiceNow API (uncached)."""
        # Try workstations
        host_details = self._search_endpoint(self.workstation_url, hostname)
        if host_details and 'error' not in host_details:
            host_details['category'] = 'workstation'
            if hostname.upper().startswith('VMVDI'):
                host_details['ciClass'] = 'Workstation'
            return host_details

        # Try servers
        host_details = self._search_endpoint(self.server_url, hostname)
        if host_details and 'error' not in host_details:
            host_details['category'] = 'server'
            if hostname.upper().startswith('VMVDI'):
                host_details['category'] = 'workstation'
                host_details['ciClass'] = 'Workstation'
                logger.debug(f"Overriding SNOW category for VMVDI host {hostname}: server → workstation")
            return host_details

        # If both endpoints returned API errors, return the last error
        if host_details and 'error' in host_details:
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
                    if attempt < max_retries - 1:
                        wait_time = 2 ** (attempt + 1)
                        logger.warning(f"Empty response body for {hostname} from {endpoint}, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})")
                        time.sleep(wait_time)
                        continue
                    else:
                        logger.warning(f"Empty response body for {hostname} from {endpoint} after {max_retries} attempts")
                        return None

                # Try to parse JSON with better error handling
                try:
                    data = response.json()
                except ValueError as json_error:
                    if attempt < max_retries - 1:
                        wait_time = 2 ** (attempt + 1)
                        logger.warning(f"Invalid JSON for {hostname}: {json_error}, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})")
                        time.sleep(wait_time)
                        continue
                    else:
                        logger.warning(f"Invalid JSON for {hostname} after {max_retries} attempts: {json_error}. Body: {response.text[:200]}")
                        return None

                items = data.get('items', data) if isinstance(data, dict) else data

                if not items:
                    logger.debug(f"No items found for {hostname}")
                    return None

                # Discard retired records; pick most recently discovered from the rest
                if len(items) > 1:
                    non_retired = [i for i in items if str(i.get('lifecycleStatus', '')).lower() != 'retired']
                    pool = non_retired if non_retired else items
                    pool = sorted(pool, key=_parse_discovery_date, reverse=True)
                    logger.debug(f"Multiple items for {hostname}: {len(items)} total, {len(non_retired)} non-retired, selected {pool[0].get('lifecycleStatus')}")
                    return pool[0]

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
        endpoint = f"{base_url}/api/x_company_it/process/changes"
        # endpoint = 'https://company-prod.service-now.com/api/x_company_it/process/changes'
        headers = self.token_manager.get_auth_headers()
        try:
            response = self.session.get(endpoint, headers=headers, params=params, timeout=10, verify=False)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching process changes: {str(e)}")
            return {"error": str(e), "status": "ServiceNow API Error"}

    def get_recent_incidents(self, assignment_group_name, minutes=15):
        """Fetch incidents assigned to a group, optionally filtered by createdDate.

        Uses the ITSM Incident API endpoint (not the Table API).
        See KB0224060 for API documentation.

        The API does not support date-range filtering, so we fetch all incidents
        for the group and optionally filter client-side by createdDate.

        Args:
            assignment_group_name: The display name of the assignment group
            minutes: How far back to look (default 15 minutes).
                     Pass 0 to skip date filtering and return all results.

        Returns:
            List of incident records or error dict
        """
        from datetime import timedelta

        base_url = config.snow_base_url.rstrip('/')
        endpoint = f"{base_url}/itsm-incident/process/incidents"
        headers = self.token_manager.get_auth_headers()

        logger.debug(f"Fetching incidents for group '{assignment_group_name}' (minutes={minutes})")

        params = {
            'assignmentGroup': assignment_group_name,
            'limit': 100
        }

        try:
            self._wait_for_rate_limit()
            response = self.session.get(endpoint, headers=headers, params=params, timeout=30, verify=False)

            if response.status_code >= 400:
                logger.error(f"API error {response.status_code}: {response.text[:500]}")
                return {"error": f"HTTP {response.status_code}", "status": "ServiceNow API Error"}

            response.raise_for_status()

            data = response.json()
            all_results = data.get('items', data.get('result', []))
            if isinstance(data, list):
                all_results = data

            logger.info(f"SNOW returned {len(all_results)} total incident(s) for '{assignment_group_name}'")
            for inc in all_results[:10]:
                logger.info(f"  INC {inc.get('number','?')} state={inc.get('state','?')} created={inc.get('createdDate','?')} group={inc.get('assignmentGroup', inc.get('assignment_group','?'))}")

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching incidents: {str(e)}")
            return {"error": str(e), "status": "ServiceNow API Error"}

        # minutes=0 means caller handles filtering (e.g. seen-ID tracking)
        if minutes == 0:
            logger.info(f"MIM poll '{assignment_group_name}': returning all {len(all_results)} incident(s) (no date filter)")
            return all_results

        # Filter by createdDate client-side — API does not support date-range params
        # CreatedDate format from ITSM API: "MM-DD-YYYY HH:MM AM/PM" (ET)
        threshold_dt = datetime.now() - timedelta(minutes=minutes)
        filtered_results = []
        for inc in all_results:
            created_str = inc.get('createdDate', '')
            if created_str:
                try:
                    created_dt = datetime.strptime(created_str, '%m-%d-%Y %I:%M %p')
                    if created_dt >= threshold_dt:
                        filtered_results.append(inc)
                except ValueError:
                    # If date parsing fails, include the incident to be safe
                    filtered_results.append(inc)
            else:
                filtered_results.append(inc)

        logger.info(f"MIM poll '{assignment_group_name}': {len(filtered_results)} recent out of {len(all_results)} total incidents")
        return filtered_results

    def get_recent_incidents_by_group_name(self, group_name, minutes=15):
        """Fetch incidents by group name.

        This is now the same as get_recent_incidents since we query by group name directly.

        Args:
            group_name: The display name of the assignment group
            minutes: How far back to look (default 15 minutes)

        Returns:
            List of incident records or error dict
        """
        return self.get_recent_incidents(group_name, minutes=minutes)

    def get_recent_changes(self, assignment_group_name, minutes=15):
        """Fetch change tickets assigned to a group in the past N minutes.

        Uses the same process/changes endpoint as get_process_changes.
        Filters client-side by createdDate since the API has no date-range param.

        Args:
            assignment_group_name: The display name of the assignment group
            minutes: How far back to look (default 15 minutes)

        Returns:
            List of change records or error dict
        """
        from datetime import timedelta

        base_url = config.snow_base_url.rstrip('/')
        endpoint = f"{base_url}/api/x_company_it/process/changes"
        headers = self.token_manager.get_auth_headers()

        params = {
            'assignmentGroup': assignment_group_name,
            'limit': 100
        }

        try:
            self._wait_for_rate_limit()
            response = self.session.get(endpoint, headers=headers, params=params, timeout=30, verify=False)

            if response.status_code >= 400:
                logger.error(f"CHG API error {response.status_code}: {response.text[:500]}")
                return {"error": f"HTTP {response.status_code}", "status": "ServiceNow API Error"}

            response.raise_for_status()

            data = response.json()
            all_results = data.get('items', data.get('result', []))
            if isinstance(data, list):
                all_results = data

            logger.info(f"SNOW returned {len(all_results)} total change(s) for '{assignment_group_name}'")
            for chg in all_results[:10]:
                logger.info(f"  CHG {chg.get('number','?')} state={chg.get('state','?')} created={chg.get('createdDate', chg.get('startDate','?'))} group={chg.get('assignmentGroup', chg.get('assignment_group','?'))}")

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching changes: {str(e)}")
            return {"error": str(e), "status": "ServiceNow API Error"}

        # Filter client-side by creation date — changes may use different date field names
        threshold_dt = datetime.now() - timedelta(minutes=minutes)
        filtered_results = []
        for chg in all_results:
            created_str = (chg.get('createdDate') or chg.get('startDate') or
                           chg.get('sys_created_on') or '')
            if created_str:
                try:
                    created_dt = datetime.strptime(created_str, '%m-%d-%Y %I:%M %p')
                    if created_dt >= threshold_dt:
                        filtered_results.append(chg)
                except ValueError:
                    filtered_results.append(chg)
            else:
                filtered_results.append(chg)

        logger.info(f"MIM CHG poll '{assignment_group_name}': {len(filtered_results)} recent out of {len(all_results)} total changes")
        return filtered_results


    def search_incidents_by_ci(self, hostname: str, hours: int = 72) -> List[dict]:
        """Search for recent SNOW incidents where the affected CI matches a hostname.

        Queries the ITSM Incident API with a configurationItem filter, then
        filters client-side by hostname match as a fallback to handle environments
        where the param is not supported.

        Args:
            hostname: Hostname to search for (short name, no domain)
            hours: How far back to look in hours (default 72 = 3 days)

        Returns:
            List of matching incident records, empty list on error
        """
        from datetime import timedelta

        base_url = config.snow_base_url.rstrip('/')
        endpoint = f"{base_url}/itsm-incident/process/incidents"
        headers = self.token_manager.get_auth_headers()
        short_hostname = hostname.split('.')[0].upper()
        threshold_dt = datetime.now() - timedelta(hours=hours)

        all_results = []
        try:
            params = {
                'configurationItem': short_hostname,
                'limit': 50,
            }
            self._wait_for_rate_limit()
            response = self.session.get(
                endpoint, headers=headers, params=params, timeout=15, verify=False
            )
            if response.status_code >= 400:
                logger.debug(f"SNOW incident CI search returned {response.status_code} for {short_hostname}")
                return []
            data = response.json()
            all_results = data.get('items', data.get('result', []))
            if isinstance(data, list):
                all_results = data
        except requests.exceptions.RequestException as e:
            logger.warning(f"SNOW search_incidents_by_ci failed for {hostname}: {e}")
            return []

        # Client-side filter: created within the time window and CI matches hostname
        filtered = []
        for inc in all_results:
            # Date filter
            created_str = inc.get('createdDate', '') or inc.get('openedAt', '')
            if created_str:
                try:
                    created_dt = datetime.strptime(created_str, '%m-%d-%Y %I:%M %p')
                    if created_dt < threshold_dt:
                        continue
                except (ValueError, TypeError):
                    pass  # Include if date can't be parsed

            # Hostname relevance filter — match on CI, description, or short description
            match_fields = ' '.join(str(inc.get(f, '')) for f in (
                'configurationItem', 'ciItem', 'shortDescription',
                'description', 'cmdbCi', 'u_affected_ci',
            )).upper()
            if short_hostname in match_fields:
                filtered.append(inc)

        logger.info(
            f"SNOW incidents for CI '{short_hostname}': "
            f"{len(filtered)} found in last {hours}h"
        )
        return filtered

    def search_changes_by_ci(self, hostname: str) -> List[dict]:
        """Search for active or recently scheduled SNOW change tickets for a hostname.

        Fetches change tickets from the process/changes endpoint and filters
        client-side for records that reference the given hostname. Active change
        windows are a critical context signal — a planned change on the affected
        host can explain an alert as expected activity.

        Args:
            hostname: Hostname to search for (short name, no domain)

        Returns:
            List of matching change ticket records, empty list on error
        """
        base_url = config.snow_base_url.rstrip('/')
        endpoint = f"{base_url}/api/x_company_it/process/changes"
        headers = self.token_manager.get_auth_headers()
        short_hostname = hostname.split('.')[0].upper()

        try:
            self._wait_for_rate_limit()
            params = {'configurationItem': short_hostname, 'limit': 50}
            response = self.session.get(
                endpoint, headers=headers, params=params, timeout=15, verify=False
            )
            if response.status_code >= 400:
                logger.debug(
                    f"SNOW change CI param returned {response.status_code}, "
                    f"falling back to unfiltered fetch"
                )
                # Fallback: fetch recent changes and filter client-side
                self._wait_for_rate_limit()
                response = self.session.get(
                    endpoint, headers=headers,
                    params={'state': 'Implement', 'limit': 100},
                    timeout=15, verify=False
                )
                if response.status_code >= 400:
                    return []

            response.raise_for_status()
            data = response.json()
            changes = data.get('items', data.get('result', []))
            if isinstance(data, list):
                changes = data

        except requests.exceptions.RequestException as e:
            logger.warning(f"SNOW search_changes_by_ci failed for {hostname}: {e}")
            return []

        # Client-side hostname filter
        filtered = []
        for chg in changes:
            match_fields = ' '.join(str(chg.get(f, '')) for f in (
                'configurationItem', 'ciItem', 'shortDescription',
                'description', 'cmdbCi', 'u_affected_ci',
            )).upper()
            if short_hostname in match_fields:
                filtered.append(chg)

        logger.info(
            f"SNOW changes for CI '{short_hostname}': {len(filtered)} found"
        )
        return filtered


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
            # Override for VMVDI hosts - always treat as workstations regardless of SNOW classification
            if hostname_short.upper().startswith('VMVDI'):
                result['category'] = 'workstation'
                result['ciClass'] = 'Workstation'
            return result
        # Try workstations
        result = await self._search_endpoint(session, self.workstation_url, hostname_short)
        if result:
            result['category'] = 'workstation'
            # Override CI class for VMVDI hosts (always workstations regardless of SNOW data)
            if hostname_short.upper().startswith('VMVDI'):
                result['ciClass'] = 'Workstation'
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
    client = ServiceNowClient(requests_per_second=30)
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

        for idx, future in enumerate(track(concurrent.futures.as_completed(futures), total=len(futures), description="Enriching hosts with ServiceNow", disable=not sys.stdout.isatty()), 1):
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

    snow_columns = ['id', 'ciClass', 'environment', 'lifecycleStatus', 'country',
                    'supportedCountry', 'operatingSystem', 'category', 'status', 'error']

    # Vectorized merge. The prior row-by-row `df.loc[idx, col] = ...` loop was
    # O(rows × cols) pandas setitem calls against arrow-backed string columns,
    # which dominated runtime (observed 30+ min on 85K rows).
    merge_start = time.time()
    snow_records = []
    for short_hostname, result in snow_data.items():
        rec = {'_snow_key': short_hostname}
        is_api_error = result.get('status') == 'ServiceNow API Error'
        for col in snow_columns:
            if col in result:
                rec[f'SNOW_{col}'] = result[col]
        if is_api_error:
            # API-error rows: blank category regardless of what the API returned
            rec['SNOW_category'] = ''
        snow_records.append(rec)
    snow_df = pd.DataFrame(snow_records)

    df['_snow_key'] = df[hostname_col].astype(str).str.split('.').str[0].str.lower()
    df = df.merge(snow_df, on='_snow_key', how='left').drop(columns=['_snow_key'])

    # Guarantee every SNOW_* column exists and unmatched rows get '' (not NaN)
    for col in snow_columns:
        col_name = f'SNOW_{col}'
        if col_name not in df.columns:
            df[col_name] = ''
        else:
            df[col_name] = df[col_name].fillna('').astype(str)

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

    hostname = "USHZK3C64.internal.example.com"
    logger.info(f"Looking up in SNOW: {hostname}...")

    details = client.get_host_details(hostname)
    if details:
        print(f"Name: {details.get('name')}")
        print(f"IP: {details.get('ipAddress')}")
        print(f"Category: {details.get('category')}")
        print(f"CI Class: {details.get('ciClass')}")
        print(f"OS: {details.get('operatingSystem')}")
        print(f"Country: {details.get('country')}")
        print(f"Supported Country: {details.get('supportedCountry')}")
        print(f"Status: {details.get('state')}")
        print(f"Lifecycle Status: {details.get('lifecycleStatus')}")
        print(f"Domain: {details.get('osDomain')}")
        print(f"Environment: {details.get('environment')}")
        print(f"ID: {details.get('id')}")
        if 'status' in details:
            print(f"SNOW Status: {details.get('status')}")
        if 'error' in details:
            print(f"SNOW Error: {details.get('error')}")
    else:
        print("Host not found")

    # changes = client.get_process_changes()
    # print(changes)
