"""
XSOAR Service using official demisto-py SDK

This module provides a wrapper around the official demisto-py SDK
to maintain backward compatibility with existing code while leveraging
the official Palo Alto Networks XSOAR Python client.

Usage:
    from services.xsoar import TicketHandler, ListHandler, XsoarEnvironment

    # Use prod environment (default)
    prod_handler = TicketHandler()
    prod_handler = TicketHandler(XsoarEnvironment.PROD)

    # Use dev environment
    dev_handler = TicketHandler(XsoarEnvironment.DEV)

    # Same for ListHandler
    prod_list = ListHandler()
    dev_list = ListHandler(XsoarEnvironment.DEV)

Migration Date: 2024-10-31
Original: services/xsoar.py.backup
"""
import ast
import json
import logging
import os
import sys
import time
from datetime import datetime
from http.client import RemoteDisconnected
from typing import Any, Dict, List, Optional, Tuple

import demisto_client
import pytz
import requests
import urllib3
from demisto_client.demisto_api import rest
from demisto_client.demisto_api.models import SearchIncidentsData
from tqdm import tqdm
from urllib3.exceptions import InsecureRequestWarning, ProtocolError

from my_config import get_config
from src.utils.xsoar_enums import XsoarEnvironment

# For easier access to ApiException
ApiException = rest.ApiException


def _parse_generic_response(response: Optional[Tuple]) -> Dict[str, Any]:
    """
    Parse response from generic_request which returns (body, status, headers) tuple.
    Body might be JSON string or Python repr string.

    Args:
        response: Tuple containing (body, status, headers) from API call

    Returns:
        Parsed response as dictionary, empty dict if parsing fails
    """
    if not response or not isinstance(response, tuple) or len(response) < 1:
        return {}

    body = response[0]
    if not body:
        return {}

    # Try JSON first, then Python repr
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        try:
            return ast.literal_eval(body)
        except (ValueError, SyntaxError):
            return {}


urllib3.disable_warnings(InsecureRequestWarning)

CONFIG = get_config()
log = logging.getLogger(__name__)

# Set urllib3 logging to WARNING to reduce log noise
# Shows connection errors and retries, but not successful connections
urllib3_logger = logging.getLogger("urllib3.connectionpool")
urllib3_logger.setLevel(logging.WARNING)

# Configure connection pool size to match parallel workers (25)
# This prevents "Connection pool is full" warnings when using ThreadPoolExecutor with 25 workers
# Patch urllib3.PoolManager to use larger default maxsize before creating clients
import functools

_original_pool_manager_init = urllib3.PoolManager.__init__


@functools.wraps(_original_pool_manager_init)
def _patched_pool_manager_init(self, *args, **kwargs):
    """Patched PoolManager init with larger default maxsize."""
    # Set maxsize to 25 if not explicitly provided (matches ticket_cache.py worker count)
    # Reduced from 100->50->25 to avoid API rate limiting
    if 'maxsize' not in kwargs:
        kwargs['maxsize'] = 25
    return _original_pool_manager_init(self, *args, **kwargs)


urllib3.PoolManager.__init__ = _patched_pool_manager_init

# Initialize demisto-py clients for prod and dev environments with timeout
prod_client = demisto_client.configure(
    base_url=CONFIG.xsoar_prod_api_base_url,
    api_key=CONFIG.xsoar_prod_auth_key,
    auth_id=CONFIG.xsoar_prod_auth_id,
    verify_ssl=False
)

dev_client = demisto_client.configure(
    base_url=CONFIG.xsoar_dev_api_base_url,
    api_key=CONFIG.xsoar_dev_auth_key,
    auth_id=CONFIG.xsoar_dev_auth_id,
    verify_ssl=False
)

# Configure connection and read timeouts for both clients
# Connect timeout: 30s (how long to wait to establish connection)
# Read timeout: 180s (how long to wait for response data after connection established)
# This prevents indefinite hangs when the API is unresponsive while allowing legitimate slow queries
# Increased to 180s to handle slow network environments (VMs) where pages can take 100+ seconds
for client in [prod_client, dev_client]:
    if hasattr(client, 'api_client') and hasattr(client.api_client, 'rest_client'):
        rest_client = client.api_client.rest_client
        # Set timeout: (connect_timeout, read_timeout) in seconds
        # Can be overridden via XSOAR_READ_TIMEOUT env var
        read_timeout = int(os.getenv('XSOAR_READ_TIMEOUT', '180'))
        rest_client.timeout = (30, read_timeout)

# Configure retry strategy for connection resilience
# Retry on connection errors, but not on HTTP errors (let application handle those)
retry_strategy = urllib3.Retry(
    total=3,  # Max 3 retries
    connect=3,  # Retry connection failures
    read=2,  # Retry read timeouts
    status=0,  # Don't retry on HTTP status codes (handle in application logic)
    backoff_factor=1,  # Wait 1s, 2s, 4s between retries
    allowed_methods=["GET", "POST", "PUT", "DELETE"],  # Retry on all methods
    raise_on_status=False  # Don't raise exception on retry exhaustion, let app handle it
)

# Also configure the rest client's pool manager if available
for client in [prod_client, dev_client]:
    if hasattr(client, 'api_client') and hasattr(client.api_client, 'rest_client'):
        rest_client = client.api_client.rest_client
        if hasattr(rest_client, 'pool_manager'):
            # Recreate pool manager with maxsize=25, proper timeout configuration, and retry logic
            # This prevents threads from hanging indefinitely waiting for connections
            # Read timeout increased to 180s to handle slow network environments (VMs)
            read_timeout = int(os.getenv('XSOAR_READ_TIMEOUT', '180'))
            rest_client.pool_manager = urllib3.PoolManager(
                num_pools=10,
                maxsize=25,  # Reduced from 100->50->25 to avoid API rate limiting
                timeout=urllib3.Timeout(connect=30.0, read=float(read_timeout)),
                retries=retry_strategy,  # Add retry logic for transient network issues
                cert_reqs='CERT_NONE' if not client.api_client.configuration.verify_ssl else 'CERT_REQUIRED'
            )


def import_ticket(source_ticket_number: str, requestor_email_address: Optional[str] = None) -> Tuple[Any, str]:
    """
    Import ticket from prod to dev environment.

    Args:
        source_ticket_number: The incident ID from prod to import
        requestor_email_address: Optional email to set as owner in dev

    Returns:
        Tuple of (ticket_id, ticket_url) or (error_dict, '') if failed
    """
    log.info(f"Importing ticket {source_ticket_number} from prod to dev")
    prod_ticket_handler = TicketHandler(XsoarEnvironment.PROD)
    dev_ticket_handler = TicketHandler(XsoarEnvironment.DEV)

    incident_data = prod_ticket_handler.get_case_data(source_ticket_number)
    log.debug(f"Retrieved incident data for {source_ticket_number}")
    if requestor_email_address:
        incident_data['owner'] = requestor_email_address

    new_ticket_data = dev_ticket_handler.create_in_dev(incident_data)

    if 'error' in new_ticket_data:
        log.error(f"Failed to import ticket {source_ticket_number}: {new_ticket_data.get('error')}")
        return new_ticket_data, ''

    ticket_id = new_ticket_data['id']
    ticket_url = f'{CONFIG.xsoar_dev_ui_base_url}/Custom/caseinfoid/{ticket_id}'
    log.info(f"Successfully imported ticket {source_ticket_number} to dev as {ticket_id}")
    return ticket_id, ticket_url


class TicketHandler:
    """Handler for XSOAR ticket operations including search, create, update, and link."""

    # Configuration class variables (can be overridden via env vars)
    # Smaller page sizes (1000-2000) work better for slow networks (VMs)
    # Larger page sizes (5000) work better for fast networks (local dev)
    DEFAULT_PAGE_SIZE = int(os.getenv('XSOAR_PAGE_SIZE', '2000'))

    # Read timeout for API requests (seconds)
    # Increase this for slow network environments where pages take 100+ seconds
    READ_TIMEOUT = int(os.getenv('XSOAR_READ_TIMEOUT', '180'))

    def __init__(self, environment: XsoarEnvironment = XsoarEnvironment.PROD):
        """
        Initialize TicketHandler with XSOAR environment.

        Args:
            environment: XsoarEnvironment enum (PROD or DEV), defaults to PROD
        """
        if environment == XsoarEnvironment.PROD:
            self.client = prod_client
            self.base_url = CONFIG.xsoar_prod_api_base_url
            self.auth_key = CONFIG.xsoar_prod_auth_key
            self.auth_id = CONFIG.xsoar_prod_auth_id
        elif environment == XsoarEnvironment.DEV:
            self.client = dev_client
            self.base_url = CONFIG.xsoar_dev_api_base_url
            self.auth_key = CONFIG.xsoar_dev_auth_key
            self.auth_id = CONFIG.xsoar_dev_auth_id
        else:
            raise ValueError(f"Invalid environment: {environment}. Must be XsoarEnvironment.PROD or XsoarEnvironment.DEV")

    def get_tickets(self, query: str, period: Optional[Dict[str, Any]] = None,
                    size: int = 20000, paginate: bool = True) -> List[Dict[str, Any]]:
        """
        Fetch security incidents from XSOAR using demisto-py SDK.

        Args:
            query: XSOAR query string for filtering incidents
            period: Optional time period filter
            size: Maximum number of results (used when paginate=False)
            paginate: Whether to fetch all results with pagination

        Returns:
            List of incident dictionaries
        """
        full_query = query + f' -category:job -type:"{CONFIG.team_name} Ticket QA" -type:"{CONFIG.team_name} SNOW Whitelist Request"'

        log.debug(f"get_tickets() called with query: {query[:100]}...")
        log.debug(f"  Paginate: {paginate}, Size: {size}")

        # Quick connectivity test with small query and DNS resolution check
        try:
            # Test DNS resolution first
            import socket
            from urllib.parse import urlparse

            log.debug(f"  Testing DNS resolution for XSOAR API...")
            parsed_url = urlparse(self.base_url)
            hostname = parsed_url.netloc.split(':')[0]  # Remove port if present
            try:
                start_dns = time.time()
                ip_address = socket.gethostbyname(hostname)
                dns_time = time.time() - start_dns
                log.debug(f"  ✓ DNS resolved {hostname} -> {ip_address} in {dns_time:.2f}s")
            except socket.gaierror as dns_err:
                log.error(f"  ✗ DNS resolution failed for {hostname}: {dns_err}")
                log.error(f"  This indicates a DNS configuration problem on this system")
                raise

            log.debug(f"  Testing XSOAR API connectivity with small test query...")
            test_filter = {"query": "id:1", "page": 0, "size": 1}
            test_search = SearchIncidentsData(filter=test_filter)

            start_api = time.time()
            test_response = self.client.search_incidents(filter=test_search)
            api_time = time.time() - start_api
            log.debug(f"  ✓ XSOAR API is reachable and responding in {api_time:.2f}s: {type(test_response)}")
        except Exception as e:
            log.error(f"  ✗ XSOAR API connectivity test failed: {e}")
            log.error(f"  This may indicate network issues, API outage, or authentication problems")
            raise

        if paginate:
            return self._fetch_paginated(full_query, period)
        return self._fetch_unpaginated(full_query, period, size)

    def _fetch_paginated(self, query: str, period: Optional[Dict[str, Any]],
                         page_size: int = None) -> List[Dict[str, Any]]:
        """
        Fetch tickets with pagination using demisto-py SDK.

        Args:
            query: XSOAR query string
            period: Optional time period filter
            page_size: Number of results per page (default from env var or 2000)

        Returns:
            List of all fetched incident dictionaries

        Note:
            Page size can be controlled via XSOAR_PAGE_SIZE env var.
            Smaller pages (1000-2000) are better for slow networks.
            Larger pages (5000) are better for fast networks.
        """
        # Use default page size if not specified
        if page_size is None:
            page_size = TicketHandler.DEFAULT_PAGE_SIZE
        all_tickets = []
        page = 0
        max_pages = 100
        server_error_retry_count = 0
        max_server_error_retries = 3

        # Create progress bar if running interactively (not in a non-TTY environment)
        # Can be forced via FORCE_PROGRESS_BAR=true environment variable for PyCharm
        use_progress_bar = sys.stdout.isatty() or os.getenv('FORCE_PROGRESS_BAR', '').lower() == 'true'
        pbar = tqdm(
            desc="Fetching tickets",
            unit=" tickets",
            disable=not use_progress_bar,
            position=0,
            leave=True,
            dynamic_ncols=True,
            bar_format='{desc}: {n_fmt} tickets [{elapsed}, {rate_fmt}]'
        ) if use_progress_bar else None

        # Log start of pagination for visibility (only log when no progress bar to avoid interference)
        if not use_progress_bar:
            log.debug(f"Starting paginated fetch with page_size={page_size}, max_pages={max_pages}")
            log.debug("Running in non-TTY mode (no progress bar), will log each page...")

        try:
            while page < max_pages:
                filter_data: Dict[str, Any] = {
                    "query": query,
                    "page": page,
                    "size": page_size,
                    "sort": [{"field": "created", "asc": False}]
                }
                if period:
                    filter_data["period"] = period

                # Log at DEBUG level (only when no progress bar)
                if not use_progress_bar:
                    log.debug(f"Fetching page {page} (size: {page_size})...")
                    log.debug(f"  Making API call to XSOAR at {datetime.now().strftime('%H:%M:%S')}...")
                else:
                    log.debug(f"Fetching page {page} (size: {page_size})...")

                try:
                    # Use search_incidents method from demisto-py
                    search_data = SearchIncidentsData(filter=filter_data)
                    if not use_progress_bar:
                        log.debug(f"  Sending request to search_incidents endpoint...")

                    request_start = time.time()
                    response = self.client.search_incidents(filter=search_data)
                    request_time = time.time() - request_start

                    if not use_progress_bar:
                        log.debug(f"  ✓ API response received in {request_time:.2f}s at {datetime.now().strftime('%H:%M:%S')}")
                    else:
                        log.debug(f"Page {page} fetch completed in {request_time:.2f}s")

                    # Reset error counter on success
                    server_error_retry_count = 0

                    # Extract data from response and convert to dicts for backward compatibility
                    raw_data = response.data if hasattr(response, 'data') else []
                    if not raw_data:
                        if not use_progress_bar:
                            log.debug("No more data returned, pagination complete")
                        break

                    # Convert model objects to dictionaries
                    data = [item.to_dict() if hasattr(item, 'to_dict') else item for item in raw_data]
                    all_tickets.extend(data)

                    # Update progress bar
                    if pbar is not None:
                        pbar.update(len(data))
                        pbar.set_postfix({"pages": page + 1, "total": len(all_tickets)})

                    # Show progress - log every page for better VM visibility
                    if not use_progress_bar:
                        log.debug(f"  ✓ Page {page} complete: fetched {len(data)} tickets (total: {len(all_tickets)})")
                    else:
                        log.debug(f"Fetched page {page}: {len(data)} tickets (total so far: {len(all_tickets)})")

                    # Check if we've reached the end
                    if len(data) < page_size:
                        if not use_progress_bar:
                            log.debug(f"Pagination complete: fetched {len(all_tickets)} total tickets across {page + 1} pages")
                        break

                    # Delay between pages to avoid rate limiting
                    if page > 0:
                        time.sleep(1.0)

                    page += 1

                except (RemoteDisconnected, ProtocolError, ConnectionError, requests.exceptions.ConnectionError) as e:
                    # Handle connection errors with retry
                    server_error_retry_count += 1
                    if server_error_retry_count > max_server_error_retries:
                        log.error(f"Exceeded max connection error retries ({max_server_error_retries})")
                        break

                    backoff_time = 5 * (2 ** (server_error_retry_count - 1))
                    log.warning(f"Connection error on page {page}: {type(e).__name__}: {e}. "
                                f"Retry {server_error_retry_count}/{max_server_error_retries}. "
                                f"Backing off for {backoff_time} seconds...")
                    time.sleep(backoff_time)
                    continue  # Retry same page

                except ApiException as e:
                    # Handle server errors (502, 503, 504) with retry
                    if e.status in [502, 503, 504]:
                        server_error_retry_count += 1
                        if server_error_retry_count > max_server_error_retries:
                            log.error(f"Exceeded max server error retries ({max_server_error_retries}) for status {e.status}")
                            break

                        backoff_time = 5 * (2 ** (server_error_retry_count - 1))
                        log.warning(f"Server error {e.status} on page {page}. "
                                    f"Retry {server_error_retry_count}/{max_server_error_retries}. "
                                    f"Backing off for {backoff_time} seconds...")
                        time.sleep(backoff_time)
                        continue  # Retry same page

                    # Handle rate limiting
                    elif e.status == 429:
                        backoff_time = 10  # Wait 10 seconds for rate limiting
                        log.warning(f"Rate limit hit (429) on page {page}. Backing off for {backoff_time} seconds...")
                        time.sleep(backoff_time)
                        continue  # Retry same page

                    else:
                        # Other errors - log and break
                        log.error(f"API error on page {page}: {e}")
                        break

            if page >= max_pages:
                log.warning(f"Reached max_pages limit ({max_pages}). Total: {len(all_tickets)} tickets - there may be more data")

            if pbar is not None:
                pbar.close()

            log.debug(f"✓ Fetch complete: {len(all_tickets)} total tickets retrieved")
            return all_tickets

        except Exception as e:
            if pbar is not None:
                pbar.close()
            log.error(f"Error in _fetch_paginated: {str(e)}")
            log.error(f"Query that failed: {query}")
            log.debug(f"Returning {len(all_tickets)} tickets collected before error")
            return all_tickets  # Return what we have so far

    def _fetch_unpaginated(self, query, period, size):
        """Fetch tickets directly from XSOAR API using demisto-py SDK (single page, no pagination)"""
        filter_data: Dict[str, Any] = {
            "query": query,
            "page": 0,
            "size": size,
            "sort": [{"field": "created", "asc": False}]
        }
        if period:
            filter_data["period"] = period

        max_retries = 3
        server_error_retry_count = 0

        try:
            log.debug(f"API Request filter: {json.dumps(filter_data, indent=2)}")

            while server_error_retry_count <= max_retries:
                try:
                    search_data = SearchIncidentsData(filter=filter_data)
                    response = self.client.search_incidents(filter=search_data)
                    raw_data = response.data if hasattr(response, 'data') else []
                    # Convert model objects to dictionaries for backward compatibility
                    data = [item.to_dict() if hasattr(item, 'to_dict') else item for item in raw_data]
                    return data

                except ApiException as e:
                    # Handle server errors with retry
                    if e.status in [502, 503, 504]:
                        server_error_retry_count += 1
                        if server_error_retry_count > max_retries:
                            log.error(f"Exceeded max retries ({max_retries}) for status {e.status}")
                            return []

                        backoff_time = 5 * (2 ** (server_error_retry_count - 1))
                        log.warning(f"Server error {e.status}. "
                                    f"Retry {server_error_retry_count}/{max_retries}. "
                                    f"Backing off for {backoff_time} seconds...")
                        time.sleep(backoff_time)
                        continue

                    elif e.status == 429:
                        backoff_time = 10
                        log.warning(f"Rate limit hit (429). Backing off for {backoff_time} seconds...")
                        time.sleep(backoff_time)
                        continue

                    else:
                        log.error(f"API error: {e}")
                        return []

        except Exception as e:
            log.error(f"Error in _fetch_unpaginated: {str(e)}")
            log.error(f"Query that failed: {query}")
            return []

    def get_entries(self, incident_id: str) -> List[Dict[str, Any]]:
        """
        Fetch entries (comments, notes) for a given incident.

        Args:
            incident_id: The XSOAR incident ID

        Returns:
            List of entry dictionaries

        Raises:
            ApiException: If API call fails
        """
        try:
            response = self.client.generic_request(
                path=f'/incidents/{incident_id}/entries',
                method='GET'
            )
            data = json.loads(response[0]) if response else {}
            return data.get('data', [])
        except ApiException as e:
            log.error(f"Error fetching entries for incident {incident_id}: {e}")
            raise

    def create(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new incident in XSOAR.

        Args:
            payload: Incident data dictionary

        Returns:
            Created incident data

        Raises:
            ApiException: If incident creation fails
        """
        payload.update({"all": True, "createInvestigation": True, "force": True})
        try:
            response = self.client.create_incident(create_incident_request=payload)
            return response.to_dict() if hasattr(response, 'to_dict') else response
        except ApiException as e:
            log.error(f"Error creating incident: {e}")
            raise

    def update_incident(self, ticket_id: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update an existing incident in XSOAR using POST /incident endpoint.

        Args:
            ticket_id: The XSOAR incident ID to update
            update_data: Dictionary of fields to update

        Returns:
            Updated incident data dictionary

        Example:
            update_data = {
                "owner": "user@example.com",
                "status": 1
            }

        Note:
            - Fetches current incident version for optimistic locking
            - The id field is automatically added if not present
        """
        # Fetch current incident data to get the latest version and merge with updates
        case_data = self.get_case_data(ticket_id)
        current_version = case_data.get('version')

        log.debug(f"Fetched current version {current_version} for incident {ticket_id}")

        # Start with all current case data, then apply updates on top
        # This preserves all existing fields that aren't being changed
        merged_data = case_data.copy()
        merged_data.update(update_data)
        merged_data['id'] = ticket_id
        merged_data['version'] = current_version

        log.debug(f"Updating incident {ticket_id} with merged data")

        try:
            response = self.client.generic_request(
                path='/incident',
                method='POST',
                body=merged_data
            )
            log.debug(f"Successfully updated incident {ticket_id}")
            return _parse_generic_response(response)
        except ApiException as e:
            log.error(f"Error updating incident {ticket_id}: {e}")
            raise

    def assign_owner(self, ticket_id: str, owner_email_address: str) -> Dict[str, Any]:
        """Assigns an owner to the specified ticket."""
        log.debug(f"Assigning owner {owner_email_address} to ticket {ticket_id}")
        return self.update_incident(ticket_id, {"owner": owner_email_address})

    def link_tickets(self, parent_ticket_id: str, link_ticket_id: str) -> Optional[Dict[str, Any]]:
        """
        Links the source ticket to the newly created QA ticket in XSOAR.

        Args:
            parent_ticket_id: The parent ticket ID
            link_ticket_id: The ticket ID to link to parent

        Returns:
            Response data or None if failed
        """
        if not link_ticket_id or not parent_ticket_id:
            log.error("Ticket ID or QA Ticket ID is empty. Cannot link tickets.")
            return None

        log.debug(f"Linking ticket {link_ticket_id} to QA ticket {parent_ticket_id}")

        entry_data = {
            "id": "",
            "version": 0,
            "investigationId": parent_ticket_id,
            "data": "!linkIncidents",
            "args": {
                "linkedIncidentIDs": {
                    "simple": link_ticket_id
                }
            },
            "markdown": False,
        }

        try:
            response = self.client.generic_request(
                path='/xsoar/entry',
                method='POST',
                body=entry_data
            )
            return _parse_generic_response(response)
        except ApiException as e:
            log.error(f"Error linking tickets: {e}")
            return None

    def add_participant(self, ticket_id: str, participant_email_address: str) -> Optional[Dict[str, Any]]:
        """
        Adds a participant to the incident.

        Args:
            ticket_id: The incident ID
            participant_email_address: Email address of participant to add

        Returns:
            Response data or None if failed
        """
        if not ticket_id or not participant_email_address:
            log.error("Ticket ID or participant email is empty. Cannot add participant.")
            return None

        log.debug(f"Adding participant {participant_email_address} to ticket {ticket_id}")

        entry_data = {
            "id": "",
            "version": 0,
            "investigationId": ticket_id,
            "data": f"@{participant_email_address}",
            "args": None,
            "markdown": False,
        }

        try:
            response = self.client.generic_request(
                path='/xsoar/entry',
                method='POST',
                body=entry_data
            )
            return _parse_generic_response(response)
        except ApiException as e:
            log.error(f"Error adding participant: {e}")
            return None

    def get_participants(self, incident_id: str) -> List[Dict[str, Any]]:
        """
        Get participants (users) for a given incident.

        Args:
            incident_id: The incident ID

        Returns:
            List of participant dictionaries

        Raises:
            ValueError: If investigation not found
            ApiException: If API call fails
        """
        if not incident_id:
            log.error("Incident ID is empty. Cannot get participants.")
            return []

        log.debug(f"Getting participants for incident {incident_id}")

        try:
            response = self.client.generic_request(
                path=f'/investigation/{incident_id}',
                method='POST',
                body={}
            )
            investigation_data = json.loads(response[0]) if response else {}
            return investigation_data.get('users', [])

        except ApiException as e:
            if e.status == 400 and 'Could not find investigation' in str(e):
                log.warning(f"Investigation {incident_id} not found")
                raise ValueError(f"Investigation {incident_id} not found")
            else:
                log.error(f"API error {e.status}: {e}")
                raise

    def get_playbook_task_id(self, ticket_id, target_task_name):
        """
        Search for a task by name in the playbook, including sub-playbooks.

        Args:
            ticket_id: The XSOAR incident/investigation ID
            target_task_name: Name of the task to find

        Returns:
            Task ID if found, None otherwise
        """
        try:
            response = self.client.generic_request(
                path=f'/investigation/{ticket_id}/workplan',
                method='GET'
            )
        except ApiException as e:
            log.error(f"Error fetching workplan for ticket {ticket_id}: {e}")
            return None

        data = _parse_generic_response(response)
        tasks = data.get('invPlaybook', {}).get('tasks', {})

        # Recursive function to search through tasks and sub-playbooks
        def search_tasks(tasks_dict, depth=0):
            for k, v in tasks_dict.items():
                task_info = v.get('task', {})
                playbook_task_id = v.get('id')
                found_task_name = task_info.get('name')

                # Check if this is the task we're looking for
                if found_task_name == target_task_name:
                    log.debug(f"Found task '{target_task_name}' with ID: {playbook_task_id} in ticket {ticket_id}")
                    return playbook_task_id

                # Check if this task has a sub-playbook
                if 'subPlaybook' in v:
                    sub_tasks = v.get('subPlaybook', {}).get('tasks', {})
                    if sub_tasks:
                        result = search_tasks(sub_tasks, depth + 1)
                        if result:
                            return result

            return None

        # Search through all tasks recursively
        task_id = search_tasks(tasks)

        if not task_id:
            log.warning(f"Task '{target_task_name}' not found in ticket {ticket_id}")

        return task_id

    def complete_task(self, ticket_id, task_name, task_input=''):
        """
        Complete a task in a playbook.

        Args:
            ticket_id: The XSOAR incident/investigation ID
            task_name: Name of the task to complete
            task_input: Optional input/completion message for the task

        Returns:
            Response from the API
        """
        log.debug(f"Completing task {task_name} in the ticket {ticket_id} with response: {task_input}")

        task_id = self.get_playbook_task_id(ticket_id, task_name)
        if not task_id:
            log.error(f"Task '{task_name}' not found in ticket {ticket_id}")
            raise ValueError(f"Task '{task_name}' not found in ticket {ticket_id}")

        # Build full URL using instance variables set during initialization
        url = f'{self.base_url}/inv-playbook/task/complete'

        try:
            # Use requests_toolbelt for proper multipart encoding
            from requests_toolbelt.multipart.encoder import MultipartEncoder

            # Build multipart/form-data payload
            multipart_data = MultipartEncoder(
                fields={
                    'investigationId': ticket_id,
                    'fileName': '',
                    'fileComment': 'Completing via API',
                    'taskId': task_id,
                    'taskInput': task_input
                }
            )

            headers = {
                'Authorization': self.auth_key,
                'x-xdr-auth-id': self.auth_id,
                'Content-Type': multipart_data.content_type,
                'Accept': 'application/json'
            }

            response = requests.post(url, data=multipart_data, headers=headers, verify=False, timeout=30)
            response.raise_for_status()

            # Parse response and check for XSOAR-specific errors
            if response.text:
                response_data = response.json()

                # Check if response contains an error field
                if isinstance(response_data, dict) and 'error' in response_data:
                    error_msg = response_data['error']

                    # Check for "Task is completed already" error
                    if 'Task is completed already' in str(error_msg):
                        log.warning(f"Task '{task_name}' (ID: {task_id}) in ticket {ticket_id} is already completed: {error_msg}")
                        raise ValueError(f"Task '{task_name}' is already completed: {error_msg}")
                    else:
                        log.error(f"Error from XSOAR when completing task '{task_name}': {error_msg}")
                        raise ValueError(f"XSOAR error: {error_msg}")

                log.debug(f"Successfully completed task '{task_name}' (ID: {task_id}) in ticket {ticket_id}")
                return response_data
            else:
                log.debug(f"Successfully completed task '{task_name}' (ID: {task_id}) in ticket {ticket_id}")
                return {}
        except requests.exceptions.RequestException as e:
            log.error(f"Error completing task '{task_name}' in ticket {ticket_id}: {e}")
            raise

    def create_in_dev(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new incident in dev XSOAR with cleaned payload.

        Args:
            payload: Incident data dictionary

        Returns:
            Created incident data or error dictionary
        """
        log.debug("Creating incident in dev environment")
        # Clean payload for dev creation
        for key in ['id', 'phase', 'status', 'roles']:
            payload.pop(key, None)

        payload.update({"all": True, "createInvestigation": True, "force": True})

        # Set default values if not present
        security_category = payload.get("CustomFields", {}).get("securitycategory")
        if not security_category:
            if "CustomFields" not in payload:
                payload["CustomFields"] = {}
            payload["CustomFields"]["securitycategory"] = "CAT-5: Scans/Probes/Attempted Access"

        hunt_source = payload.get("CustomFields", {}).get("huntsource")
        if not hunt_source:
            payload["CustomFields"]["huntsource"] = "Other"

        sla_breach_reason = payload.get("CustomFields", {}).get("slabreachreason")
        if not sla_breach_reason:
            payload["CustomFields"]["slabreachreason"] = "Place Holder - To be updated by SOC"

        try:
            response = self.client.create_incident(create_incident_request=payload)
            return response.to_dict() if hasattr(response, 'to_dict') else response
        except ApiException as e:
            log.error(f"Error creating incident in dev: {e}")
            return {"error": str(e)}

    def get_case_data(self, incident_id: str, max_retries: int = 3) -> Dict[str, Any]:
        """
        Fetch incident details.

        Args:
            incident_id: The XSOAR incident ID
            max_retries: Maximum number of retry attempts for rate limiting/server errors

        Returns:
            Dictionary containing incident details

        Raises:
            ApiException: If API call fails after all retries
        """
        retry_count = 0

        while retry_count <= max_retries:
            try:
                # Use generic_request to load incident
                response = self.client.generic_request(
                    path=f'/incident/load/{incident_id}',
                    method='GET'
                )
                return _parse_generic_response(response)
            except ApiException as e:
                # Handle rate limiting (429)
                if e.status == 429:
                    retry_count += 1
                    if retry_count > max_retries:
                        log.error(f"Exceeded max retries ({max_retries}) for incident {incident_id} due to rate limiting")
                        raise

                    backoff_time = 5 * (2 ** (retry_count - 1))
                    log.warning(f"Rate limit hit (429) for incident {incident_id}. "
                                f"Retry {retry_count}/{max_retries}. "
                                f"Backing off for {backoff_time} seconds...")
                    time.sleep(backoff_time)
                    continue

                # Handle server errors (502, 503, 504)
                elif e.status in [502, 503, 504]:
                    retry_count += 1
                    if retry_count > max_retries:
                        log.error(f"Exceeded max retries ({max_retries}) for incident {incident_id} due to server error {e.status}")
                        raise

                    backoff_time = 5 * (2 ** (retry_count - 1))
                    log.warning(f"Server error {e.status} for incident {incident_id}. "
                                f"Retry {retry_count}/{max_retries}. "
                                f"Backing off for {backoff_time} seconds...")
                    time.sleep(backoff_time)
                    continue

                # For other errors, log and raise immediately
                else:
                    log.error(f"Error fetching incident {incident_id}: {e}")
                    raise

        # Should not reach here, but just in case
        raise ApiException(f"Failed to fetch incident {incident_id} after {max_retries} retries")

    def get_case_data_with_notes(self, incident_id: str, max_retries: int = 3) -> Dict[str, Any]:
        """
        Fetch incident details along with notes.

        Args:
            incident_id: The XSOAR incident ID
            max_retries: Maximum number of retry attempts for rate limiting/server errors

        Returns:
            Dictionary containing incident investigation data with notes

        Raises:
            ApiException: If API call fails after all retries
        """
        retry_count = 0

        while retry_count <= max_retries:
            try:
                response = self.client.generic_request(
                    path=f'/investigation/{incident_id}',
                    method='POST',
                    body={}
                )
                return _parse_generic_response(response)
            except ApiException as e:
                # Handle rate limiting (429)
                if e.status == 429:
                    retry_count += 1
                    if retry_count > max_retries:
                        log.error(f"Exceeded max retries ({max_retries}) for investigation {incident_id} due to rate limiting")
                        raise

                    # Exponential backoff for rate limiting
                    backoff_time = 5 * (2 ** (retry_count - 1))
                    log.warning(f"Rate limit hit (429) for investigation {incident_id}. "
                                f"Retry {retry_count}/{max_retries}. "
                                f"Backing off for {backoff_time} seconds...")
                    time.sleep(backoff_time)
                    continue

                # Handle server errors (502, 503, 504)
                elif e.status in [502, 503, 504]:
                    retry_count += 1
                    if retry_count > max_retries:
                        log.error(f"Exceeded max retries ({max_retries}) for investigation {incident_id} due to server error {e.status}")
                        raise

                    backoff_time = 5 * (2 ** (retry_count - 1))
                    log.warning(f"Server error {e.status} for investigation {incident_id}. "
                                f"Retry {retry_count}/{max_retries}. "
                                f"Backing off for {backoff_time} seconds...")
                    time.sleep(backoff_time)
                    continue

                # For other errors, log and raise immediately
                else:
                    log.error(f"Error fetching investigation {incident_id}: {e}")
                    raise

        # Should not reach here, but just in case
        raise ApiException(f"Failed to fetch investigation {incident_id} after {max_retries} retries")

    def get_user_notes(self, incident_id: str) -> List[Dict[str, str]]:
        """
        Fetch user notes for a given incident.

        Args:
            incident_id: The XSOAR incident ID

        Returns:
            List of formatted notes with note_text, author, and created_at fields,
            sorted with latest note first
        """
        case_data_with_notes = self.get_case_data_with_notes(incident_id)
        entries = case_data_with_notes.get('entries', [])
        user_notes = [entry for entry in entries if entry.get('note')]

        # Format notes with required fields
        et_tz = pytz.timezone('America/New_York')
        formatted_notes = []
        for note in user_notes:
            # Parse ISO format timestamp
            created_str = note.get('created', '')
            if created_str:
                # Parse ISO 8601 format: "2025-10-23T22:24:17.48233Z"
                dt_utc = datetime.fromisoformat(created_str.replace('Z', '+00:00'))
                dt_et = dt_utc.astimezone(et_tz)
                created_at = dt_et.strftime('%m/%d/%Y %I:%M %p ET')
            else:
                created_at = ''

            formatted_notes.append({
                'note_text': note.get('contents', ''),
                'author': note.get('user', 'DBot'),
                'created_at': created_at
            })

        # Return with latest note first
        return list(reversed(formatted_notes))

    def _create_entry(self, incident_id: str, entry_data: str, endpoint: str,
                      markdown: bool, max_retries: int = 3) -> Dict[str, Any]:
        """
        Internal helper method to create an entry in an existing ticket with retry logic.

        Args:
            incident_id: The XSOAR incident ID
            entry_data: The entry content (note text or command)
            endpoint: API endpoint ('/xsoar/entry/note' or '/xsoar/entry')
            markdown: Whether to render the entry as markdown
            max_retries: Maximum number of retry attempts for rate limiting/server errors

        Returns:
            Response data from the API

        Raises:
            ValueError: If incident_id or entry_data is empty
            ApiException: If API call fails after all retries
        """
        # Validate inputs
        if not incident_id:
            raise ValueError("incident_id cannot be empty")
        if not entry_data:
            raise ValueError("entry_data cannot be empty")

        retry_count = 0

        while retry_count <= max_retries:
            try:
                payload = {
                    "id": "",
                    "version": 0,
                    "investigationId": incident_id,
                    "data": entry_data,
                    "markdown": markdown,
                }

                response = self.client.generic_request(
                    path=endpoint,
                    method='POST',
                    body=payload
                )
                return _parse_generic_response(response)

            except ApiException as e:
                # Handle rate limiting (429)
                if e.status == 429:
                    retry_count += 1
                    if retry_count > max_retries:
                        log.error(f"Exceeded max retries ({max_retries}) for {endpoint} on incident {incident_id} due to rate limiting")
                        raise

                    backoff_time = 5 * (2 ** (retry_count - 1))
                    log.warning(f"Rate limit hit (429) for {endpoint} on incident {incident_id}. "
                                f"Retry {retry_count}/{max_retries}. "
                                f"Backing off for {backoff_time} seconds...")
                    time.sleep(backoff_time)
                    continue

                # Handle server errors (502, 503, 504)
                elif e.status in [502, 503, 504]:
                    retry_count += 1
                    if retry_count > max_retries:
                        log.error(f"Exceeded max retries ({max_retries}) for {endpoint} on incident {incident_id} due to server error {e.status}")
                        raise

                    backoff_time = 5 * (2 ** (retry_count - 1))
                    log.warning(f"Server error {e.status} for {endpoint} on incident {incident_id}. "
                                f"Retry {retry_count}/{max_retries}. "
                                f"Backing off for {backoff_time} seconds...")
                    time.sleep(backoff_time)
                    continue

                # For other errors, log and raise immediately
                else:
                    log.error(f"Error calling {endpoint} for incident {incident_id}: {e}")
                    raise

        # Should not reach here, but just in case
        raise ApiException(f"Failed to create entry at {endpoint} for incident {incident_id} after {max_retries} retries")

    def create_new_entry_in_existing_ticket(self, incident_id: str, entry_data: str,
                                            markdown: bool = True) -> Dict[str, Any]:
        """
        Create a new entry (note) in an existing ticket.

        Args:
            incident_id: The XSOAR incident ID
            entry_data: The entry content (note text)
            markdown: Whether to render the entry as markdown (default: True)

        Returns:
            Response data from the API

        Raises:
            ValueError: If incident_id or entry_data is empty
            ApiException: If API call fails after retries

        Example:
            # Add a note
            handler.create_new_entry_in_existing_ticket("123456", "This is a note")

            # Add a note without markdown
            handler.create_new_entry_in_existing_ticket("123456", "Plain text note", markdown=False)
        """
        log.debug(f"Creating new note in ticket {incident_id}")
        result = self._create_entry(incident_id, entry_data, '/xsoar/entry/note', markdown)
        log.debug(f"Successfully created note in ticket {incident_id}")
        return result

    def execute_command_in_war_room(self, incident_id: str, command: str) -> Dict[str, Any]:
        """
        Execute a command in the war room of the specified incident.

        ⚠️ SECURITY WARNING:
        This method executes arbitrary XSOAR commands in the war room.
        Only use with trusted input. Malicious commands could compromise security
        or modify incident data unexpectedly.

        Args:
            incident_id: The XSOAR incident ID
            command: The XSOAR command to execute (e.g., "!ad-get-user username=jdoe")

        Returns:
            Response data from the API

        Raises:
            ValueError: If incident_id or command is empty
            ApiException: If API call fails after retries

        Example:
            # Safe: Query Active Directory user information
            handler.execute_command_in_war_room("123456", "!ad-get-user username=user")

            # Safe: Get incident context
            handler.execute_command_in_war_room("123456", "!Print value=${incident}")

            # WARNING: Be careful with commands that modify data
            # Only execute with validated/sanitized input

        Note:
            - Commands are executed in the incident's war room context
            - Command execution is logged at DEBUG level
            - Supports all XSOAR automation commands available in the war room
        """
        log.debug(f"Executing war room command in ticket {incident_id}: {command}")
        result = self._create_entry(incident_id, command, '/xsoar/entry', markdown=False)
        log.debug(f"Successfully executed command '{command}' in ticket {incident_id}")
        return result

    def upload_file_to_ticket(self, incident_id: str, file_path: str,
                              comment: str = "",
                              is_note_entry: bool = False,
                              show_media_files: bool = False,
                              tags: str = "") -> Dict[str, Any]:
        """
        Upload a file to the specified ticket's war room.

        Args:
            incident_id: The XSOAR incident ID
            file_path: Path to the file to upload
            comment: Optional comment for the file upload (fileComment field)
            is_note_entry: Whether to show this as a note entry (default: False)
            show_media_files: Whether to show media files (default: False)
            tags: Comma-separated tags for the file

        Returns:
            Response data from the API

        Raises:
            ValueError: If incident_id or file_path is empty
            FileNotFoundError: If the file doesn't exist
            ApiException: If API call fails

        Example:
            handler.upload_file_to_ticket("123456", "/path/to/file.txt",
                                         comment="Investigation evidence",
                                         tags="evidence,malware")

        Reference:
            https://cortex-panw.stoplight.io/docs/cortex-xsoar-8/0csr093bgycdh-upload-content-to-an-incident-war-room-entry
        """
        import os

        # Validate inputs
        if not incident_id:
            raise ValueError("incident_id cannot be empty")
        if not file_path:
            raise ValueError("file_path cannot be empty")
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        log.debug(f"Uploading file {file_path} to ticket {incident_id}")

        # Build full URL - base_url already includes /xsoar/public/v1
        url = f'{self.base_url}/entry/upload/{incident_id}'

        # Get file name from path
        file_name = os.path.basename(file_path)

        try:
            # Use requests_toolbelt for proper multipart encoding
            from requests_toolbelt.multipart.encoder import MultipartEncoder

            # Prepare multipart form data
            with open(file_path, 'rb') as f:
                file_content = f.read()

            file_size = len(file_content)
            log.debug(f"File size: {file_size} bytes")

            multipart_data = MultipartEncoder(
                fields={
                    'file': (file_name, file_content, 'application/octet-stream'),
                    'fileComment': comment,
                    'isNoteEntry': str(is_note_entry).lower(),
                    'showMediaFiles': str(show_media_files).lower(),
                    'tags': tags
                }
            )

            # Prepare headers with correct Content-Type from encoder
            headers = {
                'Authorization': self.auth_key,
                'x-xdr-auth-id': self.auth_id,
                'Content-Type': multipart_data.content_type,
                'Accept': 'application/json'
            }

            response = requests.post(
                url,
                data=multipart_data,
                headers=headers,
                verify=False,
                timeout=60
            )

            response.raise_for_status()

            # Parse response
            if response.text:
                try:
                    response_data = response.json()
                except json.JSONDecodeError:
                    log.warning(f"Could not parse response as JSON: {response.text}")
                    response_data = {"raw_response": response.text}

                # Check for XSOAR-specific errors
                if isinstance(response_data, dict) and 'error' in response_data:
                    error_msg = response_data['error']
                    log.error(f"Error from XSOAR when uploading file to ticket {incident_id}: {error_msg}")
                    raise ValueError(f"XSOAR error: {error_msg}")

                log.debug(f"Successfully uploaded file {file_name} to ticket {incident_id}")
                return response_data
            else:
                log.debug(f"Successfully uploaded file {file_name} to ticket {incident_id}")
                return {}

        except requests.exceptions.RequestException as e:
            log.error(f"Error uploading file to ticket {incident_id}: {e}")
            raise
        except (IOError, OSError) as e:
            log.error(f"Error reading file {file_path}: {e}")
            raise


class ListHandler:
    """Handler for XSOAR list operations."""

    def __init__(self, environment: XsoarEnvironment = XsoarEnvironment.PROD):
        """
        Initialize ListHandler with XSOAR environment.

        Args:
            environment: XsoarEnvironment enum (PROD or DEV), defaults to PROD
        """
        if environment == XsoarEnvironment.PROD:
            self.client = prod_client
        elif environment == XsoarEnvironment.DEV:
            self.client = dev_client
        else:
            raise ValueError(f"Invalid environment: {environment}. Must be XsoarEnvironment.PROD or XsoarEnvironment.DEV")

    def get_all_lists(self) -> List[Dict[str, Any]]:
        """
        Get all lists from XSOAR.

        Returns:
            List of XSOAR list dictionaries
        """
        import inspect
        import time

        # Get caller information for debugging
        caller_frame = inspect.currentframe().f_back
        caller_info = inspect.getframeinfo(caller_frame)
        caller_function = caller_frame.f_code.co_name
        caller_file = caller_info.filename.split('/')[-1] if caller_info.filename else 'unknown'

        start_time = time.time()
        log.debug(f"get_all_lists() called by {caller_file}:{caller_function}() at line {caller_info.lineno}")

        try:
            log.debug(f"Making request to /lists endpoint...")
            response = self.client.generic_request(
                path='/lists',
                method='GET'
            )
            elapsed = time.time() - start_time
            log.debug(f"get_all_lists() completed successfully in {elapsed:.2f}s")

            result = _parse_generic_response(response)
            # Result should be a list, but if it's a dict, return empty list
            return result if isinstance(result, list) else []
        except ApiException as e:
            elapsed = time.time() - start_time
            log.error(f"Error in get_all_lists after {elapsed:.2f}s (called by {caller_file}:{caller_function}): {e}")
            return []
        except Exception as e:
            elapsed = time.time() - start_time
            log.error(f"Unexpected error in get_all_lists after {elapsed:.2f}s (called by {caller_file}:{caller_function}): {e}")
            return []

    def get_list_data_by_name(self, list_name):
        """Get list data by name"""
        all_lists = self.get_all_lists()
        list_item = next((item for item in all_lists if item['id'] == list_name), None)
        if list_item is None:
            log.warning(f"List '{list_name}' not found")
            return None
        try:
            return json.loads(list_item['data'])
        except (TypeError, json.JSONDecodeError):
            return list_item['data']

    def get_list_version_by_name(self, list_name):
        """Get list version by name"""
        all_lists = self.get_all_lists()
        list_item = next((item for item in all_lists if item['id'] == list_name), None)
        if list_item is None:
            log.warning(f"List '{list_name}' not found")
            return None
        return list_item['version']

    def save(self, list_name: str, list_data: Any) -> Dict[str, Any]:
        """
        Save list data to XSOAR.

        Args:
            list_name: Name of the list
            list_data: Data to save (will be JSON serialized)

        Returns:
            Response data from save operation

        Raises:
            ApiException: If save operation fails
        """
        list_version = self.get_list_version_by_name(list_name)

        payload = {
            "data": json.dumps(list_data, indent=4),
            "name": list_name,
            "type": "json",
            "id": list_name,
            "version": list_version
        }

        try:
            response = self.client.generic_request(
                path='/lists/save',
                method='POST',
                body=payload
            )
            return _parse_generic_response(response)
        except ApiException as e:
            log.error(f"Error saving list: {e}")
            raise

    def save_as_text(self, list_name: str, list_data: List[str]) -> Dict[str, Any]:
        """
        Save list data as plain text (comma-separated string).

        Args:
            list_name: Name of the list
            list_data: List of strings to save

        Returns:
            Response data from save operation

        Raises:
            ApiException: If save operation fails
        """
        list_version = self.get_list_version_by_name(list_name)
        payload = {
            "data": ','.join(list_data),
            "name": list_name,
            "type": "text",
            "id": list_name,
            "version": list_version
        }

        try:
            response = self.client.generic_request(
                path='/lists/save',
                method='POST',
                body=payload
            )
            return _parse_generic_response(response)
        except ApiException as e:
            log.error(f"Error saving list as text: {e}")
            raise

    def add_item_to_list(self, list_name, new_entry):
        """Add item to existing list"""
        list_data = self.get_list_data_by_name(list_name)
        list_data.append(new_entry)
        self.save(list_name, list_data)


def main():
    """
    Main function that demonstrates core functionality of this module.

    Example usage:
        # Use prod environment (default)
        prod_handler = TicketHandler()
        prod_handler = TicketHandler(XsoarEnvironment.PROD)

        # Use dev environment
        dev_handler = TicketHandler(XsoarEnvironment.DEV)

        # Same for ListHandler
        prod_list = ListHandler()
        dev_list = ListHandler(XsoarEnvironment.DEV)
    """
    # Example usage (commented out):
    # ticket_id = '1378457'
    # playbook_task_name = 'Does the employee recognize the alerted activity?'
    # dev_ticket_handler = TicketHandler(XsoarEnvironment.DEV)
    # task_id = dev_ticket_handler.get_playbook_task_id(ticket_id, playbook_task_name)
    # print(task_id)

    #
    # Example: Get case data with notes
    # print(json.dumps(dev_ticket_handler.get_case_data_with_notes(ticket_id), indent=4))
    #
    # Example: Complete a task
    # task_name = 'Does the employee recognize the alerted activity?'
    # print(dev_ticket_handler.complete_task(ticket_id, task_name))
    #
    # Example: Create a note
    # print(dev_ticket_handler.create_new_entry_in_existing_ticket(ticket_id, "This is my note"))
    #
    # Example: Execute war room command
    # print(dev_ticket_handler.execute_command_in_war_room(ticket_id, "!ad-get-user username=user"))
    #
    # Example: Upload file
    # file_path = "/path/to/file.pdf"
    # print(dev_ticket_handler.upload_file_to_ticket(ticket_id, file_path, "Evidence file"))

    prod_list_handler = ListHandler(XsoarEnvironment.PROD)
    all_lists = prod_list_handler.get_all_lists()
    print(f"Total lists in dev: {len(all_lists)}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    main()
