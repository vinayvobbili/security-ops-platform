"""
XSOAR Search Operations

Handles ticket search and pagination for XSOAR incidents.
"""
import json
import logging
import os
import socket
import sys
import time
from datetime import datetime
from http.client import RemoteDisconnected
from typing import Any, Dict, List, Optional

import requests
from demisto_client.demisto_api.models import SearchIncidentsData
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn, SpinnerColumn
from urllib3.exceptions import ProtocolError

from ._client import ApiException
from ._retry import truncate_error_message

log = logging.getLogger(__name__)

# Default configuration
DEFAULT_PAGE_SIZE = int(os.getenv('XSOAR_PAGE_SIZE', '2000'))


def test_connectivity(client, base_url: str) -> None:
    """
    Test XSOAR API connectivity with DNS resolution and small query.

    Args:
        client: XSOAR demisto-py client
        base_url: XSOAR API base URL

    Raises:
        Exception: If connectivity test fails
    """
    from urllib.parse import urlparse

    log.debug("Testing DNS resolution for XSOAR API...")
    parsed_url = urlparse(base_url)
    hostname = parsed_url.netloc.split(':')[0]  # Remove port if present

    try:
        start_dns = time.time()
        ip_address = socket.gethostbyname(hostname)
        dns_time = time.time() - start_dns
        log.debug(f"✓ DNS resolved {hostname} -> {ip_address} in {dns_time:.2f}s")
    except socket.gaierror as dns_err:
        log.error(f"✗ DNS resolution failed for {hostname}: {dns_err}")
        log.error("This indicates a DNS configuration problem on this system")
        raise

    log.debug("Testing XSOAR API connectivity with small test query...")
    test_filter = {"query": "id:1", "page": 0, "size": 1}
    test_search = SearchIncidentsData(filter=test_filter)

    start_api = time.time()
    test_response = client.search_incidents(filter=test_search)
    api_time = time.time() - start_api
    log.debug(f"✓ XSOAR API is reachable and responding in {api_time:.2f}s: {type(test_response)}")


def get_tickets(
    client,
    base_url: str,
    query: str,
    team_name: str,
    period: Optional[Dict[str, Any]] = None,
    size: int = 20000,
    paginate: bool = True
) -> List[Dict[str, Any]]:
    """
    Fetch security incidents from XSOAR using demisto-py SDK.

    Args:
        client: XSOAR demisto-py client
        base_url: XSOAR API base URL
        query: XSOAR query string for filtering incidents
        team_name: Team name for filtering excluded ticket types
        period: Optional time period filter
        size: Maximum number of results (used when paginate=False)
        paginate: Whether to fetch all results with pagination

    Returns:
        List of incident dictionaries
    """
    full_query = query + f' -category:job -type:"{team_name} Ticket QA" -type:"{team_name} SNOW Whitelist Request"'

    log.debug(f"get_tickets() called with query: {query[:100]}...")
    log.debug(f"  Paginate: {paginate}, Size: {size}")

    # Quick connectivity test
    try:
        test_connectivity(client, base_url)
    except Exception as e:
        log.error(f"✗ XSOAR API connectivity test failed: {truncate_error_message(e)}")
        log.error("This may indicate network issues, API outage, or authentication problems")
        raise

    if paginate:
        return _fetch_paginated(client, full_query, period)
    return _fetch_unpaginated(client, full_query, period, size)


def _fetch_paginated(
    client,
    query: str,
    period: Optional[Dict[str, Any]],
    page_size: int = None
) -> List[Dict[str, Any]]:
    """
    Fetch tickets with pagination using demisto-py SDK.

    Args:
        client: XSOAR demisto-py client
        query: XSOAR query string
        period: Optional time period filter
        page_size: Number of results per page (default from env var or 2000)

    Returns:
        List of all fetched incident dictionaries
    """
    if page_size is None:
        page_size = DEFAULT_PAGE_SIZE

    all_tickets = []
    page = 0
    max_pages = 100
    server_error_retry_count = 0
    max_server_error_retries = 3

    # Create progress bar if running interactively
    use_progress_bar = sys.stdout.isatty() or os.getenv('FORCE_PROGRESS_BAR', '').lower() == 'true'
    progress = None
    task_id = None
    if use_progress_bar:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TextColumn("{task.completed} tickets"),
            TimeElapsedColumn(),
        )
        task_id = progress.add_task("Fetching tickets", total=None)
        progress.start()

    # Log start of pagination for visibility
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

            # Log at DEBUG level
            if not use_progress_bar:
                log.debug(f"Fetching page {page} (size: {page_size})...")
                log.debug(f"  Making API call to XSOAR at {datetime.now().strftime('%H:%M:%S')}...")
            else:
                log.debug(f"Fetching page {page} (size: {page_size})...")

            try:
                # Use search_incidents method from demisto-py
                search_data = SearchIncidentsData(filter=filter_data)
                if not use_progress_bar:
                    log.debug("  Sending request to search_incidents endpoint...")

                request_start = time.time()
                response = client.search_incidents(filter=search_data)
                request_time = time.time() - request_start

                if not use_progress_bar:
                    log.debug(f"  ✓ API response received in {request_time:.2f}s at {datetime.now().strftime('%H:%M:%S')}")
                else:
                    log.debug(f"Page {page} fetch completed in {request_time:.2f}s")

                # Reset error counter on success
                server_error_retry_count = 0

                # Extract data from response
                raw_data = response.data if hasattr(response, 'data') else []
                if not raw_data:
                    if not use_progress_bar:
                        log.debug("No more data returned, pagination complete")
                    break

                # Convert model objects to dictionaries
                data = [item.to_dict() if hasattr(item, 'to_dict') else item for item in raw_data]
                all_tickets.extend(data)

                # Update progress bar
                if progress is not None:
                    progress.update(task_id, advance=len(data), description=f"Fetching tickets (page {page + 1})")

                # Show progress
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
                    log.error(f"API error on page {page}: {truncate_error_message(e)}")
                    break

        if page >= max_pages:
            log.warning(f"Reached max_pages limit ({max_pages}). Total: {len(all_tickets)} tickets - there may be more data")

        if progress is not None:
            progress.stop()

        log.debug(f"✓ Fetch complete: {len(all_tickets)} total tickets retrieved")
        return all_tickets

    except Exception as e:
        if progress is not None:
            progress.stop()
        log.error(f"Error in _fetch_paginated: {str(e)}")
        log.error(f"Query that failed: {query}")
        log.debug(f"Returning {len(all_tickets)} tickets collected before error")
        return all_tickets  # Return what we have so far


def _fetch_unpaginated(
    client,
    query: str,
    period: Optional[Dict[str, Any]],
    size: int
) -> List[Dict[str, Any]]:
    """
    Fetch tickets directly from XSOAR API using demisto-py SDK (single page, no pagination).

    Args:
        client: XSOAR demisto-py client
        query: XSOAR query string
        period: Optional time period filter
        size: Maximum number of results

    Returns:
        List of incident dictionaries
    """
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
                response = client.search_incidents(filter=search_data)
                raw_data = response.data if hasattr(response, 'data') else []
                # Convert model objects to dictionaries
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
                    log.error(f"API error: {truncate_error_message(e)}")
                    return []

    except Exception as e:
        log.error(f"Error in _fetch_unpaginated: {str(e)}")
        log.error(f"Query that failed: {query}")
        return []

    return []  # Should not reach here, but satisfy return type
