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
import requests
import time
from datetime import datetime
from pprint import pprint
from typing import Any, Dict, List, Optional, Tuple

import demisto_client
import pytz
import urllib3
from demisto_client.demisto_api import rest
from demisto_client.demisto_api.models import SearchIncidentsData
from urllib3.exceptions import InsecureRequestWarning

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

# Initialize demisto-py clients for prod and dev environments
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

    def __init__(self, environment: XsoarEnvironment = XsoarEnvironment.PROD):
        """
        Initialize TicketHandler with XSOAR environment.

        Args:
            environment: XsoarEnvironment enum (PROD or DEV), defaults to PROD
        """
        if environment == XsoarEnvironment.PROD:
            self.client = prod_client
        elif environment == XsoarEnvironment.DEV:
            self.client = dev_client
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

        log.debug(f"Making API call for query: {query}")

        if paginate:
            return self._fetch_paginated(full_query, period)
        return self._fetch_unpaginated(full_query, period, size)

    def _fetch_paginated(self, query: str, period: Optional[Dict[str, Any]],
                         page_size: int = 5000) -> List[Dict[str, Any]]:
        """
        Fetch tickets with pagination using demisto-py SDK.

        Args:
            query: XSOAR query string
            period: Optional time period filter
            page_size: Number of results per page

        Returns:
            List of all fetched incident dictionaries
        """
        all_tickets = []
        page = 0
        max_pages = 100
        server_error_retry_count = 0
        max_server_error_retries = 3

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

                log.debug(f"Fetching page {page} with size {page_size}")

                try:
                    # Use search_incidents method from demisto-py
                    search_data = SearchIncidentsData(filter=filter_data)
                    response = self.client.search_incidents(filter=search_data)

                    # Reset error counter on success
                    server_error_retry_count = 0

                    # Extract data from response and convert to dicts for backward compatibility
                    raw_data = response.data if hasattr(response, 'data') else []
                    if not raw_data:
                        break

                    # Convert model objects to dictionaries
                    data = [item.to_dict() if hasattr(item, 'to_dict') else item for item in raw_data]
                    all_tickets.extend(data)

                    # Show progress
                    if page % 5 == 0 or len(data) < page_size:
                        log.debug(f"  Fetched {len(all_tickets)} tickets so far...")
                    log.debug(f"Fetched page {page}: {len(data)} tickets (total so far: {len(all_tickets)})")

                    # Check if we've reached the end
                    if len(data) < page_size:
                        log.debug(f"Completed: {len(all_tickets)} total tickets fetched")
                        break

                    # Delay between pages to avoid rate limiting
                    if page > 0:
                        time.sleep(1.0)

                    page += 1

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
                log.debug(f"Warning: Reached max_pages limit ({max_pages}). Total: {len(all_tickets)} tickets")

            log.debug(f"Total tickets fetched: {len(all_tickets)}")
            return all_tickets

        except Exception as e:
            log.error(f"Error in _fetch_paginated: {str(e)}")
            log.error(f"Query that failed: {query}")
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
            log.info(f"Successfully updated incident {ticket_id}")
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
        response = self.client.generic_request(
            path=f'/investigation/{ticket_id}/workplan',
            method='GET'
        )
        data = _parse_generic_response(response)
        tasks = data.get('invPlaybook', {}).get('tasks', {})

        # Recursive function to search through tasks and sub-playbooks
        def search_tasks(tasks_dict, depth=0):
            for k, v in tasks_dict.items():
                task_info = v.get('task', {})
                task_id = v.get('id')
                found_task_name = task_info.get('name')

                # Check if this is the task we're looking for
                if found_task_name == target_task_name:
                    log.debug(f"Found task '{target_task_name}' with ID: {task_id} in ticket {ticket_id}")
                    return task_id

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

        # Extract credentials from the already-configured client
        base_url = self.client.api_client.configuration.host
        auth_key = self.client.api_client.configuration.api_key.get('authorization')
        auth_id = self.client.api_client.configuration.api_key.get('x-xdr-auth-id')

        # Build full URL
        url = f'{base_url}/xsoar/public/v1/inv-playbook/task/complete'

        # Use the working multipart/form-data format from the custom script
        file_comment = "Completing via API"
        file_name = ""

        # Build multipart/form-data payload manually
        payload = (
            "-----011000010111000001101001\r\n"
            "Content-Disposition: form-data; name=\"investigationId\"\r\n\r\n"
            f"{ticket_id}\r\n"
            "-----011000010111000001101001\r\n"
            "Content-Disposition: form-data; name=\"fileName\"\r\n\r\n"
            f"{file_name}\r\n"
            "-----011000010111000001101001\r\n"
            "Content-Disposition: form-data; name=\"fileComment\"\r\n\r\n"
            f"{file_comment}\r\n"
            "-----011000010111000001101001\r\n"
            "Content-Disposition: form-data; name=\"taskId\"\r\n\r\n"
            f"{task_id}\r\n"
            "-----011000010111000001101001\r\n"
            "Content-Disposition: form-data; name=\"taskInput\"\r\n\r\n"
            f"{task_input}\r\n"
            "-----011000010111000001101001--\r\n"
        )

        headers = {
            'Authorization': auth_key,
            'x-xdr-auth-id': auth_id,
            'Content-Type': 'multipart/form-data; boundary=---011000010111000001101001',
            'Accept': 'application/json'
        }

        try:
            response = requests.post(url, data=payload, headers=headers, verify=False)
            response.raise_for_status()
            log.info(f"Successfully completed task '{task_name}' (ID: {task_id}) in ticket {ticket_id}")

            if response.text:
                return response.json()
            else:
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
        try:
            response = self.client.generic_request(
                path='/lists',
                method='GET'
            )
            result = _parse_generic_response(response)
            # Result should be a list, but if it's a dict, return empty list
            return result if isinstance(result, list) else []
        except ApiException as e:
            log.error(f"Error in get_all_lists: {e}")
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
    # print(json.dumps(get_user_notes('878736'), indent=4))
    ticket_id = '1374341'
    dev_ticket_handler = TicketHandler(XsoarEnvironment.DEV)
    pprint(dev_ticket_handler.get_case_data(ticket_id))

    pprint(dev_ticket_handler.assign_owner(ticket_id, 'user@company.com'))


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    main()
