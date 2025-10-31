"""
XSOAR Service using official demisto-py SDK

This module provides a wrapper around the official demisto-py SDK
to maintain backward compatibility with existing code while leveraging
the official Palo Alto Networks XSOAR Python client.

Migration Date: 2024-10-31
Original: services/xsoar.py.backup
"""
import ast
import json
import logging
import time
from datetime import datetime

import demisto_client
from demisto_client.demisto_api import rest
from demisto_client.demisto_api.models import SearchIncidentsData
import pytz
import urllib3
from urllib3.exceptions import InsecureRequestWarning

from my_config import get_config

# For easier access to ApiException
ApiException = rest.ApiException


def _parse_generic_response(response):
    """
    Parse response from generic_request which returns (body, status, headers) tuple.
    Body might be JSON string or Python repr string.
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


def get_case_data_with_notes(incident_id):
    """Fetch incident details along with notes from prod environment"""
    try:
        response = prod_client.generic_request(
            path=f'/investigation/{incident_id}',
            method='POST',
            body={}
        )
        return _parse_generic_response(response)
    except ApiException as e:
        log.error(f"Error fetching investigation {incident_id}: {e}")
        raise


def get_user_notes(incident_id):
    """Fetch user notes for a given incident from prod environment"""
    case_data_with_notes = get_case_data_with_notes(incident_id)
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


def get_case_data(incident_id):
    """Fetch incident details from prod environment"""
    try:
        # Use generic_request to load incident
        response = prod_client.generic_request(
            path=f'/incident/load/{incident_id}',
            method='GET'
        )
        return _parse_generic_response(response)
    except ApiException as e:
        log.error(f"Error fetching incident {incident_id}: {e}")
        raise


def import_ticket(source_ticket_number, requestor_email_address=None):
    """Import ticket from prod to dev"""
    ticket_handler = TicketHandler()

    incident_data = get_case_data(source_ticket_number)
    if requestor_email_address:
        incident_data['owner'] = requestor_email_address

    new_ticket_data = ticket_handler.create_in_dev(incident_data)

    if 'error' in new_ticket_data:
        return new_ticket_data, ''

    return new_ticket_data['id'], f'{CONFIG.xsoar_dev_ui_base_url}/Custom/caseinfoid/{new_ticket_data["id"]}'


class TicketHandler:
    def __init__(self):
        self.prod_base = CONFIG.xsoar_prod_api_base_url
        self.dev_base = CONFIG.xsoar_dev_api_base_url
        self.client = prod_client
        self.dev_client = dev_client

    def get_tickets(self, query, period=None, size=20000, paginate=True):
        """Fetch security incidents from XSOAR using demisto-py SDK"""
        full_query = query + f' -category:job -type:"{CONFIG.team_name} Ticket QA" -type:"{CONFIG.team_name} SNOW Whitelist Request"'

        log.debug(f"Making API call for query: {query}")

        if paginate:
            return self._fetch_paginated(full_query, period)
        return self._fetch_from_api(full_query, period, size)

    def _fetch_paginated(self, query, period, page_size=5000):
        """Fetch tickets with pagination using demisto-py SDK"""
        all_tickets = []
        page = 0
        max_pages = 100
        server_error_retry_count = 0
        max_server_error_retries = 3

        try:
            while page < max_pages:
                filter_data = {
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

    def _fetch_from_api(self, query, period, size):
        """Fetch tickets directly from XSOAR API using demisto-py SDK"""
        filter_data = {
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
            log.error(f"Error in _fetch_from_api: {str(e)}")
            log.error(f"Query that failed: {query}")
            return []

    def get_entries(self, incident_id):
        """Fetch entries (comments, notes) for a given incident"""
        try:
            response = prod_client.generic_request(
                path=f'/incidents/{incident_id}/entries',
                method='GET'
            )
            data = json.loads(response[0]) if response else {}
            return data.get('data', [])
        except ApiException as e:
            log.error(f"Error fetching entries for incident {incident_id}: {e}")
            raise

    def create(self, payload):
        """Create a new incident in prod XSOAR"""
        payload.update({"all": True, "createInvestigation": True, "force": True})
        try:
            response = self.client.create_incident(create_incident_request=payload)
            return response.to_dict() if hasattr(response, 'to_dict') else response
        except ApiException as e:
            log.error(f"Error creating incident: {e}")
            raise

    def link_tickets(self, parent_ticket_id, link_ticket_id):
        """Links the source ticket to the newly created QA ticket in XSOAR."""
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
            response = prod_client.generic_request(
                path='/xsoar/entry',
                method='POST',
                body=entry_data
            )
            return _parse_generic_response(response)
        except ApiException as e:
            log.error(f"Error linking tickets: {e}")
            return None

    def add_participant(self, ticket_id, participant_email_address):
        """Adds a participant to the incident."""
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
            response = prod_client.generic_request(
                path='/xsoar/entry',
                method='POST',
                body=entry_data
            )
            return _parse_generic_response(response)
        except ApiException as e:
            log.error(f"Error adding participant: {e}")
            return None

    def get_participants(self, incident_id):
        """Get participants (users) for a given incident."""
        if not incident_id:
            log.error("Incident ID is empty. Cannot get participants.")
            return []

        log.debug(f"Getting participants for incident {incident_id}")

        try:
            response = prod_client.generic_request(
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

    def complete_task(self, incident_id, task_id, response_value):
        """Complete a conditional task in a playbook."""
        if not incident_id or not task_id:
            log.error("Incident ID or Task ID is empty. Cannot complete task.")
            return None

        log.info(f"Completing task {task_id} in incident {incident_id} with response: {response_value}")

        try:
            # Use the complete_task method from demisto-py
            task_data = {
                "investigationId": incident_id,
                "id": task_id,
                "data": response_value
            }
            response = self.client.complete_task(task_data=task_data)
            log.info(f"Successfully completed task {task_id} in incident {incident_id}")
            return response.to_dict() if hasattr(response, 'to_dict') else response

        except ApiException as e:
            log.error(f"Error completing task {task_id} in incident {incident_id}: {e}")
            raise

    def create_in_dev(self, payload):
        """Create a new incident in dev XSOAR"""
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
            response = self.dev_client.create_incident(create_incident_request=payload)
            return response.to_dict() if hasattr(response, 'to_dict') else response
        except ApiException as e:
            log.error(f"Error creating incident in dev: {e}")
            return {"error": str(e)}


class ListHandler:
    def __init__(self):
        self.base_url = CONFIG.xsoar_prod_api_base_url
        self.client = prod_client

    def get_all_lists(self):
        """Get all lists from XSOAR"""
        try:
            response = prod_client.generic_request(
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

    def save(self, list_name, list_data):
        """Save list data"""
        list_version = self.get_list_version_by_name(list_name)

        payload = {
            "data": json.dumps(list_data, indent=4),
            "name": list_name,
            "type": "json",
            "id": list_name,
            "version": list_version
        }

        try:
            response = prod_client.generic_request(
                path='/lists/save',
                method='POST',
                body=payload
            )
            return _parse_generic_response(response)
        except ApiException as e:
            log.error(f"Error saving list: {e}")
            raise

    def save_as_text(self, list_name, list_data):
        """Save list data as plain text (comma-separated string)."""
        list_version = self.get_list_version_by_name(list_name)
        payload = {
            "data": ','.join(list_data),
            "name": list_name,
            "type": "text",
            "id": list_name,
            "version": list_version
        }

        try:
            response = prod_client.generic_request(
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
    """Main function that demonstrates core functionality of this module"""
    print(json.dumps(get_user_notes('878736'), indent=4))


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    main()
