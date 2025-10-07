import json
import logging

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning

from my_config import get_config
from src.utils.http_utils import get_session

urllib3.disable_warnings(InsecureRequestWarning)

CONFIG = get_config()
log = logging.getLogger(__name__)

# Get robust HTTP session instance
http_session = get_session()

prod_headers = {
    'Authorization': CONFIG.xsoar_prod_auth_key,
    'x-xdr-auth-id': CONFIG.xsoar_prod_auth_id,
    'Content-Type': 'application/json'
}

dev_headers = {
    'Authorization': CONFIG.xsoar_dev_auth_key,
    'x-xdr-auth-id': CONFIG.xsoar_dev_auth_id,
    'Content-Type': 'application/json'
}


def get_incident(incident_id):
    """Fetch incident details from prod environment"""
    incident_url = f"{CONFIG.xsoar_prod_api_base_url}/incident/load/{incident_id}"
    response = http_session.get(incident_url, headers=prod_headers, verify=False, timeout=30)
    if response is None:
        raise requests.exceptions.ConnectionError("Failed to connect after multiple retries")
    response.raise_for_status()
    return response.json()


def import_ticket(source_ticket_number, requestor_email_address=None):
    """Import ticket from prod to dev"""
    ticket_handler = TicketHandler()

    incident_data = get_incident(source_ticket_number)
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

    def get_tickets(self, query, period=None, size=20000, paginate=False):
        """Fetch security incidents from XSOAR"""
        full_query = query + f' -category:job -type:"{CONFIG.team_name} Ticket QA" -type:"{CONFIG.team_name} SNOW Whitelist Request"'

        log.debug(f"Making API call for query: {query}")

        if paginate:
            return self._fetch_paginated(full_query, period)
        return self._fetch_from_api(full_query, period, size)

    def _fetch_paginated(self, query, period, page_size=5000):
        """Fetch tickets with pagination to avoid max response size limit"""
        all_tickets = []
        page = 0
        max_pages = 100  # Safety limit to prevent infinite loops

        try:
            while page < max_pages:
                payload = {
                    "filter": {
                        "query": query,
                        "page": page,
                        "size": page_size,
                        "sort": [{"field": "created", "asc": False}]
                    }
                }
                if period:
                    payload["filter"]["period"] = period

                log.debug(f"Fetching page {page} with size {page_size}")

                response = http_session.post(
                    f"{self.prod_base}/incidents/search",
                    headers=prod_headers,
                    json=payload,
                    timeout=300,
                    verify=False
                )
                if response is None:
                    raise requests.exceptions.ConnectionError("Failed to connect after multiple retries")
                response.raise_for_status()

                data = response.json().get('data', [])
                if not data:
                    break  # No more results

                all_tickets.extend(data)
                # Show progress every 5 pages to reduce verbosity
                if page % 5 == 0 or len(data) < page_size:
                    print(f"  Fetched {len(all_tickets)} tickets so far...")
                log.info(f"Fetched page {page}: {len(data)} tickets (total so far: {len(all_tickets)})")

                # If we got fewer results than page_size, we've reached the end
                if len(data) < page_size:
                    print(f"Completed: {len(all_tickets)} total tickets fetched")
                    break

                page += 1

            if page >= max_pages:
                print(f"Warning: Reached max_pages limit ({max_pages}). Total: {len(all_tickets)} tickets")

            log.info(f"Total tickets fetched: {len(all_tickets)}")
            return all_tickets

        except Exception as e:
            log.error(f"Error in _fetch_paginated: {str(e)}")
            log.error(f"Query that failed: {query}")
            if hasattr(e, 'response') and e.response is not None:
                log.error(f"Response status: {e.response.status_code}")
                log.error(f"Response body: {e.response.text}")
            return all_tickets  # Return what we have so far

    def _fetch_from_api(self, query, period, size):
        """Fetch tickets directly from XSOAR API"""
        payload = {
            "filter": {
                "query": query,
                "page": 0,
                "size": size,
                "sort": [{"field": "created", "asc": False}]
            }
        }
        try:
            if period:
                payload["filter"]["period"] = period

            log.debug(f"API Request payload: {json.dumps(payload, indent=2)}")

            response = http_session.post(
                f"{self.prod_base}/incidents/search",
                headers=prod_headers,
                json=payload,
                timeout=300,
                verify=False
            )
            if response is None:
                raise requests.exceptions.ConnectionError("Failed to connect after multiple retries")
            response.raise_for_status()
            return response.json().get('data', [])
        except Exception as e:
            log.error(f"Error in _fetch_from_api: {str(e)}")
            log.error(f"Query that failed: {query}")
            log.error(f"Payload that failed: {json.dumps(payload, indent=2)}")
            if hasattr(e, 'response') and e.response is not None:
                log.error(f"Response status: {e.response.status_code}")
                log.error(f"Response body: {e.response.text}")
            return []

    def get_entries(self, incident_id):
        """Fetch entries (comments, notes) for a given incident"""
        response = http_session.get(
            f"{self.prod_base}/incidents/{incident_id}/entries",
            headers=prod_headers,
            timeout=60,
            verify=False
        )
        if response is None:
            raise requests.exceptions.ConnectionError("Failed to connect after multiple retries")
        response.raise_for_status()
        return response.json().get('data', [])

    def create(self, payload):
        """Create a new incident in prod XSOAR"""
        payload.update({"all": True, "createInvestigation": True, "force": True})
        response = http_session.post(f"{self.prod_base}/incident", headers=prod_headers, json=payload)
        if response is None:
            raise requests.exceptions.ConnectionError("Failed to connect after multiple retries")
        response.raise_for_status()
        return response.json()

    def link_tickets(self, parent_ticket_id, link_ticket_id):

        """
        Links the source ticket to the newly created QA ticket in XSOAR.
        """
        if not link_ticket_id or not parent_ticket_id:
            log.error("Ticket ID or QA Ticket ID is empty. Cannot link tickets.")
            return None
        log.info(f"Linking ticket {link_ticket_id} to QA ticket {parent_ticket_id}")
        payload = {
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
        response = http_session.post(f"{self.prod_base}/xsoar/entry", headers=prod_headers, json=payload)
        return response.json()

    def add_participant(self, ticket_id, participant_email_address):
        """
        Adds a participant to the incident.
        """
        if not ticket_id or not participant_email_address:
            log.error("Ticket ID or participant email is empty. Cannot add participant.")
            return None
        log.info(f"Adding participant {participant_email_address} to ticket {ticket_id}")
        payload = {
            "id": "",
            "version": 0,
            "investigationId": ticket_id,
            "data": f"@{participant_email_address}",
            "args": None,
            "markdown": False,
        }
        response = http_session.post(f"{self.prod_base}/xsoar/entry", headers=prod_headers, json=payload)
        return response.json()

    def get_participants(self, incident_id):
        """
        Get participants (users) for a given incident.
        """
        if not incident_id:
            log.error("Incident ID is empty. Cannot get participants.")
            return []

        log.info(f"Getting participants for incident {incident_id}")
        investigation_url = f"{self.prod_base}/investigation/{incident_id}"

        # Based on the JSON structure from the user's example, send empty payload
        payload = {}

        response = http_session.post(investigation_url, headers=prod_headers, json=payload, verify=False, timeout=30)
        if response is None:
            raise requests.exceptions.ConnectionError("Failed to connect after multiple retries")

        # Handle API errors gracefully
        if not response.ok:
            error_data = response.json() if response.content else {}
            error_msg = error_data.get('detail', 'Unknown error')

            if response.status_code == 400 and 'Could not find investigation' in error_msg:
                log.warning(f"Investigation {incident_id} not found")
                raise ValueError(f"Investigation {incident_id} not found")
            else:
                log.error(f"API error {response.status_code}: {error_msg}")
                raise requests.exceptions.HTTPError(f"API error {response.status_code}: {error_msg}")

        investigation_data = response.json()
        return investigation_data.get('users', [])

    def create_in_dev(self, payload):
        """Create a new incident in dev XSOAR"""

        # Clean payload for dev creation
        for key in ['id', 'phase', 'status', 'roles']:
            payload.pop(key, None)

        payload.update({"all": True, "createInvestigation": True, "force": True})
        security_category = payload["CustomFields"].get("securitycategory")
        if not security_category:
            payload["CustomFields"]["securitycategory"] = "CAT-5: Scans/Probes/Attempted Access"

        hunt_source = payload["CustomFields"].get("huntsource")
        if not hunt_source:
            payload["CustomFields"]["huntsource"] = "Other"

        sla_breach_reason = payload["CustomFields"].get("slabreachreason")
        if not sla_breach_reason:
            payload["CustomFields"]["slabreachreason"] = "Place Holder - To be updated by SOC"

        response = http_session.post(f"{self.dev_base}/incident", headers=dev_headers, json=payload)

        if response is None:
            return {"error": "Failed to connect after multiple retries"}

        if response.ok:
            return response.json()
        else:
            return {"error": response.text}


class ListHandler:
    def __init__(self):
        self.base_url = CONFIG.xsoar_prod_api_base_url

    def get_all_lists(self):
        """Get all lists from XSOAR"""
        try:
            response = http_session.get(f"{self.base_url}/lists", headers=prod_headers, timeout=30, verify=False)
            if response is None:
                raise requests.exceptions.ConnectionError("Failed to connect after multiple retries")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            log.error(f"Error in get_all_lists: {str(e)}")
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

        response = http_session.post(f"{self.base_url}/lists/save", headers=prod_headers, json=payload)
        if response is None:
            raise requests.exceptions.ConnectionError("Failed to connect after multiple retries")
        response.raise_for_status()

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
        response = http_session.post(f"{self.base_url}/lists/save", headers=prod_headers, json=payload)
        if response is None:
            raise requests.exceptions.ConnectionError("Failed to connect after multiple retries")
        response.raise_for_status()

    def add_item_to_list(self, list_name, new_entry):
        """Add item to existing list"""
        list_data = self.get_list_data_by_name(list_name)
        list_data.append(new_entry)
        self.save(list_name, list_data)


def main():
    """Main function that demonstrates core functionality of this module"""
    from src.components.ticket_cache import TicketCache

    log.info("Starting XSOAR ticket caching process")
    ticket_cache = TicketCache()
    ticket_cache.generate()
    log.info("XSOAR ticket caching process completed")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    main()
