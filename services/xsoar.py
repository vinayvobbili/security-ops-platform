import urllib3
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)

import json
import logging
from datetime import datetime

import requests

from my_config import get_config
from src.utils.http_utils import get_session

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

    def get_tickets(self, query, period=None, size=10000):
        """Fetch security incidents from XSOAR, using cached data when available"""
        # Check if we can use cached data for common queries
        base_query = f'type:{CONFIG.team_name} -owner:""'
        full_query = query + f' -category:job -type:"{CONFIG.team_name} Ticket QA" -type:"{CONFIG.team_name} SNOW Whitelist Request"'
        
        # Try to use cached data for queries that match our cache pattern
        if self._can_use_cache(query, period):
            cached_tickets = self._get_cached_tickets()
            if cached_tickets is not None:
                log.info(f"Using cached data for query: {query}")
                return self._filter_cached_tickets(cached_tickets, full_query, period)
        
        # Fall back to API call
        log.info(f"Making API call for query: {query}")
        return self._fetch_from_api(full_query, period, size)
    
    def _can_use_cache(self, query: str, period) -> bool:
        """Check if we can use cached data for this query"""
        base_query = f'type:{CONFIG.team_name} -owner:""'
        
        # Can use cache if:
        # 1. Query matches our base pattern
        # 2. Period is within the last 3 months or None
        if not query.startswith(base_query):
            return False
            
        if period is None:
            return True
            
        # Check if period is within our 3-month cache range
        if period.get("byFrom") == "months" and period.get("fromValue", 0) <= 3:
            return True
        if period.get("byFrom") == "days" and period.get("fromValue", 0) <= 90:
            return True
            
        return False
    
    def _get_cached_tickets(self):
        """Get cached tickets for today's date"""
        try:
            # Import here to avoid circular imports
            from src.utils.data_cache import DataCache
            cache = DataCache()
            cached_data = cache.get_cached_data()
            return cached_data.get("tickets", []) if cached_data else None
        except Exception as e:
            log.warning(f"Failed to load cached data: {e}")
            return None
    
    def _filter_cached_tickets(self, tickets, query, period):
        """Apply additional filtering to cached tickets"""
        # For now, return all cached tickets - the charts can do their own filtering
        # This still saves the expensive API call
        # TODO: Implement more sophisticated filtering if needed
        return tickets
    
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
        if period:
            payload["filter"]["period"] = period

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

    def create_in_dev(self, payload):
        """Create a new incident in dev XSOAR"""

        # Clean payload for dev creation
        for key in ['id', 'phase', 'status', 'roles']:
            payload.pop(key, None)

        payload.update({"all": True, "createInvestigation": True, "force": True})

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
        response = http_session.get(f"{self.base_url}/lists", headers=prod_headers)
        if response is None:
            raise requests.exceptions.ConnectionError("Failed to connect after multiple retries")
        response.raise_for_status()
        return response.json()

    def get_list_data_by_name(self, list_name):
        """Get list data by name"""
        all_lists = self.get_all_lists()
        list_item = next(item for item in all_lists if item['id'] == list_name)
        try:
            return json.loads(list_item['data'])
        except (TypeError, json.JSONDecodeError):
            return list_item['data']

    def get_list_version_by_name(self, list_name):
        """Get list version by name"""
        all_lists = self.get_all_lists()
        list_item = next(item for item in all_lists if item['id'] == list_name)
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


if __name__ == "__main__":
    # destination_ticket_number, destination_ticket_link = import_ticket('690289')
    # print(destination_ticket_number, destination_ticket_link)
    list_handler = ListHandler()
    ticket_handler = TicketHandler()
    # print(ticket_handler.get_tickets("id:717407"))
    # print(ticket_handler.link_tickets('1345807', '1345822'))
    print(ticket_handler.add_participant('1345807', 'tyler.brescia@company.com'))
