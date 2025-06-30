import urllib3
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)

import json
import logging

import requests

from config import get_config

CONFIG = get_config()
log = logging.getLogger(__name__)

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
    response = requests.get(incident_url, headers=prod_headers, verify=False, timeout=30)
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
        """Fetch security incidents from XSOAR"""
        query += f' -category:job -type:"{CONFIG.team_name} Ticket QA" -type:"{CONFIG.team_name} SNOW Whitelist Request"'

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

        response = requests.post(
            f"{self.prod_base}/incidents/search",
            headers=prod_headers,
            json=payload,
            timeout=300,
            verify=False
        )
        response.raise_for_status()
        return response.json().get('data', [])

    def get_entries(self, incident_id):
        """Fetch entries (comments, notes) for a given incident"""
        response = requests.get(
            f"{self.prod_base}/incidents/{incident_id}/entries",
            headers=prod_headers,
            timeout=60,
            verify=False
        )
        response.raise_for_status()
        return response.json().get('data', [])

    def create(self, payload):
        """Create a new incident in prod XSOAR"""
        payload.update({"all": True, "createInvestigation": True, "force": True})
        response = requests.post(f"{self.prod_base}/incident", headers=prod_headers, json=payload)
        response.raise_for_status()
        return response.json()

    def create_in_dev(self, payload):
        """Create a new incident in dev XSOAR"""
        print(f"Importing prod ticket# {payload.get('id')}")

        # Clean payload for dev creation
        for key in ['id', 'phase', 'status']:
            payload.pop(key, None)

        payload.update({"all": True, "createInvestigation": True, "force": True})

        response = requests.post(f"{self.dev_base}/incident", headers=dev_headers, json=payload)

        if response.ok:
            return response.json()
        else:
            return {"error": response.text}


class ListHandler:
    def __init__(self):
        self.base_url = CONFIG.xsoar_prod_api_base_url

    def get_all_lists(self):
        """Get all lists from XSOAR"""
        response = requests.get(f"{self.base_url}/lists", headers=prod_headers)
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

        response = requests.post(f"{self.base_url}/lists/save", headers=prod_headers, json=payload)
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
    print(ticket_handler.get_tickets("id:717407"))
