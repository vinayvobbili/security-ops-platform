import json
import logging
from pathlib import Path

import requests

from config import get_config

CONFIG = get_config()

# Configure logging
log = logging.getLogger(__name__)

ROOT_DIRECTORY = Path(__file__).parent.parent

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
headers = prod_headers


def get_incident(incident_id):
    """Fetch incident details from source environment"""

    try:
        incident_url = f"{CONFIG.xsoar_prod_api_base_url}/incident/load/{incident_id}"
        response = requests.get(
            incident_url,
            headers=headers,
            verify=False,  # Note: Only for testing. Use proper cert verification in production
            timeout=30
        )
        return response.json()

    except requests.exceptions.RequestException as e:
        raise Exception(f"Network error while fetching incident: {str(e)}")


def import_ticket(source_ticket_number):
    incident_handler = IncidentHandler()

    # Get incident from prod
    incident_data = get_incident(source_ticket_number)

    # Create incident in target
    new_incident = incident_handler.create_in_dev(incident_data)

    return new_incident['id'], f'{CONFIG.xsoar_dev_ui_base_url}/Custom/caseinfoid/{new_incident['id']}'


class IncidentHandler:
    def __init__(self):
        self.headers = headers
        self.incident_search_url = CONFIG.xsoar_prod_api_base_url + '/incidents/search'
        self.incident_entries_url = CONFIG.xsoar_prod_api_base_url + '/incidents/{incident_id}/entries'  # Endpoint for entries
        self.incident_create_url = CONFIG.xsoar_prod_api_base_url + '/incident'
        self.incident_create_url_dev = CONFIG.xsoar_dev_api_base_url + '/incident'

    def get_tickets(self, query, period=None, size=10000) -> list:
        """Fetches security incidents from XSOAR."""
        query = query + f' -category:job -type:"{CONFIG.ticket_type_prefix} Ticket QA" -type:"{CONFIG.ticket_type_prefix} SNOW Whitelist Request"'
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

        try:
            response = requests.post(self.incident_search_url, headers=self.headers, json=payload, timeout=300)
            response.raise_for_status()
            tickets = response.json()

            return tickets.get('data', [])  # Ensure only incident data is returned
        except requests.exceptions.RequestException as e:
            log.error(f"Error fetching incidents: {e}")
            return []

    def get_entries(self, incident_id) -> list:
        """Fetches entries (comments, notes) for a given incident."""
        url = self.incident_entries_url.format(incident_id=incident_id)  # Format the URL with incident ID

        try:
            response = requests.get(url, headers=self.headers, timeout=60)
            response.raise_for_status()
            entries = response.json()
            return entries.get('data', [])  # Extract entries from response
        except requests.exceptions.RequestException as e:
            log.error(f"Error fetching entries for incident {incident_id}: {e}")
            return []  # Return an empty list on failure

    def create(self, payload):
        """Creates a new incident in XSOAR."""
        payload.update({"all": True, "createInvestigation": True, "force": True})
        response = requests.post(self.incident_create_url, headers=self.headers, json=payload)
        response.raise_for_status()
        return response.json()

    def create_in_dev(self, payload):
        """Creates a new incident in XSOAR Dev."""
        try:
            payload.pop('id', None)
            payload.pop('phase', None)
            payload.pop('status', None)
            payload.update({"all": True, "createInvestigation": True, "force": True})
            response = requests.post(self.incident_create_url_dev, headers=dev_headers, json=payload)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            log.error(f"Error creating incident in dev: {e}")
            return {"error": str(e)}


class ListHandler:
    def __init__(self):
        self.headers = prod_headers
        self.list_fetch_url = CONFIG.xsoar_prod_api_base_url + '/lists'
        self.save_url = f"{CONFIG.xsoar_prod_api_base_url}/lists/save"

    def __get_all_lists__(self) -> list:
        return requests.get(self.list_fetch_url, headers=headers).json()

    def get_list_data_by_name(self, list_name):
        all_lists = self.__get_all_lists__()
        list_contents = list(filter(lambda item: item['id'] == list_name, all_lists))[0]
        return json.loads(list_contents['data'])

    def get_list_version_by_name(self, list_name):
        all_lists = self.__get_all_lists__()
        list_contents = list(filter(lambda item: item['id'] == list_name, all_lists))[0]
        return list_contents['version']

    def save(self, list_name, list_data):
        list_version = self.get_list_version_by_name(list_name)
        result = requests.post(self.save_url, headers=prod_headers, json={
            "data": json.dumps(list_data, indent=4),
            "name": list_name,
            "type": "json",
            "id": list_name,
            "version": list_version
        })

        if result.status_code != 200:
            raise RuntimeError(f"Failed to save list. Status code: {result.status_code}")


if __name__ == "__main__":
    # destination_ticket_number, destination_ticket_link = import_ticket('621684')
    # print(destination_ticket_number, destination_ticket_link)
    list_handler = ListHandler()
