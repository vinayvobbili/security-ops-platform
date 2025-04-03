import logging

import requests

from config import get_config

# Load configuration
config = get_config()

# Configure logging
log = logging.getLogger(__name__)  # Consistent with best practices

headers = {
    'Authorization': config.xsoar_auth_token,
    'x-xdr-auth-id': config.xsoar_auth_id,
    'Content-Type': 'application/json'
}


def get_incident(base_url, incident_id, auth_id, auth_key):
    """Fetch incident details from source environment"""
    headers = {
        'Accept': 'application/json',
        'authorization': auth_key,
        'x-xdr-auth-id': auth_id
    }

    try:
        incident_url = f"{base_url}/incident/load/{incident_id}"
        response = requests.get(
            incident_url,
            headers=headers,
            verify=False,  # Note: Only for testing. Use proper cert verification in production
            timeout=30
        )
        return response.json()

    except requests.exceptions.RequestException as e:
        raise Exception(f"Network error while fetching incident: {str(e)}")


def create_incident(base_url, incident_data, auth_id, auth_token):
    """Create incident in target environment"""
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'x-xdr-auth-id': auth_id,
        'authorization': auth_token,
    }

    try:
        create_url = f"{base_url}/incident"
        payload = {
            "details": incident_data.get('details', 'Details not found'),
            "name": incident_data.get('name', 'Name not found'),
            "severity": int(incident_data.get('severity', 1)),
            "type": incident_data.get('type', f'{config.ticket_type_prefix} Case'),
            "closeNotes": incident_data.get('closeNotes', 'Close notes not found'),
            "closeReason": incident_data.get('closeReason', 'Close reason not found'),
            "email": incident_data.get('email', 'Email not found'),
            "emailbodyhtml": incident_data.get('emailbodyhtml', 'Email body HTML not found'),
            "CustomFields": {
                'detectionsource': incident_data.get('CustomFields', {}).get('detectionsource', 'Unknown'),
                'securitycategory': incident_data.get('CustomFields', {}).get('securitycategory', 'Unknown'),
                'qradareventid': incident_data.get('CustomFields', {}).get('qradareventid', 'Unknown'),
                'impact': incident_data.get('CustomFields', {}).get('impact', 'Unknown'),
                'rootcause': incident_data.get('CustomFields', {}).get('rootcause', 'Unknown'),
                'securitysubcategory': incident_data.get('CustomFields', {}).get('securitysubcategory', 'Unknown')
            },
            "all": True,
            "createInvestigation": True,
            "data": incident_data,
            "force": True,
        }

        # Validate payload
        if not isinstance(payload, dict):
            raise ValueError("Payload must be a dictionary")

        response = requests.post(
            create_url,
            headers=headers,
            json=payload,
            verify=False,
            timeout=30
        )
        response.raise_for_status()  # Raise an error for bad status codes
        return response.json()

    except requests.exceptions.RequestException as e:
        raise Exception(f"Network error while creating incident: {str(e)}")
    except ValueError as e:
        raise Exception(f"Payload error: {str(e)}")


def transfer_incident(source_url, target_url, incident_id, source_auth, target_auth):
    """Main function to transfer incident between environments"""
    try:
        # Get incident from source
        # print(f"Fetching incident {incident_id} from source environment...")
        incident_data = get_incident(
            source_url,
            incident_id,
            auth_id=source_auth['auth_id'],
            auth_key=source_auth['auth_key']
        )

        # print("Successfully retrieved incident data")

        # Create incident in target
        print("Creating the incident in target environment...")
        new_incident = create_incident(
            target_url,
            incident_data,
            auth_id=target_auth['auth_id'],
            auth_token=target_auth['auth_key']
        )

        return {
            'status': 'success',
            'source_incident_id': incident_id,
            'target_incident_id': new_incident.get('id'),
            'message': 'Incident transferred successfully'
        }
    except Exception as e:
        return {
            'status': 'error',
            'error_type': 'UNEXPECTED_ERROR',
            'message': f"Unexpected error: {str(e)}"
        }


def import_ticket(source_ticket_number):
    # Configuration
    source_env = {
        'url': config.xsoar_api_base_url,
        'auth': {
            'auth_id': config.xsoar_auth_id,
            'auth_key': config.xsoar_auth_token,
        }
    }

    target_env = {
        'url': config.xsoar_dev_api_base_url,
        'auth': {
            'auth_id': config.xsoar_dev_auth_id,
            'auth_key': config.xsoar_dev_auth_token,
        }
    }

    result = transfer_incident(
        source_env['url'],
        target_env['url'],
        source_ticket_number,
        source_env['auth'],
        target_env['auth']
    )

    destination_ticket_number = result.get('target_incident_id')
    return destination_ticket_number, f'{config.xsoar_dev_ui_base_url}/Custom/caseinfoid/{destination_ticket_number}'


class IncidentFetcher:
    def __init__(self):
        self.headers = headers
        self.incident_search_url = config.xsoar_api_base_url + '/incidents/search'
        self.incident_entries_url = config.xsoar_api_base_url + '/incidents/{incident_id}/entries'  # Endpoint for entries

    def get_tickets(self, query, period=None, size=10000) -> list:
        """Fetches security incidents from XSOAR."""
        query = query + f' -category:job -type:"{config.ticket_type_prefix} Ticket QA" -type:"{config.ticket_type_prefix} SNOW Whitelist Request"'
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
            response = requests.post(self.incident_search_url, headers=self.headers, json=payload, timeout=120)
            response.raise_for_status()
            tickets = response.json()
            log.info(f'Retrieved {tickets.get("total", 0)} incidents')
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


def __get_all_lists__() -> list:
    api_url = config.xsoar_api_base_url + '/lists'
    return requests.get(api_url, headers=headers).json()


def get_list_by_name(all_lists, list_name):
    list_contents = list(filter(lambda item: item['id'] == list_name, all_lists))[0]
    return list_contents['data'], list_contents['version']


class ListFetcher:
    def __init__(self):
        self.headers = headers
        self.list_fetch_url = config.xsoar_api_base_url + '/lists'


if __name__ == "__main__":
    destination_ticket_number, destination_ticket_link = import_ticket('623454')
    print(destination_ticket_number, destination_ticket_link)
