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
        incident_url = f"{base_url}/xsoar/public/v1/incident/load/{incident_id}"
        response = requests.get(
            incident_url,
            headers=headers,
            verify=False,  # Note: Only for testing. Use proper cert verification in production
            timeout=30
        )
        return response.json()

    except requests.exceptions.RequestException as e:
        raise Exception(f"Network error while fetching incident: {str(e)}")


def create_incident(base_url, incident_data, auth_id, auth_key):
    """Create incident in target environment"""
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'authorization': auth_key,
        'x-xdr-auth-id': auth_id
    }

    try:
        create_url = f"{base_url}/xsoar/public/v1/incident"
        payload = {
            "details": incident_data.get('details', 'Details not found'),
            "name": incident_data.get('name', 'Name not found'),
            "severity": incident_data.get('severity', 1),
            "type": incident_data.get('type', f'{config.ticket_type_prefix} Case'),
            "CustomFields": {
                'detectionsource': incident_data.get('CustomFields', {}).get('detectionsource', 'Unknown'),
                'securitycategory': incident_data.get('CustomFields', {}).get('securitycategory', 'Unknown'),
                'qradareventid': incident_data.get('CustomFields', {}).get('qradareventid', 'Unknown'),
            },
            "all": True,
            "createInvestigation": True,
            "data": incident_data,
            "force": True,
        }

        response = requests.post(
            create_url,
            headers=headers,
            json=payload,
            verify=False,
            timeout=30
        )
        # print("Create Incident Response: ", response.json())
        return response.json()

    except requests.exceptions.RequestException as e:
        raise Exception(f"Network error while creating incident: {str(e)}")


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
        # print("Creating incident in target environment...")
        new_incident = create_incident(
            target_url,
            incident_data,
            auth_id=target_auth['auth_id'],
            auth_key=target_auth['auth_key']
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
        'url': 'https://api-msoar.crtx.us.paloaltonetworks.com',
        'auth': {
            'auth_id': '25',
            'auth_key': 'OP2JKkAze7xIW6ca4YnYhpvkqFQTzD8L2AOnTLZ8IoeTOPuyzvDxuStSfuxQLoZkm4sjRNLvT4nfPialwnDgdBY986o1ps8wV5EZfD0gRulObNPAd3uRBr0LfSITkKBe',
        }
    }

    target_env = {
        'url': 'https://api-msoardev.crtx.us.paloaltonetworks.com',
        'auth': {
            'auth_id': '66',
            'auth_key': 'bumyL61MBpjgMiZ2AoYsqyShcRnBUm9LwIYII7nCQZkNXGMAc5QPYov3tis9IDmHhOugMQnDP7Z0IB8REERT1vHqUSAtNm0WcU5jNM9ssHOGBEFkjmwRj3CKuxfbRzz7'
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
    return destination_ticket_number, f'https://msoardev.crtx.us.paloaltonetworks.com/Custom/caseinfoid/{destination_ticket_number}'


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
            response = requests.post(self.incident_search_url, headers=self.headers, json=payload, timeout=60)
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
            return []  # Return empty list on failure


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
