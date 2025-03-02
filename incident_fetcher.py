import logging

import requests

from config import get_config

# Load configuration
config = get_config()

# Configure logging
log = logging.getLogger(__name__)  # Consistent with best practices


class IncidentFetcher:
    def __init__(self):
        self.headers = {
            'Authorization': config.xsoar_auth_token,
            'x-xdr-auth-id': config.xsoar_auth_id,
            'Content-Type': 'application/json'
        }
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
