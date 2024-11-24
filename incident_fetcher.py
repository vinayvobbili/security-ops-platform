import logging

import requests

from config import get_config

# Load configuration
config = get_config()

# Configure logging
log = logging.getLogger(__name__)  # Consistent with best practices


class IncidentFetcher:
    def __init__(self):
        self.headers = {  # More generic name
            'Authorization': config.xsoar_auth_token,
            'x-xdr-auth-id': config.xsoar_auth_id,
            'Content-Type': 'application/json'
        }
        self.api_url = config.xsoar_api_base_url + '/incidents/search'

    def get_tickets(self, query, period=None) -> dict | None:
        """Fetches security incidents from XSOAR."""
        payload = {
            "filter": {
                "query": query,
                "page": 0,
                "size": 10000,  # Good to have a large size
                "sort": [{"field": "created", "asc": False}]
            }
        }
        if period:  # Add period to the payload only if it's provided
            payload["filter"]["period"] = period

        try:
            response = requests.post(self.api_url, headers=self.headers, json=payload, timeout=60)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            tickets = response.json()
            log.info(f'Retrieved {tickets.get("total", 0)} incidents')  # Handles missing "total"
            return tickets.get('data', {})  # Return the JSON response
        except requests.exceptions.RequestException as e:
            log.error(f"Error fetching incidents: {e}")
            return None  # Return None on error
