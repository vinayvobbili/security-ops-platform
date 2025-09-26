import json
import logging
from datetime import datetime

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

    def get_tickets(self, query, period=None, size=20000):
        """Fetch security incidents from XSOAR"""
        full_query = query + f' -category:job -type:"{CONFIG.team_name} Ticket QA" -type:"{CONFIG.team_name} SNOW Whitelist Request"'

        log.debug(f"Making API call for query: {query}")
        return self._fetch_from_api(full_query, period, size)

    def _fetch_from_api(self, query, period, size):
        """Fetch tickets directly from XSOAR API"""
        try:
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
        except Exception as e:
            log.error(f"Error in _fetch_from_api: {str(e)}")
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

    def cache_past_90_days_tickets(self):
        """Cache past 90 days tickets from prod environment with pre-calculated derived fields"""
        from datetime import datetime, timedelta, timezone
        from pathlib import Path

        root_directory = Path(__file__).parent.parent

        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=90)
        query = f"created:>={start_date.strftime('%Y-%m-%dT%H:%M:%SZ')} created:<={end_date.strftime('%Y-%m-%dT%H:%M:%SZ')} type:{CONFIG.team_name} -closeReason:Duplicate"

        tickets = self.get_tickets(query)
        log.info(f"Fetched {len(tickets)} tickets from prod for caching")

        # Pre-calculate derived fields for each ticket
        current_time = datetime.now(timezone.utc)

        for ticket in tickets:
            try:
                # Parse created date
                created_date = None
                if ticket.get('created'):
                    try:
                        created_date = datetime.fromisoformat(ticket['created'].replace('Z', '+00:00'))
                    except ValueError:
                        try:
                            created_date = datetime.strptime(ticket['created'], '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)
                        except ValueError:
                            log.warning(f"Could not parse created date: {ticket.get('created')} for ticket {ticket.get('id')}")

                # Parse closed date
                closed_date = None
                if ticket.get('closed'):
                    try:
                        closed_date = datetime.fromisoformat(ticket['closed'].replace('Z', '+00:00'))
                    except ValueError:
                        try:
                            closed_date = datetime.strptime(ticket['closed'], '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)
                        except ValueError:
                            log.warning(f"Could not parse closed date: {ticket.get('closed')} for ticket {ticket.get('id')}")

                # Calculate age in days (only for open tickets: status 0=Pending, 1=Active)
                ticket['age_days'] = None
                ticket['is_open'] = ticket.get('status', 0) in [0, 1]  # 0=Pending, 1=Active, 2=Closed

                if created_date and ticket['is_open']:
                    age_delta = current_time - created_date
                    ticket['age_days'] = age_delta.days

                # Calculate days since creation (for all tickets)
                ticket['days_since_creation'] = None
                if created_date:
                    days_delta = current_time - created_date
                    ticket['days_since_creation'] = days_delta.days

                # Calculate time to resolution (for closed tickets)
                ticket['resolution_time_days'] = None
                if created_date and closed_date:
                    resolution_delta = closed_date - created_date
                    ticket['resolution_time_days'] = resolution_delta.days

                # Add age filter categories for frontend filtering
                ticket['age_category'] = 'all'  # Default category
                if ticket['age_days'] is not None:
                    if ticket['age_days'] <= 7:
                        ticket['age_category'] = 'le7'  # ≤7 days
                    elif ticket['age_days'] <= 30:
                        ticket['age_category'] = 'le30'  # ≤30 days
                    else:
                        ticket['age_category'] = 'gt30'  # >30 days

                # Debug logging for age calculation (remove after testing)
                if ticket.get('id'):
                    log.debug(f"Ticket {ticket['id']}: created={ticket.get('created')}, "
                             f"age_days={ticket['age_days']}, is_open={ticket['is_open']}, "
                             f"age_category={ticket['age_category']}")

                # Add date ranges for quick filtering
                if created_date:
                    ticket['created_days_ago'] = (current_time - created_date).days

            except Exception as e:
                log.error(f"Error processing ticket {ticket.get('id', 'unknown')}: {str(e)}")
                # Set default values for failed calculations
                ticket.update({
                    'age_days': None,
                    'is_open': ticket.get('status', 0) in [0, 1],
                    'days_since_creation': None,
                    'resolution_time_days': None,
                    'age_category': 'all',
                    'created_days_ago': None
                })

        # save raw tickets data under today's date in web/static/charts
        today_date = datetime.now().strftime('%m-%d-%Y')
        raw_output_path = root_directory / "web" / "static" / "charts" / today_date / "past_90_days_tickets_raw.json"
        raw_output_path.parent.mkdir(parents=True, exist_ok=True)  # Ensure the directory exists

        with open(raw_output_path, 'w') as f:
            json.dump(tickets, f, indent=4)
        log.info(f"Cached {len(tickets)} raw tickets with pre-calculated derived fields to {raw_output_path}")

        # Generate lightweight UI data
        ui_data = self.prep_data_for_UI(tickets)
        ui_output_path = root_directory / "web" / "static" / "charts" / today_date / "past_90_days_tickets.json"

        with open(ui_output_path, 'w') as f:
            json.dump(ui_data, f, indent=2)
        log.info(f"Generated lightweight UI data with {len(ui_data)} tickets to {ui_output_path}")

    def prep_data_for_UI(self, raw_tickets):
        """
        Prepare fully flattened data for UI with all pre-calculated display values
        """
        from datetime import datetime, timezone

        ui_data = []
        datetime.now(timezone.utc)

        for ticket in raw_tickets:
            try:
                # Skip tickets without valid ID
                if not ticket.get('id'):
                    continue

                ui_ticket = {
                    # Core identification
                    'id': ticket.get('id'),
                    'name': ticket.get('name', f"Ticket {ticket.get('id')}"),
                    'type': ticket.get('type', 'Unknown'),

                    # Status and priority (keep numeric for filtering, add display versions)
                    'status': ticket.get('status', 0),
                    'status_display': {0: 'Pending', 1: 'Active', 2: 'Closed'}.get(ticket.get('status', 0), 'Unknown'),
                    'severity': ticket.get('severity', 0),
                    'severity_display': {0: 'Unknown', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}.get(ticket.get('severity', 0), 'Unknown'),
                    'impact': ticket.get('impact', 'Unknown'),

                    # Geographic and organizational
                    'affected_country': ticket.get('affected_country', 'Unknown'),
                    'affected_region': ticket.get('affected_region', 'Unknown'),
                    'owner': ticket.get('owner', 'Unknown'),
                    'owner_display': self._clean_owner_name(ticket.get('owner', 'Unknown')),

                    # Timestamps - formatted for display
                    'created': ticket.get('created', ''),
                    'created_display': self._format_date_for_display(ticket.get('created')),
                    'closed': ticket.get('closed', ''),
                    'closed_display': self._format_date_for_display(ticket.get('closed')),

                    # Automation
                    'automation_level': ticket.get('automation_level', 'Unknown'),

                    # Pre-calculated metrics
                    'age': ticket.get('age_days'),  # Only set for open tickets
                    'age_display': self._format_age_display(ticket.get('age_days')),
                    'is_open': ticket.get('is_open', False),
                    'days_since_creation': ticket.get('days_since_creation'),
                    'created_days_ago': ticket.get('created_days_ago'),

                    # Time to respond/contain - flattened and formatted
                    'ttr_seconds': self._extract_duration(ticket.get('timetorespond')),
                    'ttr_display': self._format_duration(self._extract_duration(ticket.get('timetorespond'))),
                    'ttr_breach': self._extract_breach_status(ticket.get('timetorespond')),

                    'ttc_seconds': self._extract_duration(ticket.get('timetocontain')),
                    'ttc_display': self._format_duration(self._extract_duration(ticket.get('timetocontain'))),
                    'ttc_breach': self._extract_breach_status(ticket.get('timetocontain')),

                    # Display-friendly type (remove METCIRT prefix)
                    'type_display': self._clean_type_name(ticket.get('type', 'Unknown')),

                    # Filter-friendly fields
                    'has_host': bool(ticket.get('hostname') and ticket.get('hostname').strip() and ticket.get('hostname') != 'Unknown'),
                    'has_owner': bool(ticket.get('owner') and ticket.get('owner').strip()),
                    'has_ttr': bool(self._extract_duration(ticket.get('timetorespond'))),
                    'has_ttc': bool(self._extract_duration(ticket.get('timetocontain'))),

                    # Chart-friendly data
                    'chart_date': self._extract_chart_date(ticket.get('created')),
                }

                ui_data.append(ui_ticket)

            except Exception as e:
                log.error(f"Error processing ticket {ticket.get('id', 'unknown')}: {str(e)}")
                continue

        log.info(f"Prepared flattened UI data: {len(ui_data)} tickets from {len(raw_tickets)} raw tickets")
        return ui_data

    def _clean_owner_name(self, owner):
        """Remove @company.com from owner names"""
        if not owner or owner == 'Unknown':
            return owner
        return owner.replace('@company.com', '') if owner.endswith('@company.com') else owner

    def _clean_type_name(self, ticket_type):
        """Remove METCIRT prefix from ticket types"""
        if not ticket_type or ticket_type == 'Unknown':
            return ticket_type
        import re
        return re.sub(r'^METCIRT[_\-\s]*', '', ticket_type, flags=re.IGNORECASE) if ticket_type.startswith('METCIRT') else ticket_type

    def _format_date_for_display(self, date_str):
        """Format date for display (MM/DD format)"""
        if not date_str:
            return ''
        try:
            date_obj = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            return f"{date_obj.month:02d}/{date_obj.day:02d}"
        except (ValueError, AttributeError):
            return date_str

    def _format_age_display(self, age_days):
        """Format age for display"""
        if age_days is None:
            return ''
        return f"{age_days}d" if age_days > 0 else '0d'

    def _extract_duration(self, time_obj):
        """Extract totalDuration from time object"""
        if not time_obj or not isinstance(time_obj, dict):
            return None
        return time_obj.get('totalDuration')

    def _extract_breach_status(self, time_obj):
        """Extract breach status from time object"""
        if not time_obj or not isinstance(time_obj, dict):
            return False
        breach = time_obj.get('breachTriggered')
        return breach is True or breach == 'true'

    def _format_duration(self, seconds):
        """Format duration in MM:SS format"""
        if not seconds or seconds <= 0:
            return '0:00'
        minutes = seconds // 60
        secs = seconds % 60
        return f"{minutes}:{secs:02d}"

    def _extract_chart_date(self, date_str):
        """Extract date in YYYY-MM-DD format for charts"""
        if not date_str:
            return None
        try:
            date_obj = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            return date_obj.strftime('%Y-%m-%d')
        except (ValueError, AttributeError):
            return None


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


if __name__ == "__main__":
    ticket_handler = TicketHandler()
    ticket_handler.cache_past_90_days_tickets()
