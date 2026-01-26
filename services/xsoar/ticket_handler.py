"""
XSOAR Ticket Handler

Handles all XSOAR ticket operations including:
- Search and pagination
- Create, update, and read operations
- Entries, notes, and war room commands
- Playbook task operations
- File uploads (attachments and war room)
- Participant management

This module provides a unified TicketHandler class that delegates to
specialized modules for each operation type.
"""
import logging
import os
import time
from typing import Any, Dict, List, Optional

from src.utils.xsoar_enums import XsoarEnvironment
from ._client import (
    ApiException,
    get_config,
    get_prod_client,
    get_dev_client,
)
from ._utils import _parse_generic_response
from ._retry import truncate_error_message
from . import _search
from . import _entries
from . import _files
from . import _tasks
from . import _participants

log = logging.getLogger(__name__)
CONFIG = get_config()


class TicketHandler:
    """Handler for XSOAR ticket operations including search, create, update, and link."""

    # Configuration class variables (can be overridden via env vars)
    DEFAULT_PAGE_SIZE = int(os.getenv('XSOAR_PAGE_SIZE', '2000'))
    READ_TIMEOUT = int(os.getenv('XSOAR_READ_TIMEOUT', '30'))

    def __init__(self, environment: XsoarEnvironment = XsoarEnvironment.PROD):
        """
        Initialize TicketHandler with XSOAR environment.

        Args:
            environment: XsoarEnvironment enum (PROD or DEV), defaults to PROD
        """
        if environment == XsoarEnvironment.PROD:
            self.client = get_prod_client()
            self.base_url = CONFIG.xsoar_prod_api_base_url
            self.auth_key = CONFIG.xsoar_prod_auth_key
            self.auth_id = CONFIG.xsoar_prod_auth_id
        elif environment == XsoarEnvironment.DEV:
            self.client = get_dev_client()
            self.base_url = CONFIG.xsoar_dev_api_base_url
            self.auth_key = CONFIG.xsoar_dev_auth_key
            self.auth_id = CONFIG.xsoar_dev_auth_id
        else:
            raise ValueError(f"Invalid environment: {environment}. Must be XsoarEnvironment.PROD or XsoarEnvironment.DEV")

    # --- Search Operations (delegated to _search module) ---

    def get_tickets(self, query: str, period: Optional[Dict[str, Any]] = None,
                    size: int = 20000, paginate: bool = True) -> List[Dict[str, Any]]:
        """
        Fetch security incidents from XSOAR using demisto-py SDK.

        Args:
            query: XSOAR query string for filtering incidents
            period: Optional time period filter
            size: Maximum number of results (used when paginate=False)
            paginate: Whether to fetch all results with pagination

        Returns:
            List of incident dictionaries
        """
        return _search.get_tickets(
            self.client, self.base_url, query, CONFIG.team_name,
            period=period, size=size, paginate=paginate
        )

    # --- Entry Operations (delegated to _entries module) ---

    def get_entries(self, incident_id: str) -> List[Dict[str, Any]]:
        """Fetch entries (comments, notes) for a given incident."""
        return _entries.get_entries(self.client, incident_id)

    def get_user_notes(self, incident_id: str, max_retries: int = 3) -> List[Dict[str, str]]:
        """Fetch user notes for a given incident."""
        return _entries.get_user_notes(self.client, incident_id, max_retries)

    def create_new_entry_in_existing_ticket(self, incident_id: str, entry_data: str,
                                            markdown: bool = True) -> Dict[str, Any]:
        """Create a new entry (note) in an existing ticket."""
        return _entries.create_new_entry_in_existing_ticket(
            self.client, incident_id, entry_data, markdown
        )

    def execute_command_in_war_room(self, incident_id: str, command: str) -> Dict[str, Any]:
        """Execute a command in the war room of the specified incident."""
        return _entries.execute_command_in_war_room(self.client, incident_id, command)

    # --- File Upload Operations (delegated to _files module) ---

    def upload_file_to_attachment(self, incident_id: str, file_path: str,
                                  comment: str = "") -> Dict[str, Any]:
        """Upload a file to the incident's Attachments field (not war room)."""
        return _files.upload_file_to_attachment(
            self.base_url, self.auth_key, self.auth_id,
            incident_id, file_path, comment
        )

    def upload_file_to_war_room(self, incident_id: str, file_path: str,
                                comment: str = "",
                                is_note_entry: bool = False,
                                show_media_files: bool = False,
                                tags: str = "") -> Dict[str, Any]:
        """Upload a file to the specified ticket's war room."""
        return _files.upload_file_to_war_room(
            self.base_url, self.auth_key, self.auth_id,
            incident_id, file_path, comment, is_note_entry, show_media_files, tags
        )

    def upload_file_to_ticket(self, incident_id: str, file_path: str,
                              comment: str = "",
                              upload_to: str = "attachment") -> Dict[str, Any]:
        """Upload a file to a ticket (attachments field or war room)."""
        return _files.upload_file_to_ticket(
            self.base_url, self.auth_key, self.auth_id,
            incident_id, file_path, comment, upload_to
        )

    # --- Playbook Task Operations (delegated to _tasks module) ---

    def get_playbook_task_id(self, ticket_id: str, target_task_name: str) -> Optional[str]:
        """Search for a task by name in the playbook, including sub-playbooks."""
        return _tasks.get_playbook_task_id(self.client, ticket_id, target_task_name)

    def complete_task(self, ticket_id: str, task_name: str, task_input: str = ''):
        """Complete a task in a playbook."""
        return _tasks.complete_task(
            self.client, self.base_url, self.auth_key, self.auth_id,
            ticket_id, task_name, task_input
        )

    # --- Participant Operations (delegated to _participants module) ---

    def link_tickets(self, parent_ticket_id: str, link_ticket_id: str) -> Optional[Dict[str, Any]]:
        """Links the source ticket to the newly created QA ticket in XSOAR."""
        return _participants.link_tickets(self.client, parent_ticket_id, link_ticket_id)

    def add_participant(self, ticket_id: str, participant_email_address: str) -> Optional[Dict[str, Any]]:
        """Adds a participant to the incident."""
        return _participants.add_participant(self.client, ticket_id, participant_email_address)

    def get_participants(self, incident_id: str) -> List[Dict[str, Any]]:
        """Get participants (users) for a given incident."""
        return _participants.get_participants(self.client, incident_id)

    def assign_owner(self, ticket_id: str, owner_email_address: str) -> Dict[str, Any]:
        """Assigns an owner to the specified ticket."""
        log.debug(f"Assigning owner {owner_email_address} to ticket {ticket_id}")
        return self.update_incident(ticket_id, {"owner": owner_email_address})

    # --- Core CRUD Operations (kept in this module) ---

    def create(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new incident in XSOAR.

        Args:
            payload: Incident data dictionary

        Returns:
            Created incident data

        Raises:
            ApiException: If incident creation fails
        """
        payload.update({"all": True, "createInvestigation": True, "force": True})
        try:
            response = self.client.create_incident(create_incident_request=payload)
            return response.to_dict() if hasattr(response, 'to_dict') else response
        except ApiException as e:
            log.error(f"Error creating incident: {truncate_error_message(e)}")
            raise

    def update_incident(self, ticket_id: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update an existing incident in XSOAR using POST /incident endpoint.

        Args:
            ticket_id: The XSOAR incident ID to update
            update_data: Dictionary of fields to update

        Returns:
            Updated incident data dictionary

        Note:
            - Fetches current incident version for optimistic locking
            - The id field is automatically added if not present
        """
        # Fetch current incident data to get the latest version and merge with updates
        case_data = self.get_case_data(ticket_id)
        current_version = case_data.get('version')

        log.debug(f"Fetched current version {current_version} for incident {ticket_id}")

        # Start with all current case data, then apply updates on top
        merged_data = case_data.copy()
        merged_data.update(update_data)
        merged_data['id'] = ticket_id
        merged_data['version'] = current_version

        log.debug(f"Updating incident {ticket_id} with merged data")

        try:
            response = self.client.generic_request(
                path='/incident',
                method='POST',
                body=merged_data
            )
            log.debug(f"Successfully updated incident {ticket_id}")
            return _parse_generic_response(response)
        except ApiException as e:
            log.error(f"Error updating incident {ticket_id}: {truncate_error_message(e)}")
            raise

    def get_case_data(self, incident_id: str, max_retries: int = 3) -> Dict[str, Any]:
        """
        Fetch incident details.

        Args:
            incident_id: The XSOAR incident ID
            max_retries: Maximum number of retry attempts for rate limiting/server errors

        Returns:
            Dictionary containing incident details

        Raises:
            ApiException: If API call fails after all retries
        """
        retry_count = 0

        while retry_count <= max_retries:
            try:
                response = self.client.generic_request(
                    path=f'/incident/load/{incident_id}',
                    method='GET'
                )
                return _parse_generic_response(response)
            except ApiException as e:
                # Handle rate limiting (429)
                if e.status == 429:
                    retry_count += 1
                    if retry_count > max_retries:
                        log.error(f"Exceeded max retries ({max_retries}) for incident {incident_id} due to rate limiting")
                        raise

                    backoff_time = 5 * (2 ** (retry_count - 1))
                    log.warning(f"Rate limit hit (429) for incident {incident_id}. "
                                f"Retry {retry_count}/{max_retries}. "
                                f"Backing off for {backoff_time} seconds...")
                    time.sleep(backoff_time)
                    continue

                # Handle server errors (502, 503, 504)
                elif e.status in [502, 503, 504]:
                    retry_count += 1
                    if retry_count > max_retries:
                        log.error(f"Exceeded max retries ({max_retries}) for incident {incident_id} due to server error {e.status}")
                        raise

                    backoff_time = 5 * (2 ** (retry_count - 1))
                    log.warning(f"Server error {e.status} for incident {incident_id}. "
                                f"Retry {retry_count}/{max_retries}. "
                                f"Backing off for {backoff_time} seconds...")
                    time.sleep(backoff_time)
                    continue

                # For other errors, log and raise immediately
                else:
                    log.error(f"Error fetching incident {incident_id}: {truncate_error_message(e)}")
                    raise

        # Should not reach here, but just in case
        raise ApiException(f"Failed to fetch incident {incident_id} after {max_retries} retries")

    def get_case_data_with_notes(self, incident_id: str, max_retries: int = 3) -> Dict[str, Any]:
        """Fetch incident details along with notes."""
        return _entries.get_case_data_with_notes(self.client, incident_id, max_retries)

    def create_in_dev(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new incident in dev XSOAR with cleaned payload.

        Args:
            payload: Incident data dictionary

        Returns:
            Created incident data or error dictionary
        """
        log.debug("Creating incident in dev environment")
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
            response = self.client.create_incident(create_incident_request=payload)
            return response.to_dict() if hasattr(response, 'to_dict') else response
        except ApiException as e:
            log.error(f"Error creating incident in dev: {truncate_error_message(e)}")
            return {"error": str(e)}

    # --- Internal helper for _create_entry (kept for backward compatibility) ---

    def _create_entry(self, incident_id: str, entry_data: str, endpoint: str,
                      markdown: bool, max_retries: int = 3) -> Dict[str, Any]:
        """Internal helper method to create an entry in an existing ticket with retry logic."""
        return _entries.create_entry(
            self.client, incident_id, entry_data, endpoint, markdown, max_retries
        )


if __name__ == "__main__":
    # Example usage
    xsoar_handler = TicketHandler(XsoarEnvironment.PROD)
    incident_id = "929947"
    note_response = xsoar_handler.get_user_notes(incident_id)
    print(f"Note Response: {note_response}")
