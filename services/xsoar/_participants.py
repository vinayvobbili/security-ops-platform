"""
XSOAR Participant Operations

Handles participant management and ticket linking operations.
"""
import json
import logging
from typing import Any, Dict, List, Optional

from ._client import ApiException
from ._retry import truncate_error_message
from ._utils import _parse_generic_response

log = logging.getLogger(__name__)


def link_tickets(
    client,
    parent_ticket_id: str,
    link_ticket_id: str
) -> Optional[Dict[str, Any]]:
    """
    Links the source ticket to the newly created QA ticket in XSOAR.

    Args:
        client: XSOAR demisto-py client
        parent_ticket_id: The parent ticket ID
        link_ticket_id: The ticket ID to link to parent

    Returns:
        Response data or None if failed
    """
    if not link_ticket_id or not parent_ticket_id:
        log.error("Ticket ID or QA Ticket ID is empty. Cannot link tickets.")
        return None

    log.debug(f"Linking ticket {link_ticket_id} to QA ticket {parent_ticket_id}")

    entry_data = {
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

    try:
        response = client.generic_request(
            path='/xsoar/entry',
            method='POST',
            body=entry_data
        )
        return _parse_generic_response(response)
    except ApiException as e:
        log.error(f"Error linking tickets: {truncate_error_message(e)}")
        return None


def add_participant(
    client,
    ticket_id: str,
    participant_email_address: str
) -> Optional[Dict[str, Any]]:
    """
    Adds a participant to the incident.

    Args:
        client: XSOAR demisto-py client
        ticket_id: The incident ID
        participant_email_address: Email address of participant to add

    Returns:
        Response data or None if failed
    """
    if not ticket_id or not participant_email_address:
        log.error("Ticket ID or participant email is empty. Cannot add participant.")
        return None

    log.debug(f"Adding participant {participant_email_address} to ticket {ticket_id}")

    entry_data = {
        "id": "",
        "version": 0,
        "investigationId": ticket_id,
        "data": f"@{participant_email_address}",
        "args": None,
        "markdown": False,
    }

    try:
        response = client.generic_request(
            path='/xsoar/entry',
            method='POST',
            body=entry_data
        )
        return _parse_generic_response(response)
    except ApiException as e:
        log.error(f"Error adding participant: {truncate_error_message(e)}")
        return None


def get_participants(client, incident_id: str) -> List[Dict[str, Any]]:
    """
    Get participants (users) for a given incident.

    Args:
        client: XSOAR demisto-py client
        incident_id: The incident ID

    Returns:
        List of participant dictionaries

    Raises:
        ValueError: If investigation not found
        ApiException: If API call fails
    """
    if not incident_id:
        log.error("Incident ID is empty. Cannot get participants.")
        return []

    log.debug(f"Getting participants for incident {incident_id}")

    try:
        response = client.generic_request(
            path=f'/investigation/{incident_id}',
            method='POST',
            body={}
        )
        investigation_data = json.loads(response[0]) if response else {}
        return investigation_data.get('users', [])

    except ApiException as e:
        if e.status == 400 and 'Could not find investigation' in str(e):
            log.warning(f"Investigation {incident_id} not found")
            raise ValueError(f"Investigation {incident_id} not found")
        else:
            log.error(f"API error {e.status}: {truncate_error_message(e)}")
            raise
