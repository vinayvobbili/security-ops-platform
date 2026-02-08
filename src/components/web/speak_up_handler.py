"""Speak Up Form Handler for Web Dashboard."""

import logging
from typing import Dict, Any

from services.xsoar import TicketHandler

logger = logging.getLogger(__name__)


def handle_speak_up_form_submission(
    form_data: Dict[str, Any],
    ticket_handler: TicketHandler,
    xsoar_dev_ui_base_url: str,
    team_name: str
) -> Dict[str, Any]:
    """Handles Speak Up form submissions and creates a ticket.

    Args:
        form_data: Form data from request
        ticket_handler: XSOAR ticket handler instance
        xsoar_dev_ui_base_url: Base URL for XSOAR dev UI
        team_name: Name of the team (e.g., 'SecOps')

    Returns:
        Dictionary with status, new_incident_id, and new_incident_link
    """
    logger.info(f"Processing Speak Up form submission")

    # Format the date from yyyy-mm-dd to mm/dd/yyyy
    date_occurred = form_data.get('dateOccurred', '')
    formatted_date = ""
    if date_occurred:
        try:
            year, month, day = date_occurred.split('-')
            formatted_date = f"{month}/{day}/{year}"
        except ValueError:
            formatted_date = date_occurred

    form = {
        'name': 'Speak Up Report',
        'type': f'{team_name} Employee Reported Incident',
        'details': (
            f"Date Occurred: {formatted_date} \n"
            f"Issue Type: {form_data.get('issueType')} \n"
            f"Description: {form_data.get('description')} \n"
        )
    }

    response = ticket_handler.create(form)

    return {
        'status': 'success',
        'new_incident_id': response['id'],
        'new_incident_link': f"{xsoar_dev_ui_base_url}/Custom/caseinfoid/{response['id']}"
    }
