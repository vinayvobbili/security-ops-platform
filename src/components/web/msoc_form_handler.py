"""MSOC Form Handler for Web Dashboard."""

import logging
from typing import Dict, Any

from services.xsoar import TicketHandler

logger = logging.getLogger(__name__)


def handle_msoc_form_submission(
    form_data: Dict[str, Any],
    ticket_handler: TicketHandler,
    xsoar_dev_ui_base_url: str
) -> Dict[str, Any]:
    """Handles MSOC form submissions and creates a ticket.

    Args:
        form_data: Form data from request
        ticket_handler: XSOAR ticket handler instance
        xsoar_dev_ui_base_url: Base URL for XSOAR dev UI

    Returns:
        Dictionary with status, new_incident_id, and new_incident_link
    """
    logger.info(f"Processing MSOC form submission: {form_data}")

    form = dict(form_data)
    form['type'] = 'MSOC Site Security Device Management'

    response = ticket_handler.create_in_dev(form)

    return {
        'status': 'success',
        'new_incident_id': response['id'],
        'new_incident_link': f"{xsoar_dev_ui_base_url}/Custom/caseinfoid/{response['id']}"
    }
