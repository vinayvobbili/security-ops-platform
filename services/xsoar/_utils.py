"""
XSOAR Utility Functions

Internal utility functions used by XSOAR modules.
"""
import ast
import json
import logging
from typing import Any, Dict, Optional, Tuple

from src.utils.xsoar_enums import XsoarEnvironment

log = logging.getLogger(__name__)


def _parse_generic_response(response: Optional[Tuple]) -> Dict[str, Any]:
    """
    Parse response from generic_request which returns (body, status, headers) tuple.
    Body might be JSON string or Python repr string.

    Args:
        response: Tuple containing (body, status, headers) from API call

    Returns:
        Parsed response as dictionary, empty dict if parsing fails
    """
    if not response or not isinstance(response, tuple) or len(response) < 1:
        return {}

    body = response[0]
    if not body:
        return {}

    # Try JSON first, then Python repr
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        try:
            return ast.literal_eval(body)
        except (ValueError, SyntaxError):
            return {}


def import_ticket(source_ticket_number: str, requestor_email_address: Optional[str] = None) -> Tuple[Any, str]:
    """
    Import ticket from prod to dev environment.

    Args:
        source_ticket_number: The incident ID from prod to import
        requestor_email_address: Optional email to set as owner in dev

    Returns:
        Tuple of (ticket_id, ticket_url) or (error_dict, '') if failed
    """
    # Import here to avoid circular dependency
    from ._client import get_config
    from .ticket_handler import TicketHandler

    CONFIG = get_config()
    log.info(f"Importing ticket {source_ticket_number} from prod to dev")
    prod_ticket_handler = TicketHandler(XsoarEnvironment.PROD)
    dev_ticket_handler = TicketHandler(XsoarEnvironment.DEV)

    incident_data = prod_ticket_handler.get_case_data(source_ticket_number)
    log.debug(f"Retrieved incident data for {source_ticket_number}")
    if requestor_email_address:
        incident_data['owner'] = requestor_email_address

    new_ticket_data = dev_ticket_handler.create_in_dev(incident_data)

    if 'error' in new_ticket_data:
        log.error(f"Failed to import ticket {source_ticket_number}: {new_ticket_data.get('error')}")
        return new_ticket_data, ''

    ticket_id = new_ticket_data['id']
    ticket_url = f'{CONFIG.xsoar_dev_ui_base_url}/Custom/caseinfoid/{ticket_id}'
    log.info(f"Successfully imported ticket {source_ticket_number} to dev as {ticket_id}")
    return ticket_id, ticket_url
