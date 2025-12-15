"""Toodles Handler for Web Dashboard."""

import logging
from typing import Dict, Any, Tuple

from services.xsoar import TicketHandler

from my_config import get_config
CONFIG = get_config()

logger = logging.getLogger(__name__)


def authenticate_toodles(password: str, configured_password: str) -> Tuple[bool, str]:
    """Authenticate user for Toodles.

    Args:
        password: Password provided by user
        configured_password: Configured password from config

    Returns:
        Tuple of (success, error_message)
    """
    logger.debug("Authenticating Toodles user")

    if not configured_password:
        logger.error("TOODLES_PASSWORD not configured in .env file")
        return False, 'Authentication system not configured'

    if password == configured_password:
        return True, ''
    else:
        return False, 'Invalid password'


def create_x_ticket(
    title: str,
    details: str,
    detection_source: str,
    user_email: str,
    submitter_ip: str,
    ticket_handler: TicketHandler,
    xsoar_prod_ui_base_url: str
) -> str:
    """Create X ticket in XSOAR.

    Args:
        title: Ticket title
        details: Ticket details
        detection_source: Detection source
        user_email: User's email
        submitter_ip: Submitter's IP address
        ticket_handler: XSOAR ticket handler instance
        xsoar_prod_ui_base_url: Base URL for XSOAR prod UI

    Returns:
        Success message with ticket link
    """
    logger.info(f"Creating X ticket: {title}")

    # Add submitter info to details
    details += f"\n\nSubmitted by: {user_email}"
    details += f"\nSubmitted from: {submitter_ip}"

    incident = {
        'name': title,
        'details': details,
        'CustomFields': {
            'detectionsource': detection_source,
            'isusercontacted': False,
            'securitycategory': 'CAT-5: Scans/Probes/Attempted Access'
        }
    }

    result = ticket_handler.create(incident)
    new_incident_id = result.get('id')
    incident_url = xsoar_prod_ui_base_url + '/Custom/caseinfoid/' + new_incident_id

    return f'Ticket [#{new_incident_id}]({incident_url}) has been created in XSOAR Prod.'


def create_ioc_hunt(
    ioc_title: str,
    iocs: str,
    user_email: str,
    submitter_ip: str,
    ticket_handler: TicketHandler,
    xsoar_prod_ui_base_url: str
) -> str:
    """Create IOC hunt in XSOAR.

    Args:
        ioc_title: IOC hunt title
        iocs: IOCs to hunt for
        user_email: User's email
        submitter_ip: Submitter's IP address
        ticket_handler: XSOAR ticket handler instance
        xsoar_prod_ui_base_url: Base URL for XSOAR prod UI

    Returns:
        Success message with ticket link
    """
    logger.info(f"Creating IOC hunt: {ioc_title}")

    details = iocs
    if user_email:
        details += f"\n\nSubmitted by: {user_email}"
    details += f"\nSubmitted from: {submitter_ip}"

    incident = {
        'name': ioc_title,
        'details': details,
        'type': f'{CONFIG.team_name} IOC Hunt',
        'CustomFields': {
            'huntsource': 'Other'
        }
    }

    result = ticket_handler.create(incident)
    ticket_no = result.get('id')
    incident_url = xsoar_prod_ui_base_url + '/Custom/caseinfoid/' + ticket_no

    return f'A New IOC Hunt has been created in XSOAR. Ticket: [#{ticket_no}]({incident_url})'


def create_threat_hunt(
    threat_title: str,
    threat_description: str,
    user_email: str,
    submitter_ip: str,
    ticket_handler: TicketHandler,
    xsoar_prod_ui_base_url: str
) -> str:
    """Create threat hunt in XSOAR.

    Args:
        threat_title: Threat hunt title
        threat_description: Threat description
        user_email: User's email
        submitter_ip: Submitter's IP address
        ticket_handler: XSOAR ticket handler instance
        xsoar_prod_ui_base_url: Base URL for XSOAR prod UI

    Returns:
        Success message with ticket link
    """
    logger.info(f"Creating threat hunt: {threat_title}")

    details = threat_description
    if user_email:
        details += f"\n\nSubmitted by: {user_email}"
    details += f"\nSubmitted from: {submitter_ip}"

    incident = {
        'name': threat_title,
        'details': details,
        'type': "Threat Hunt"
    }

    result = ticket_handler.create(incident)
    ticket_no = result.get('id')
    incident_url = xsoar_prod_ui_base_url + '/Custom/caseinfoid/' + ticket_no

    return f'A new Threat Hunt has been created in XSOAR. Ticket: [#{ticket_no}]({incident_url})'


def get_oncall_info() -> Dict[str, Any]:
    """Get on-call information.

    Returns:
        On-call person data
    """
    logger.info("Getting on-call info")
    import src.components.oncall as oncall
    return oncall.get_on_call_person()
