"""XSOAR Dashboard Handler for Web Dashboard."""

import logging
from typing import Dict, Any, List, Tuple

from services.xsoar import TicketHandler

logger = logging.getLogger(__name__)


def get_xsoar_incidents(
    ticket_handler: TicketHandler,
    query: str,
    period: str,
    size: int = 50
) -> List[Dict[str, Any]]:
    """Get XSOAR incidents with search and pagination.

    Args:
        ticket_handler: XSOAR ticket handler instance
        query: Search query
        period: Time period filter
        size: Number of incidents to return

    Returns:
        List of incidents
    """
    logger.info(f"Fetching XSOAR incidents: query={query}, period={period}, size={size}")
    return ticket_handler.get_tickets(query, period, size)


def get_xsoar_incident_detail(
    ticket_handler: TicketHandler,
    incident_id: str
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Get XSOAR incident details.

    Args:
        ticket_handler: XSOAR ticket handler instance
        incident_id: Incident ID to fetch

    Returns:
        Tuple of (incident data, entries list)
    """
    logger.info(f"Fetching XSOAR incident detail: {incident_id}")
    incident = ticket_handler.get_case_data(incident_id)
    entries = ticket_handler.get_entries(incident_id)
    return incident, entries


def get_xsoar_incident_entries(
    ticket_handler: TicketHandler,
    incident_id: str
) -> List[Dict[str, Any]]:
    """Get incident entries/comments.

    Args:
        ticket_handler: XSOAR ticket handler instance
        incident_id: Incident ID

    Returns:
        List of entries
    """
    logger.info(f"Fetching entries for incident: {incident_id}")
    return ticket_handler.get_entries(incident_id)


def link_xsoar_incidents(
    ticket_handler: TicketHandler,
    incident_id: str,
    link_incident_id: str
) -> Dict[str, Any]:
    """Link two XSOAR incidents.

    Args:
        ticket_handler: XSOAR ticket handler instance
        incident_id: Primary incident ID
        link_incident_id: Incident ID to link

    Returns:
        Result from link operation
    """
    logger.info(f"Linking incidents: {incident_id} -> {link_incident_id}")
    return ticket_handler.link_tickets(incident_id, link_incident_id)


def add_participant_to_incident(
    ticket_handler: TicketHandler,
    incident_id: str,
    email: str
) -> Dict[str, Any]:
    """Add participant to XSOAR incident.

    Args:
        ticket_handler: XSOAR ticket handler instance
        incident_id: Incident ID
        email: Email of participant to add

    Returns:
        Result from add participant operation
    """
    logger.info(f"Adding participant {email} to incident {incident_id}")
    return ticket_handler.add_participant(incident_id, email)
