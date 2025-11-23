"""XSOAR Ticket Import Handler for Web Dashboard."""

import logging
from typing import Tuple

from services import xsoar

logger = logging.getLogger(__name__)


def import_ticket(source_ticket_number: str) -> Tuple[str, str]:
    """Imports a ticket from one XSOAR environment to another.

    Args:
        source_ticket_number: Ticket number to import

    Returns:
        Tuple of (destination_ticket_number, destination_ticket_link)
    """
    logger.info(f"Importing XSOAR ticket: {source_ticket_number}")
    return xsoar.import_ticket(source_ticket_number)
