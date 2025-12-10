"""XSOAR Ticket Import Handler for Web Dashboard."""

import logging
import os
import tempfile
from typing import Any, Optional, Tuple

from services import xsoar
from services.xsoar import TicketHandler

logger = logging.getLogger(__name__)


def import_ticket(
    source_ticket_number: str,
    file_data: Optional[Any] = None,
    ticket_handler: Optional[TicketHandler] = None
) -> Tuple[str, str]:
    """Imports a ticket from one XSOAR environment to another.

    Args:
        source_ticket_number: Ticket number to import
        file_data: Optional file attachment to upload to the destination ticket
        ticket_handler: XSOAR ticket handler instance (required if file_data provided)

    Returns:
        Tuple of (destination_ticket_number, destination_ticket_link)
    """
    logger.info(f"Importing XSOAR ticket: {source_ticket_number}")
    destination_ticket_number, destination_ticket_link = xsoar.import_ticket(source_ticket_number)

    # Handle file attachment if present
    if file_data and hasattr(file_data, 'filename') and file_data.filename:
        if not ticket_handler:
            logger.warning("File attachment provided but no ticket_handler available")
        else:
            _handle_file_attachment(file_data, destination_ticket_number, ticket_handler)

    return destination_ticket_number, destination_ticket_link


def _handle_file_attachment(file_data: Any, ticket_id: str, ticket_handler: TicketHandler) -> None:
    """Handle file attachment upload to XSOAR.

    Args:
        file_data: File data from request
        ticket_id: XSOAR ticket ID
        ticket_handler: XSOAR ticket handler instance
    """
    logger.info(f"Handling file attachment: {file_data.filename}")

    temp_fd, temp_file_path = tempfile.mkstemp(suffix=f"_{file_data.filename}")
    try:
        # Close the file descriptor and write the file
        os.close(temp_fd)
        file_data.save(temp_file_path)
        logger.info(f"Saved attachment {file_data.filename} to temporary file {temp_file_path}")

        # Upload to XSOAR ticket
        ticket_handler.upload_file_to_ticket(
            ticket_id,
            temp_file_path,
            comment="Attachment from ticket import"
        )
        logger.info(f"Uploaded attachment {file_data.filename} to ticket {ticket_id}")

    finally:
        # Clean up temporary file
        if temp_file_path and os.path.exists(temp_file_path):
            os.remove(temp_file_path)
            logger.debug(f"Cleaned up temporary file {temp_file_path}")
