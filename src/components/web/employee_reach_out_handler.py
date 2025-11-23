"""Employee Reach Out Handler for Web Dashboard."""

import logging
import os
import tempfile
from typing import Dict, Any, Optional, Tuple

from services.xsoar import TicketHandler

logger = logging.getLogger(__name__)


def get_employee_reach_out_task_info(
    ticket_id: str,
    ticket_handler: TicketHandler
) -> Optional[str]:
    """Get employee reach out task information.

    Args:
        ticket_id: XSOAR ticket ID
        ticket_handler: XSOAR ticket handler instance

    Returns:
        Task ID if found, None if task already completed
    """
    logger.info(f"Getting employee reach out task info for ticket {ticket_id}")

    playbook_task_name = 'Does the employee recognize the alerted activity?'
    task_id = ticket_handler.get_playbook_task_id(ticket_id, target_task_name=playbook_task_name)

    return task_id


def submit_employee_response(
    recognized: str,
    ticket_id: str,
    comments: str,
    file_data: Any,
    ticket_handler: TicketHandler
) -> Tuple[bool, str]:
    """Handle employee reach out form submission.

    Args:
        recognized: Employee's response ('yes' or 'no')
        ticket_id: XSOAR ticket ID
        comments: Employee comments
        file_data: File attachment (if any)
        ticket_handler: XSOAR ticket handler instance

    Returns:
        Tuple of (success, message)
    """
    logger.info(f"Processing employee response: recognized={recognized}, ticket_id={ticket_id}")

    try:
        # Complete the XSOAR task
        ticket_handler.complete_task(
            ticket_id,
            'Does the employee recognize the alerted activity?',
            recognized
        )
        logger.info(f"Completed employee reach out task in ticket {ticket_id} with response: {recognized}")

        # Add comments if provided
        if comments:
            note_content = f"Employee Comments:\n{comments}"
            ticket_handler.create_new_entry_in_existing_ticket(ticket_id, note_content)
            logger.info(f"Added employee comments to ticket {ticket_id}")

        # Handle file attachment if present
        if file_data and hasattr(file_data, 'filename') and file_data.filename:
            _handle_file_attachment(file_data, ticket_id, ticket_handler)

        return True, 'Thank you for your response. An analyst will contact you if required.'

    except Exception as exc:
        logger.error(f"Error completing XSOAR task: {exc}")
        return False, f'Failed to complete XSOAR task: {str(exc)}'


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
            comment="Employee provided attachment"
        )
        logger.info(f"Uploaded attachment {file_data.filename} to ticket {ticket_id}")

    finally:
        # Clean up temporary file
        if temp_file_path and os.path.exists(temp_file_path):
            os.remove(temp_file_path)
            logger.debug(f"Cleaned up temporary file {temp_file_path}")
