"""
XSOAR Summary Tools Module

Tools for generating executive summaries and reports from XSOAR tickets.
"""

import logging
from typing import Dict, Any
from langchain_core.tools import tool

# Import tool logging decorator
from src.utils.tool_decorator import log_tool_call
from services.xsoar.ticket_handler import TicketHandler
from src.utils.xsoar_enums import XsoarEnvironment

logger = logging.getLogger(__name__)


def _format_ticket_data_for_summary(ticket_data: Dict[str, Any], notes: list) -> str:
    """
    Format ticket data and notes into a structured text for LLM processing.

    Args:
        ticket_data: Ticket details from get_case_data()
        notes: List of user notes from get_user_notes()

    Returns:
        Formatted text ready for LLM summary generation
    """
    # Extract key ticket information
    ticket_id = ticket_data.get('id', 'Unknown')
    ticket_name = ticket_data.get('name', 'No title')
    severity = ticket_data.get('severity', 'Unknown')
    status_name = ticket_data.get('status', 'Unknown')
    close_notes = ticket_data.get('closeNotes', '')
    close_reason = ticket_data.get('closeReason', '')

    # Custom fields
    custom_fields = ticket_data.get('CustomFields', {})
    security_category = custom_fields.get('securitycategory', 'Unknown')
    hostname = custom_fields.get('hostname', 'Unknown')
    username = custom_fields.get('username', 'Unknown')
    detection_source = custom_fields.get('detectionsource', 'Unknown')

    # Build formatted text
    formatted_text = f"""XSOAR Ticket #{ticket_id} - Executive Summary Request

TICKET DETAILS:
- Title: {ticket_name}
- Severity: {severity}
- Status: {status_name}
- Security Category: {security_category}
- Detection Source: {detection_source}
- Hostname: {hostname}
- Username: {username}

"""

    # Add close notes if ticket is closed
    if close_notes or close_reason:
        formatted_text += "CLOSE NOTES/RESOLUTION:\n"
        if close_reason:
            formatted_text += f"Close Reason: {close_reason}\n"
        if close_notes:
            formatted_text += f"{close_notes}\n"
        formatted_text += "\n"

    # Add analyst notes if available
    if notes:
        formatted_text += "ANALYST NOTES (chronological order):\n"
        for i, note in enumerate(notes, 1):
            author = note.get('author', 'Unknown')
            created_at = note.get('created_at', 'Unknown time')
            note_text = note.get('note_text', '')
            formatted_text += f"\n{i}. [{created_at}] {author}:\n{note_text}\n"
    else:
        formatted_text += "ANALYST NOTES: No notes available\n"

    return formatted_text


def _generate_summary_with_llm(formatted_data: str) -> str:
    """
    Use the LLM to generate an executive summary from formatted ticket data.

    Args:
        formatted_data: Formatted ticket data and notes

    Returns:
        Executive summary as formatted text
    """
    from my_bot.core.state_manager import get_state_manager

    state_manager = get_state_manager()
    if not state_manager or not state_manager.is_initialized:
        return "Error: LLM not initialized. Cannot generate summary."

    # Craft a precise prompt for the LLM
    summary_prompt = f"""{formatted_data}

Please generate a sharp, crisp executive summary of this security ticket. The summary should:
1. Be 5-6 bullet points maximum
2. Focus on the "who, what, when, where, why" of the incident
3. Highlight key actions taken and outcomes
4. Be written for executive/management audience (non-technical)
5. Include any outstanding risks or next steps

Format as bullet points using markdown (- prefix).
"""

    try:
        # Use the LLM directly without tools
        response = state_manager.llm.invoke(summary_prompt)

        # Extract content from response
        if hasattr(response, 'content'):
            return response.content
        else:
            return str(response)

    except Exception as e:
        logger.error(f"Error generating summary with LLM: {e}")
        return f"Error generating summary: {str(e)}"


@tool
@log_tool_call
def generate_executive_summary(ticket_id: str, environment: str = "prod") -> str:
    """
    Generate an executive summary for an XSOAR ticket.

    This tool fetches ticket details and analyst notes from XSOAR, then uses AI
    to generate a concise 5-6 bullet point executive summary suitable for
    management review.

    Args:
        ticket_id: The XSOAR ticket/incident ID (e.g., "123456")
        environment: XSOAR environment - "prod" (default) or "dev"

    Returns:
        Executive summary with 5-6 sharp, crisp bullet points

    Example:
        generate_executive_summary("929947")
        generate_executive_summary("123456", "dev")
    """
    try:
        # Validate environment
        if environment.lower() == "prod":
            xsoar_env = XsoarEnvironment.PROD
        elif environment.lower() == "dev":
            xsoar_env = XsoarEnvironment.DEV
        else:
            return f"Error: Invalid environment '{environment}'. Must be 'prod' or 'dev'."

        logger.info(f"Generating executive summary for ticket {ticket_id} in {environment} environment")

        # Initialize ticket handler
        ticket_handler = TicketHandler(environment=xsoar_env)

        # Fetch ticket details
        logger.info(f"Fetching ticket details for {ticket_id}...")
        ticket_data = ticket_handler.get_case_data(ticket_id)

        if not ticket_data:
            return f"Error: Could not fetch ticket {ticket_id}. Please verify the ticket ID exists."

        # Fetch ticket notes
        logger.info(f"Fetching notes for ticket {ticket_id}...")
        notes = ticket_handler.get_user_notes(ticket_id)

        # Format data for LLM
        formatted_data = _format_ticket_data_for_summary(ticket_data, notes)

        # Generate summary using LLM
        logger.info(f"Generating executive summary using LLM...")
        summary = _generate_summary_with_llm(formatted_data)

        # Add header to summary
        ticket_name = ticket_data.get('name', 'Unknown Ticket')
        result = f"**Executive Summary for Ticket #{ticket_id}**\n"
        result += f"*{ticket_name}*\n\n"
        result += summary

        logger.info(f"Successfully generated executive summary for ticket {ticket_id}")
        return result

    except Exception as e:
        logger.error(f"Error generating executive summary for ticket {ticket_id}: {e}", exc_info=True)
        return f"Error generating executive summary: {str(e)}\n\nPlease verify:\n- Ticket ID is correct\n- You have access to the XSOAR environment\n- Network connectivity is available"