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
from my_config import get_config

logger = logging.getLogger(__name__)


@tool
@log_tool_call
def get_xsoar_ticket(ticket_id: str, environment: str = "prod") -> str:
    """Get basic details from an XSOAR ticket.

    USE THIS TOOL when you need to look up information about an XSOAR ticket, such as
    hostname, username, detection source, status, or other ticket fields. This returns
    the raw ticket data without generating a summary.

    Args:
        ticket_id: The XSOAR ticket/incident ID (e.g., '1059495')
        environment: XSOAR environment - 'prod' (default) or 'dev'

    Returns:
        Formatted ticket details including hostname, username, status, etc.
    """
    try:
        # Normalize ticket ID
        ticket_id = ticket_id.strip()
        if ticket_id.upper().startswith("X#"):
            ticket_id = ticket_id[2:]

        # Validate environment
        if environment.lower() == "prod":
            xsoar_env = XsoarEnvironment.PROD
        elif environment.lower() == "dev":
            xsoar_env = XsoarEnvironment.DEV
        else:
            return f"Error: Invalid environment '{environment}'. Must be 'prod' or 'dev'."

        # Initialize ticket handler and fetch data
        ticket_handler = TicketHandler(environment=xsoar_env)
        ticket_data = ticket_handler.get_case_data(ticket_id)

        if not ticket_data:
            return f"Error: Could not fetch ticket {ticket_id}. Please verify the ticket ID exists."

        # Extract key fields
        custom_fields = ticket_data.get('CustomFields', {})

        result_lines = [
            f"**XSOAR Ticket #{ticket_id}**",
            f"**Name:** {ticket_data.get('name', 'Unknown')}",
            f"**Status:** {ticket_data.get('status', 'Unknown')}",
            f"**Phase:** {ticket_data.get('phase', 'Unknown')}",
            f"**Owner:** {ticket_data.get('owner', 'Unassigned')}",
            "",
            "**Key Fields:**",
            f"- Hostname: {custom_fields.get('hostname', 'N/A')}",
            f"- Username: {custom_fields.get('username', 'N/A')}",
            f"- Detection Source: {custom_fields.get('detectionsource', 'N/A')}",
            f"- Security Category: {custom_fields.get('securitycategory', 'N/A')}",
            f"- Device ID: {custom_fields.get('deviceid', 'N/A')}",
            f"- Device Status: {custom_fields.get('devicestatus', 'N/A')}",
            f"- Host Contained: {custom_fields.get('hostcontained', 'N/A')}",
            f"- Source IP: {custom_fields.get('sourceip', 'N/A')}",
        ]

        return "\n".join(result_lines)

    except Exception as e:
        logger.error(f"Error fetching XSOAR ticket {ticket_id}: {e}")
        return f"Error fetching ticket: {str(e)}"


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
    details = ticket_data.get('details', '')

    # Custom fields
    custom_fields = ticket_data.get('CustomFields', {})
    security_category = custom_fields.get('securitycategory', 'Unknown')
    hostname = custom_fields.get('hostname', 'Unknown')
    username = custom_fields.get('username', 'Unknown')
    detection_source = custom_fields.get('detectionsource', 'Unknown')
    action_summary = custom_fields.get('actionsummary', '')

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

    # Add details if available
    if details:
        formatted_text += f"INCIDENT DETAILS:\n{details}\n\n"

    # Add action summary if available
    if action_summary:
        formatted_text += f"ACTION LOG:\n{action_summary}\n\n"

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


def _generate_summary_with_llm(formatted_data: str) -> dict:
    """
    Use the LLM to generate an executive summary from formatted ticket data.

    Args:
        formatted_data: Formatted ticket data and notes

    Returns:
        dict with 'content' and token metrics (input_tokens, output_tokens, etc.)
    """
    import time
    from my_bot.core.state_manager import get_state_manager

    # Default metrics for error cases
    default_metrics = {
        'content': '',
        'input_tokens': 0,
        'output_tokens': 0,
        'total_tokens': 0,
        'prompt_time': 0.0,
        'generation_time': 0.0,
        'tokens_per_sec': 0.0
    }

    state_manager = get_state_manager()
    if not state_manager or not state_manager.is_initialized:
        default_metrics['content'] = "Error: LLM not initialized. Cannot generate summary."
        return default_metrics

    # Use higher temperature for more natural prose in summaries
    summary_llm = state_manager.get_llm_with_temperature(0.4)
    if not summary_llm:
        summary_llm = state_manager.llm  # Fallback to default

    # Craft a precise prompt for the LLM with consistent formatting template
    summary_prompt = f"""{formatted_data}

Generate a CONCISE executive summary following this EXACT format:

🔍 **Incident Overview**
[1-2 sentence summary of what happened - who, what, when, where]

🎯 **Detection**
[Single sentence on how it was detected]

🔧 **Investigation & Remediation**
1. [Key action 1]
2. [Key action 2]
3. [Key action 3]
[Maximum 5 numbered steps - only the most important actions]

✅ **Outcome**
[Single sentence on current status and resolution]

⚠️ **Next Steps & Risks**
• [Risk/action 1]
• [Risk/action 2]
[Maximum 3 bullet points - only critical items]

🛡️ **Proactive Measures**
[Optional - Single sentence on preventive measures, or "None" if not applicable]

CRITICAL FORMATTING RULES - NEVER DEVIATE:
✓ Section headings MUST have emoji prefix, then **bold text** (e.g., "🔍 **Incident Overview**")
✓ NO colon after heading, NO bullets before headings
✓ Blank line BEFORE and AFTER each section for visual separation
✓ Investigation: Numbered list (1., 2., 3.)
✓ Next Steps: Bullet points (•)
✓ Concise, executive-level language (non-technical)
✓ Include ALL sections - use "None" for Proactive Measures if not applicable

Follow this structure exactly with emoji prefixes and proper bold markdown formatting.
"""

    try:
        start_time = time.time()

        # Use higher-temperature LLM for more natural prose
        response = summary_llm.invoke(summary_prompt)

        # Extract token metrics from response
        input_tokens = 0
        output_tokens = 0
        prompt_time = 0.0
        generation_time = 0.0

        if hasattr(response, 'usage_metadata') and response.usage_metadata:
            input_tokens = response.usage_metadata.get('input_tokens', 0)
            output_tokens = response.usage_metadata.get('output_tokens', 0)
        elif hasattr(response, 'response_metadata'):
            metadata = response.response_metadata
            input_tokens = metadata.get('prompt_eval_count', 0)
            output_tokens = metadata.get('eval_count', 0)
            if 'prompt_eval_duration' in metadata:
                prompt_time = metadata['prompt_eval_duration'] / 1e9
            if 'eval_duration' in metadata:
                generation_time = metadata['eval_duration'] / 1e9

        # If timing not available from metadata, use wall clock
        if generation_time == 0:
            generation_time = time.time() - start_time

        tokens_per_sec = output_tokens / generation_time if generation_time > 0 else 0.0

        # Extract content from response
        content = response.content if hasattr(response, 'content') else str(response)

        return {
            'content': content,
            'input_tokens': input_tokens,
            'output_tokens': output_tokens,
            'total_tokens': input_tokens + output_tokens,
            'prompt_time': prompt_time,
            'generation_time': generation_time,
            'tokens_per_sec': tokens_per_sec
        }

    except Exception as e:
        logger.error(f"Error generating summary with LLM: {e}")
        default_metrics['content'] = f"Error generating summary: {str(e)}"
        return default_metrics


def generate_executive_summary_with_metrics(ticket_id: str, environment: str = "prod") -> dict:
    """
    Generate executive summary with token metrics.

    Args:
        ticket_id: The XSOAR ticket/incident ID
        environment: XSOAR environment - "prod" (default) or "dev"

    Returns:
        dict with 'content' and token metrics
    """
    # Default metrics for error cases
    default_metrics = {
        'content': '',
        'input_tokens': 0,
        'output_tokens': 0,
        'total_tokens': 0,
        'prompt_time': 0.0,
        'generation_time': 0.0,
        'tokens_per_sec': 0.0
    }

    try:
        # Normalize ticket ID - strip "X#" prefix if present
        ticket_id = ticket_id.strip()
        if ticket_id.upper().startswith("X#"):
            ticket_id = ticket_id[2:]

        # Validate environment
        if environment.lower() == "prod":
            xsoar_env = XsoarEnvironment.PROD
        elif environment.lower() == "dev":
            xsoar_env = XsoarEnvironment.DEV
        else:
            default_metrics['content'] = f"Error: Invalid environment '{environment}'. Must be 'prod' or 'dev'."
            return default_metrics

        logger.info(f"Generating executive summary for ticket {ticket_id} in {environment} environment")

        # Initialize ticket handler
        ticket_handler = TicketHandler(environment=xsoar_env)

        # Fetch ticket details
        logger.info(f"Fetching ticket details for {ticket_id}...")
        ticket_data = ticket_handler.get_case_data(ticket_id)

        if not ticket_data:
            default_metrics['content'] = f"Error: Could not fetch ticket {ticket_id}. Please verify the ticket ID exists."
            return default_metrics

        # Fetch ticket notes
        logger.info(f"Fetching notes for ticket {ticket_id}...")
        notes = ticket_handler.get_user_notes(ticket_id)

        # Format data for LLM
        formatted_data = _format_ticket_data_for_summary(ticket_data, notes)

        # Generate summary using LLM (now returns dict with metrics)
        logger.info(f"Generating executive summary using LLM...")
        llm_result = _generate_summary_with_llm(formatted_data)

        # Add header to summary with hyperlink to XSOAR ticket
        ticket_name = ticket_data.get('name', 'Unknown Ticket')
        config = get_config()
        ui_base_url = config.xsoar_prod_ui_base_url if xsoar_env == XsoarEnvironment.PROD else config.xsoar_dev_ui_base_url
        ticket_url = f"{ui_base_url}/Custom/caseinfoid/{ticket_id}" if ui_base_url else None

        if ticket_url:
            header = f"📋 **Executive Summary for [Ticket #{ticket_id}]({ticket_url})**\n"
        else:
            header = f"📋 **Executive Summary for Ticket #{ticket_id}**\n"
        header += f"*{ticket_name}*\n\n---\n\n"

        # Combine header with LLM content
        llm_result['content'] = header + llm_result['content']

        logger.info(f"Successfully generated executive summary for ticket {ticket_id}")
        return llm_result

    except Exception as e:
        logger.error(f"Error generating executive summary for ticket {ticket_id}: {e}", exc_info=True)
        default_metrics['content'] = f"Error generating executive summary: {str(e)}\n\nPlease verify:\n- Ticket ID is correct\n- You have access to the XSOAR environment\n- Network connectivity is available"
        return default_metrics


@tool
@log_tool_call
def generate_executive_summary(ticket_id: str, environment: str = "prod") -> str:
    """
    Get details and generate an executive summary for an XSOAR case/ticket/incident.

    USE THIS TOOL when users ask for:
    - Case details or information (e.g., "details of XSOAR case 1023724")
    - Ticket information (e.g., "tell me about XSOAR ticket 929947")
    - Incident summaries (e.g., "summarize XSOAR ticket 123456")
    - Any XSOAR case/ticket/incident queries

    This tool fetches complete ticket details and analyst notes from XSOAR, then generates
    a concise executive summary following a strict format structure.

    DEFAULT FORMAT (use this structure unless user requests different formatting):
    - Section headings: Emoji prefix + **Bold text** (e.g., "🔍 **Incident Overview**")
    - NO colon after headings, NO bullets before headings
    - Blank lines between sections for visual separation
    - Investigation steps: Numbered list (1., 2., 3.)
    - Next Steps: Bullet points (•) for list items
    - If user requests plain text, paragraph format, or no styling, honor that request instead

    SECTIONS (in this order):
    1. 🔍 **Incident Overview** - 1-2 sentence summary
    2. 🎯 **Detection** - Single sentence on detection method
    3. 🔧 **Investigation & Remediation** - Numbered steps (max 5)
    4. ✅ **Outcome** - Single sentence on resolution
    5. ⚠️ **Next Steps & Risks** - Bulleted list (max 3 items)
    6. 🛡️ **Proactive Measures** - Single sentence or "None"

    Args:
        ticket_id: The XSOAR ticket/incident ID (e.g., "123456")
        environment: XSOAR environment - "prod" (default) or "dev"

    Returns:
        Executive summary with consistent formatting structure

    Example:
        generate_executive_summary("929947")
        generate_executive_summary("123456", "dev")
    """
    # Use the metrics version and return just the content
    result = generate_executive_summary_with_metrics(ticket_id, environment)
    return result['content']


@tool
@log_tool_call
def add_note_to_xsoar_ticket(ticket_id: str, note_text: str, environment: str = "prod") -> str:
    """
    Add a note to an existing XSOAR ticket/incident.

    USE THIS TOOL when users ask to:
    - Write findings or results to an XSOAR ticket
    - Add notes or comments to a case
    - Document analysis results in XSOAR
    - Update a ticket with enrichment data

    This is useful for multi-tool workflows where you enrich IOCs and then
    write the results to an XSOAR ticket.

    Args:
        ticket_id: The XSOAR ticket/incident ID (e.g., "123456")
        note_text: The note content to add (supports Markdown formatting)
        environment: XSOAR environment - "prod" (default) or "dev"

    Returns:
        Success or error message

    Example:
        add_note_to_xsoar_ticket("929947", "## VT Analysis\\nIP 1.2.3.4 is clean.")
        add_note_to_xsoar_ticket("123456", "Enrichment complete. No threats found.", "dev")
    """
    try:
        # Normalize ticket ID - strip "X#" prefix if present
        ticket_id = ticket_id.strip()
        if ticket_id.upper().startswith("X#"):
            ticket_id = ticket_id[2:]

        # Validate inputs
        if not ticket_id:
            return "Error: ticket_id cannot be empty"
        if not note_text or not note_text.strip():
            return "Error: note_text cannot be empty"

        # Validate environment
        if environment.lower() == "prod":
            xsoar_env = XsoarEnvironment.PROD
        elif environment.lower() == "dev":
            xsoar_env = XsoarEnvironment.DEV
        else:
            return f"Error: Invalid environment '{environment}'. Must be 'prod' or 'dev'."

        logger.info(f"Adding note to XSOAR ticket {ticket_id} in {environment} environment")

        # Initialize ticket handler
        ticket_handler = TicketHandler(environment=xsoar_env)

        # Add the note
        result = ticket_handler.create_new_entry_in_existing_ticket(
            incident_id=ticket_id,
            entry_data=note_text,
            markdown=True
        )

        if result:
            logger.info(f"Successfully added note to ticket {ticket_id}")
            return f"Successfully added note to XSOAR ticket #{ticket_id}"
        else:
            return f"Note may have been added to ticket #{ticket_id}, but response was empty"

    except ValueError as e:
        logger.error(f"Validation error adding note to ticket {ticket_id}: {e}")
        return f"Error: {str(e)}"
    except Exception as e:
        logger.error(f"Error adding note to ticket {ticket_id}: {e}", exc_info=True)
        return f"Error adding note to ticket: {str(e)}"


# =============================================================================
# SAMPLE PROMPTS FOR LLM GUIDANCE
# =============================================================================
# Use these prompts to help users discover XSOAR summary capabilities:
#
# - "Summarize XSOAR ticket 123456"
# - "Get details for XSOAR case 929947"
# - "What's the status of XSOAR incident 456789?"
# - "Generate executive summary for X#123456"
# - "Tell me about XSOAR ticket 789012"
# - "Add a note to XSOAR ticket 123456: Investigation complete, no threats found"
# - "Write these findings to XSOAR case 929947"
# - "Update XSOAR ticket 456789 with VT enrichment results"
# =============================================================================