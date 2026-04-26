"""
XSOAR Summary Tools Module

Tools for generating executive summaries and reports from XSOAR tickets.
"""

import logging
from typing import Dict, Any, Union
from langchain_core.tools import tool

# Import tool logging decorator
from src.utils.tool_decorator import log_tool_call
from services.xsoar.ticket_handler import TicketHandler
from src.utils.xsoar_enums import XsoarEnvironment
from my_config import get_config

logger = logging.getLogger(__name__)


# XSOAR enum mappings (severity/status codes → human text)
_XSOAR_SEVERITY = {0: "Unknown", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
_XSOAR_STATUS = {0: "Pending", 1: "Active", 2: "Closed", 3: "Archived"}


def _is_populated(value: Any) -> bool:
    """True if a custom field value carries real content (not None/empty/placeholder)."""
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip() not in ("", "null", "N/A")
    if isinstance(value, (list, dict)):
        return len(value) > 0
    return True


def _flatten(value: Any) -> str:
    """Render a custom-field value for display, unwrapping single-element lists."""
    if isinstance(value, list):
        if len(value) == 1:
            return str(value[0])
        return ", ".join(str(v) for v in value)
    return str(value)


@tool
@log_tool_call
def get_xsoar_ticket(ticket_id: Union[str, int], environment: str = "prod") -> str:
    """Get details from an XSOAR ticket including verdicts, incident description, and recent analyst notes.

    USE THIS TOOL when you need to look up information about an XSOAR ticket. Works for
    all ticket types (endpoint, email, identity, phishing, NUC, etc.) — endpoint-specific
    fields are only shown when populated.

    Args:
        ticket_id: The XSOAR ticket/incident ID (e.g., '1059495')
        environment: XSOAR environment - 'prod' (default) or 'dev'

    Returns:
        Formatted ticket details: name, type, severity, status, phase, owner,
        analyst verdicts (triage/final/impact), incident description, endpoint
        context if applicable, and the most recent analyst notes.
    """
    try:
        # Normalize ticket ID
        # Coerce to string — LLMs sometimes pass numeric ticket IDs as JSON ints
        ticket_id = str(ticket_id).strip()
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

        cf = ticket_data.get('CustomFields', {}) or {}

        # Header: name, type, severity (text), status (text), phase, owner
        sev_raw = ticket_data.get('severity')
        status_raw = ticket_data.get('status')
        sev_text = _XSOAR_SEVERITY.get(sev_raw, str(sev_raw)) if sev_raw is not None else "Unknown"
        status_text = _XSOAR_STATUS.get(status_raw, str(status_raw)) if status_raw is not None else "Unknown"
        ticket_type = ticket_data.get('type', '')

        result_lines = [
            f"**XSOAR Ticket #{ticket_id}**" + (f" ({ticket_type})" if ticket_type else ""),
            f"**Name:** {(ticket_data.get('name') or 'Unknown').strip()}",
            f"**Severity:** {sev_text}",
            f"**Status:** {status_text}",
            f"**Phase:** {ticket_data.get('phase') or 'Unknown'}",
            f"**Owner:** {ticket_data.get('owner') or 'Unassigned'}",
            f"**Detection Source:** {cf.get('detectionsource') or 'N/A'}",
            f"**Security Category:** {cf.get('securitycategory') or 'N/A'}",
        ]

        sub_cat = cf.get('securitysubcategory')
        if _is_populated(sub_cat):
            result_lines.append(f"**Security Sub-Category:** {_flatten(sub_cat)}")

        region = cf.get('affectedregion')
        if _is_populated(region):
            result_lines.append(f"**Affected Region:** {_flatten(region)}")

        escalation = cf.get('escalationstate')
        if _is_populated(escalation):
            result_lines.append(f"**Escalation State:** {_flatten(escalation)}")

        # Incident description (the most useful field for non-endpoint cases)
        details = ticket_data.get('details') or ''
        if details.strip():
            result_lines.append("")
            result_lines.append("**Incident Details:**")
            result_lines.append(details.strip())

        # Analyst verdicts — surface these so the LLM can reason about impact
        # without re-doing analysis the analyst already did
        verdict_fields = [
            ('Triage Verdict', cf.get('triageverdict')),
            ('Final Triage Verdict', cf.get('triagefinalverdict')),
            ('Impact', cf.get('impact')),
            ('Email Classification', cf.get('emailclassification')),
            ('Root Cause', cf.get('rootcause')),
            ('Close Reason', ticket_data.get('closeReason')),
        ]
        verdicts = [(label, val) for label, val in verdict_fields if _is_populated(val)]
        if verdicts:
            result_lines.append("")
            result_lines.append("**Analyst Verdicts:**")
            for label, val in verdicts:
                result_lines.append(f"- {label}: {_flatten(val)}")

        # Endpoint context — only show when this is actually an endpoint case
        endpoint_fields = [
            ('Hostname', cf.get('hostname')),
            ('Username', cf.get('username')),
            ('Device ID', cf.get('deviceid')),
            ('Device OS', cf.get('deviceostype')),
            ('Device Status', cf.get('devicestatus')),
            ('Host Contained', cf.get('hostcontained') or cf.get('contained')),
            ('Source IP', cf.get('sourceip')),
        ]
        populated_endpoint = [(label, val) for label, val in endpoint_fields if _is_populated(val)]
        # Heuristic: only show the section if at least hostname OR deviceid is populated
        if any(label in ('Hostname', 'Device ID') for label, _ in populated_endpoint):
            result_lines.append("")
            result_lines.append("**Endpoint Context:**")
            for label, val in populated_endpoint:
                result_lines.append(f"- {label}: {_flatten(val)}")

        # Recent analyst notes (latest 5) — these often contain the actual investigation
        try:
            notes = ticket_handler.get_user_notes(ticket_id) or []
        except Exception as e:
            logger.warning(f"Could not fetch notes for ticket {ticket_id}: {e}")
            notes = []

        if notes:
            result_lines.append("")
            result_lines.append(f"**Recent Analyst Notes (latest {min(5, len(notes))} of {len(notes)}):**")
            for note in notes[:5]:
                author = note.get('author', 'Unknown')
                created = note.get('created_at', '')
                text = (note.get('note_text') or '').strip()
                # Truncate long notes so the result stays readable
                if len(text) > 600:
                    text = text[:600] + '... [truncated]'
                result_lines.append(f"\n[{created}] {author}:")
                result_lines.append(text)

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
✓ Only ONE blank line before each section heading - never two or more
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

        from my_bot.utils.llm_factory import extract_token_metrics
        if hasattr(response, 'usage_metadata') and response.usage_metadata:
            input_tokens = response.usage_metadata.get('input_tokens', 0)
            output_tokens = response.usage_metadata.get('output_tokens', 0)
        elif hasattr(response, 'response_metadata'):
            m = extract_token_metrics(response.response_metadata)
            input_tokens = m['input_tokens']
            output_tokens = m['output_tokens']
            prompt_time = m['prompt_time']
            generation_time = m['generation_time']

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
        # Coerce to string — LLMs sometimes pass numeric ticket IDs as JSON ints
        ticket_id = str(ticket_id).strip()
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
        header += f"*{ticket_name}*\n---\n"

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
def generate_executive_summary(ticket_id: Union[str, int], environment: str = "prod") -> str:
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
    - Single blank line before each section heading (compact layout)
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
    # Use the metrics version and return just the content.
    # Prefix with FINAL_RESPONSE sentinel so the agentic loop returns this
    # directly without an extra LLM call to "present" it.
    from my_bot.core.state_manager import FINAL_RESPONSE_PREFIX
    result = generate_executive_summary_with_metrics(ticket_id, environment)
    return FINAL_RESPONSE_PREFIX + result['content']


@tool
@log_tool_call
def add_note_to_xsoar_ticket(ticket_id: Union[str, int], note_text: str, environment: str = "prod") -> str:
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
        # Coerce to string — LLMs sometimes pass numeric ticket IDs as JSON ints
        ticket_id = str(ticket_id).strip()
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


@tool
@log_tool_call
def attach_file_to_xsoar_ticket(ticket_id: Union[str, int], file_path: str, comment: str = "", environment: str = "prod") -> str:
    """
    Attach a file to an XSOAR ticket's attachments field.

    USE THIS TOOL when users ask to:
    - Attach a file to an XSOAR ticket
    - Upload evidence or artifacts to a case
    - Add browser history, logs, or other files to a ticket

    Args:
        ticket_id: The XSOAR ticket/incident ID (e.g., "123456")
        file_path: Full path to the file to attach (e.g., "/tmp/excel_exports/browser_history_HOST123_20250204.xlsx")
        comment: Optional comment describing the file
        environment: XSOAR environment - "prod" (default) or "dev"

    Returns:
        Success or error message

    Example:
        attach_file_to_xsoar_ticket("929947", "/tmp/excel_exports/browser_history_HOST123.xlsx", "Browser history from HOST123")
    """
    import os

    try:
        # Normalize ticket ID - strip "X#" prefix if present
        # Coerce to string — LLMs sometimes pass numeric ticket IDs as JSON ints
        ticket_id = str(ticket_id).strip()
        if ticket_id.upper().startswith("X#"):
            ticket_id = ticket_id[2:]

        # Validate inputs
        if not ticket_id:
            return "Error: ticket_id cannot be empty"
        if not file_path or not file_path.strip():
            return "Error: file_path cannot be empty"
        if not os.path.exists(file_path):
            return f"Error: File not found: {file_path}"

        # Validate environment
        if environment.lower() == "prod":
            xsoar_env = XsoarEnvironment.PROD
        elif environment.lower() == "dev":
            xsoar_env = XsoarEnvironment.DEV
        else:
            return f"Error: Invalid environment '{environment}'. Must be 'prod' or 'dev'."

        logger.info(f"Attaching file {file_path} to XSOAR ticket {ticket_id} in {environment} environment")

        # Initialize ticket handler
        ticket_handler = TicketHandler(environment=xsoar_env)

        # Upload the file
        result = ticket_handler.upload_file_to_attachment(
            incident_id=ticket_id,
            file_path=file_path,
            comment=comment or f"File attached via the security assistant bot: {os.path.basename(file_path)}"
        )

        file_name = os.path.basename(file_path)
        logger.info(f"Successfully attached {file_name} to ticket {ticket_id}")
        return f"✅ Successfully attached **{file_name}** to XSOAR ticket #{ticket_id}"

    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        return f"Error: {str(e)}"
    except ValueError as e:
        logger.error(f"Validation error attaching file to ticket {ticket_id}: {e}")
        return f"Error: {str(e)}"
    except Exception as e:
        logger.error(f"Error attaching file to ticket {ticket_id}: {e}", exc_info=True)
        return f"Error attaching file to ticket: {str(e)}"


@tool
@log_tool_call
def triage_xsoar_ticket(ticket_id: Union[str, int]) -> str:
    """Run Sentinel Triage on an XSOAR ticket: enrich from source platform, AI verdict, similar tickets.

    USE THIS TOOL when users ask to:
    - Triage an XSOAR ticket (e.g., "triage 1059495", "triage XSOAR ticket 123456")
    - Get an AI verdict on a security alert
    - Analyze a ticket with enrichment from QRadar or CrowdStrike

    This runs the full Sentinel Triage pipeline:
    1. Fetches the XSOAR ticket
    2. Enriches IOCs (VirusTotal, AbuseIPDB, Recorded Future)
    3. Fetches source alert details (QRadar offense or CrowdStrike detection)
    4. Runs LLM triage for AI verdict, risk/mitigating factors
    5. Finds similar past tickets via semantic search
    6. Returns a formatted triage report

    Args:
        ticket_id: The XSOAR ticket/incident ID (e.g., "1059495")

    Returns:
        Formatted triage report with AI verdict, enrichment, and similar tickets
    """
    from my_bot.core.state_manager import FINAL_RESPONSE_PREFIX

    try:
        # Coerce to string — LLMs sometimes pass numeric ticket IDs as JSON ints
        ticket_id = str(ticket_id).strip()
        if ticket_id.upper().startswith("X#"):
            ticket_id = ticket_id[2:]

        logger.info(f"On-demand triage requested for XSOAR ticket {ticket_id}")

        # Fetch raw ticket data
        ticket_handler = TicketHandler(environment=XsoarEnvironment.PROD)
        ticket_data = ticket_handler.get_case_data(ticket_id)

        if not ticket_data:
            return FINAL_RESPONSE_PREFIX + f"Error: Could not fetch ticket {ticket_id}. Please verify the ticket ID exists."

        from src.components.xsoar_alert_triage.xsoar_triage_pipeline import XsoarTriagePipeline

        # No webex_api/room_id — on-demand triage should NOT send cards to
        # the prod Sentinel Triage room.  The bot replies inline instead.
        pipeline = XsoarTriagePipeline()
        result = pipeline.triage_ticket(ticket_data)

        if not result:
            return FINAL_RESPONSE_PREFIX + f"Triage failed for ticket {ticket_id}. The LLM may be unavailable."

        # Format result as markdown
        from webex_bots.cards.sentinel_cards import build_xsoar_triage_markdown

        markdown = build_xsoar_triage_markdown(result)

        # Stash triage result for the bot to send an action card inline
        import threading
        _triage_results = getattr(triage_xsoar_ticket, '_triage_results', {})
        _triage_results[threading.current_thread().ident] = result
        triage_xsoar_ticket._triage_results = _triage_results

        return FINAL_RESPONSE_PREFIX + markdown

    except Exception as e:
        logger.error(f"On-demand triage failed for ticket {ticket_id}: {e}", exc_info=True)
        return FINAL_RESPONSE_PREFIX + f"Error triaging ticket {ticket_id}: {str(e)}"


@tool
@log_tool_call
def qa_review_xsoar_ticket(ticket_id: Union[str, int]) -> str:
    """QA review an XSOAR ticket: evaluate investigation quality, impact classification,
    close notes, SLA compliance, and flag concerns.

    USE THIS TOOL when users ask to:
    - QA or quality-review an XSOAR ticket
    - Check if a ticket was handled properly
    - Review a closed ticket for completeness

    Args:
        ticket_id: The XSOAR ticket/incident ID (e.g., '1059495' or 'X#1059495')

    Returns:
        Formatted QA review with PASS/CONCERN/FAIL verdicts per criterion
        and an overall GOOD/NEEDS REVIEW/POOR rating.
    """
    from my_bot.core.state_manager import FINAL_RESPONSE_PREFIX
    from src.components.qa_tickets import (
        _build_qa_prompt, _call_llm, _find_similar_well_handled,
    )

    try:
        ticket_id = str(ticket_id).strip()
        if ticket_id.upper().startswith("X#"):
            ticket_id = ticket_id[2:]

        ticket_handler = TicketHandler(environment=XsoarEnvironment.PROD)
        ticket_data = ticket_handler.get_case_data(ticket_id)

        if not ticket_data:
            return FINAL_RESPONSE_PREFIX + f"Could not fetch ticket {ticket_id}."

        try:
            notes = ticket_handler.get_user_notes(ticket_id)
        except Exception as e:
            logger.warning(f"Failed to fetch notes for ticket {ticket_id}: {e}")
            notes = []

        prompt = _build_qa_prompt(ticket_data, notes)
        llm_review = _call_llm(prompt)
        similar_ref = _find_similar_well_handled(ticket_data)

        config = get_config()
        url = f"{config.xsoar_prod_ui_base_url}/Custom/caseinfoid/{ticket_id}"
        name = (ticket_data.get('name', '') or '')[:80]
        impact = ticket_data.get('CustomFields', {}).get('impact', '?')
        ticket_type = ticket_data.get('type', '?')

        ref_block = f"\n\n{similar_ref}" if similar_ref else ''
        result = (
            f"🔎 **QA Review: X#{ticket_id}** — {name}\n"
            f"📌 **Impact:** {impact} · **Type:** {ticket_type}\n"
            f"🔗 [View in XSOAR]({url})\n\n"
            f"{llm_review}{ref_block}"
        )
        return FINAL_RESPONSE_PREFIX + result

    except Exception as e:
        logger.error(f"QA review failed for ticket {ticket_id}: {e}", exc_info=True)
        return FINAL_RESPONSE_PREFIX + f"Error reviewing ticket {ticket_id}: {str(e)}"