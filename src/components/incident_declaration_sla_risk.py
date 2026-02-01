import logging
from datetime import datetime

import pytz
from tenacity import retry, stop_after_attempt, wait_exponential, before_sleep_log
from webexpythonsdk import WebexAPI

from my_config import get_config
from services.xsoar import TicketHandler, XsoarEnvironment

CONFIG = get_config()
# Configure timeout to prevent hanging if Webex API is slow/down
# Increased from 60s to 180s to handle network congestion
webex_api = WebexAPI(
    access_token=CONFIG.webex_bot_access_token_soar,
    single_request_timeout=180  # 180 second timeout (3 minutes)
)

# Configure logging for better error tracking
logger = logging.getLogger(__name__)


def parse_due_date(due_date_str):
    """Parse due date string with multiple format support, including nanoseconds."""
    if not due_date_str:
        return None

    # Handle nanosecond precision by truncating to microseconds
    if '.' in due_date_str:
        date_part, frac_part = due_date_str.split('.', 1)
        if 'Z' in frac_part:
            frac_digits, z = frac_part.split('Z', 1)
            # Truncate or pad to 6 digits for microseconds
            frac_digits = (frac_digits + '000000')[:6]
            due_date_str = f"{date_part}.{frac_digits}Z"

    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",  # With microseconds
        "%Y-%m-%dT%H:%M:%SZ"  # Without microseconds
    ]

    for fmt in formats:
        try:
            return datetime.strptime(due_date_str, fmt).replace(tzinfo=pytz.utc)
        except ValueError:
            continue

    # If parsing fails, log and return None instead of raising exception
    logger.error(f"Unable to parse date format: {due_date_str}")
    return None


def calculate_seconds_remaining(due_date_utc):
    """Calculate seconds remaining until SLA breach."""
    now_utc = datetime.now(pytz.utc)
    delta = due_date_utc - now_utc
    seconds_remaining = int(delta.total_seconds())

    # If already past due date, return 0 (breached)
    if seconds_remaining < 0:
        return 0

    return seconds_remaining


def process_ticket(ticket):
    """Process a single ticket and return urgency data."""
    ticket_id = ticket.get('id')
    incident_sla = ticket.get('CustomFields', {}).get('sirtincidentnotificationsla', {})
    due_date_str = incident_sla.get('dueDate')

    # Check if SLA is already breached
    breach_triggered = incident_sla.get('breachTriggered', False)
    run_status = incident_sla.get('runStatus', '')

    try:
        # If already breached or ended, treat as 0 seconds remaining
        if breach_triggered or run_status == 'ended':
            return 0, ticket, due_date_str

        if due_date_str:
            due_date_utc = parse_due_date(due_date_str)
            if due_date_utc:
                seconds_remaining = calculate_seconds_remaining(due_date_utc)
                # Double-check: if calculation shows past due, return 0
                if seconds_remaining < 0:
                    seconds_remaining = 0
            else:
                seconds_remaining = 0  # Treat as urgent if parsing fails
        else:
            logger.warning(f"No due date found for ticket {ticket_id}")
            seconds_remaining = 0  # Treat as urgent if no due date

        return seconds_remaining, ticket, due_date_str

    except Exception as e:
        logger.error(f"Error processing ticket {ticket_id}: {e}")
        return 0, ticket, due_date_str  # Treat as urgent if we can't calculate


def build_ticket_message(seconds_remaining, ticket, index, due_date_str=None):
    """Build formatted message for a single ticket at risk."""
    ticket_id = ticket.get('id')
    ticket_name = ticket.get('name') or ticket.get('title') or 'No Title'
    incident_url = CONFIG.xsoar_prod_ui_base_url + '/Custom/caseinfoid/' + ticket_id

    # Get ticket owner - display without mention to avoid "user not in room" errors
    owner_email = ticket.get('owner')
    if owner_email and '@' in owner_email:
        # Just display username without @mention (since user may not be in the room)
        owner_text = f"**{owner_email.split('@')[0]}**"
    else:
        owner_text = owner_email or 'Unassigned'

    # Format time remaining
    minutes = seconds_remaining // 60
    seconds = seconds_remaining % 60
    if minutes > 0:
        time_text = f"{minutes} min{'s' if minutes != 1 else ''} {seconds} sec{'s' if seconds != 1 else ''}"
    else:
        time_text = f"{seconds} sec{'s' if seconds != 1 else ''}"

    # Extract SLA due date if available
    sla_info = ""
    if due_date_str:
        try:
            due_date_utc = parse_due_date(due_date_str)
            if due_date_utc:
                # Convert to Eastern Time for display
                eastern = pytz.timezone('US/Eastern')
                due_date_et = due_date_utc.astimezone(eastern)
                due_date_formatted = due_date_et.strftime("%Y-%m-%d %H:%M:%S ET")
                sla_info = f" (SLA due: {due_date_formatted})"
        except (ValueError, AttributeError, TypeError) as e:
            # If parsing fails, don't add SLA info
            logger.debug(f"Failed to parse or format due date for ticket: {e}")
            pass

    return (
        f"{index}. [{ticket_id}]({incident_url}) - {ticket_name}\n"
        f"   {owner_text}, act within the next **{time_text}** {sla_info}"
    )


@retry(
    stop=stop_after_attempt(3),  # Retry up to 3 times
    wait=wait_exponential(multiplier=2, min=2, max=10),  # Exponential backoff: 2s, 4s, 8s
    before_sleep=before_sleep_log(logger, logging.WARNING),
)
def start(room_id):
    """
    Main function to process incident declaration SLA risk tickets.
    Query: tickets at risk of breaching incident declaration SLA (slaStatus:2)
    """
    logger.debug(f"[SCHEDULER DEBUG] incident_declaration_sla_risk.start() called with room_id={room_id}")
    try:
        ticket_handler = TicketHandler(XsoarEnvironment.PROD)
        query = f'-status:closed -category:job type:{CONFIG.team_name} sirtincidentnotificationsla.runStatus:running sirtincidentnotificationsla.slaStatus:2'
        tickets = ticket_handler.get_tickets(query)

        if not tickets:
            return  # Silent when no tickets at risk

        # Process all tickets and calculate urgency
        processed_tickets = []
        for ticket in tickets:
            seconds_remaining, ticket_data, due_date_str = process_ticket(ticket)

            # Only include tickets that are at risk, not already breached
            incident_sla = ticket_data.get('CustomFields', {}).get('sirtincidentnotificationsla', {})
            breach_triggered = incident_sla.get('breachTriggered', False)
            run_status = incident_sla.get('runStatus', '')

            # Skip tickets that have already breached
            if breach_triggered or run_status == 'ended':
                continue

            processed_tickets.append((seconds_remaining, ticket_data, due_date_str))

        # If no at-risk tickets remain after filtering, return silently
        if not processed_tickets:
            return

        # Sort by urgency (least time remaining first)
        processed_tickets.sort(key=lambda x: x[0])

        # Build messages for each ticket
        messages = []
        for index, (seconds_remaining, ticket, due_date_str) in enumerate(processed_tickets, start=1):
            message = build_ticket_message(seconds_remaining, ticket, index, due_date_str)
            messages.append(message)

        # Create simplified header
        markdown_header = "🚨 Tickets at risk of breaching Incident Declaration SLA ⏰"
        markdown_message = "\n\n".join(messages)

        # Send notification
        webex_api.messages.create(
            roomId=room_id,
            text=f"Tickets at risk of breaching Incident Declaration SLA - {len(processed_tickets)} tickets",
            markdown=f"{markdown_header}\n\n{markdown_message}"
        )

    except Exception as e:
        logger.error(f"Critical error in incident declaration SLA processing: {e}", exc_info=True)
        raise  # Reraise to trigger retry


if __name__ == "__main__":
    room_id = CONFIG.webex_room_id_dev_test_space
    start(room_id)
