import logging
from datetime import datetime

import pytz
from webexpythonsdk import WebexAPI

from config import get_config
from services.xsoar import TicketHandler

CONFIG = get_config()
webex_api = WebexAPI(access_token=CONFIG.webex_bot_access_token_soar)

# Configure logging for better error tracking
logger = logging.getLogger(__name__)

# Urgency thresholds in seconds
# Note: XSOAR only returns tickets with slaStatus:2 (already at risk, typically within 3 mins of breach)
CRITICAL_THRESHOLD = 60  # Critical urgency if <= 60 seconds remaining
WARNING_THRESHOLD = 120  # Warning urgency if <= 120 seconds remaining


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
    # If parsing fails, log and return None
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
    timetocontain = ticket.get('CustomFields', {}).get('timetocontain', {})
    due_date_str = timetocontain.get('dueDate')

    # Check if SLA is already breached
    breach_triggered = timetocontain.get('breachTriggered', False)
    run_status = timetocontain.get('runStatus', '')

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


def build_ticket_message(seconds_remaining, ticket, due_date_str, index):
    """Build formatted message for a single ticket."""
    ticket_id = ticket.get('id')
    ticket_name = ticket.get('name') or ticket.get('title') or 'No Title'
    ticket_owner = ticket.get('owner')
    incident_url = CONFIG.xsoar_prod_ui_base_url + '/Custom/caseinfoid/' + ticket_id

    # Check if ticket has breached
    timetocontain = ticket.get('CustomFields', {}).get('timetocontain', {})
    breach_triggered = timetocontain.get('breachTriggered', False)
    run_status = timetocontain.get('runStatus', '')

    # Format owner information
    if ticket_owner:
        # Use Webex person email format to make it clickable
        if '@' in ticket_owner:
            owner_text = f"<@personEmail:{ticket_owner}>"
        else:
            # If it's just a username, assume it's the part before @ and add domain if needed
            owner_text = ticket_owner
    else:
        owner_text = "Unassigned"

    # Format time remaining or breach status
    if breach_triggered or run_status == 'ended' or seconds_remaining == 0:
        time_text = "⚠️ **SLA BREACHED**"
    else:
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
                due_date_formatted = due_date_et.strftime("%Y-%m-%d %I:%M:%S %p ET")
                sla_info = f" (SLA due: {due_date_formatted})"
        except (ValueError, AttributeError, TypeError) as e:
            # If parsing fails, don't add SLA info
            logger.debug(f"Failed to parse or format due date for ticket: {e}")
            pass

    if breach_triggered or run_status == 'ended' or seconds_remaining == 0:
        return (
            f"{index}. [{ticket_id}]({incident_url}) - {ticket_name}\n"
            f"   {owner_text}, {time_text}{sla_info}"
        )
    else:
        return (
            f"{index}. [{ticket_id}]({incident_url}) - {ticket_name}\n"
            f"   {owner_text}, act within the next {time_text}{sla_info}"
        )


def start(room_id):
    """
    Main function to process containment SLA risk tickets.

    Query explanation:
    - timetocontain.slaStatus:2 = tickets at risk of breaching (within ~3 mins)
    - timetocontain.runStatus:running = active SLA timers
    - SLA durations are typically 15 minutes for containment
    """
    try:
        ticket_handler = TicketHandler()
        query = '-status:closed -category:job type:METCIRT timetocontain.runStatus:running timetocontain.slaStatus:2 -hostname:""'
        tickets = ticket_handler.get_tickets(query)

        if not tickets:
            return  # Silent when no tickets at risk

        # Process all tickets and calculate urgency
        processed_tickets = []
        for ticket in tickets:
            seconds_remaining, ticket_data, due_date_str = process_ticket(ticket)
            processed_tickets.append((seconds_remaining, ticket_data, due_date_str))

        # Sort by urgency (least time remaining first)
        processed_tickets.sort(key=lambda x: x[0])

        # Build messages for each ticket
        messages = []
        for index, (seconds_remaining, ticket, due_date_str) in enumerate(processed_tickets, start=1):
            message = build_ticket_message(seconds_remaining, ticket, due_date_str, index)
            messages.append(message)

        # Create simplified header
        markdown_header = "🚨 Tickets at risk of breaching Containment SLA ⏰"
        markdown_message = "\n\n".join(messages)

        # Send notification
        webex_api.messages.create(
            roomId=room_id,
            text=f"Tickets at risk of breaching containment SLA - {len(processed_tickets)} tickets",
            markdown=f"{markdown_header}\n\n{markdown_message}"
        )

    except Exception as e:
        error_message = f"❌ **Error processing containment SLA tickets:** {str(e)}"
        logger.error(f"Critical error in containment SLA processing: {e}", exc_info=True)

        # Send error notification to the room
        try:
            webex_api.messages.create(
                roomId=room_id,
                text="Error processing containment SLA tickets",
                markdown=error_message
            )
        except Exception as notification_error:
            logger.error(f"Failed to send error notification: {notification_error}")


if __name__ == "__main__":
    room_id = CONFIG.webex_room_id_vinay_test_space
    start(room_id)
