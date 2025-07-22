from webexpythonsdk import WebexAPI
from datetime import datetime
import pytz
import logging

from config import get_config
from services.xsoar import TicketHandler
from src.secops import get_staffing_data

CONFIG = get_config()
webex_api = WebexAPI(access_token=CONFIG.webex_bot_access_token_soar)

# Configure logging for better error tracking
logger = logging.getLogger(__name__)

# Urgency thresholds in minutes for response SLA
# Note: XSOAR only returns tickets with slaStatus:2 (already at risk, typically within 3 mins of breach)
CRITICAL_THRESHOLD = 1  # Critical urgency if <= 1 minute remaining
WARNING_THRESHOLD = 2  # Warning urgency if <= 2 minutes remaining


def get_current_shift():
    """Determine current shift based on Eastern time."""
    eastern = pytz.timezone('US/Eastern')
    now = datetime.now(eastern)
    hour = now.hour
    minute = now.minute
    total_minutes = hour * 60 + minute
    # Morning: 04:30 - 12:29, Afternoon: 12:30 - 20:29, Night: 20:30 - 04:29
    if 270 <= total_minutes < 750:
        return 'morning'
    elif 750 <= total_minutes < 1230:
        return 'afternoon'
    else:
        return 'night'


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

    raise ValueError(f"Unable to parse date format: {due_date_str}")


def calculate_minutes_remaining(due_date_utc):
    """Calculate seconds remaining until SLA breach."""
    now_utc = datetime.now(pytz.utc)
    delta = due_date_utc - now_utc
    return int(delta.total_seconds())


def format_time_remaining(minutes):
    """Format time remaining with appropriate urgency indicators."""
    if minutes <= 0:
        return "⚠️ **OVERDUE**"
    elif minutes <= CRITICAL_THRESHOLD:
        return f"🔴 **{minutes} min{'s' if minutes != 1 else ''}**"
    elif minutes <= WARNING_THRESHOLD:
        return f"🟡 **{minutes} min{'s' if minutes != 1 else ''}**"
    else:
        hours = minutes // 60
        mins = minutes % 60
        if hours > 0:
            return f"🟢 **{hours}h {mins}m**"
        else:
            return f"🟢 **{minutes} mins**"


def get_urgency_emoji(minutes):
    """Get urgency emoji based on time remaining."""
    if minutes <= 0:
        return "🚨"
    elif minutes <= CRITICAL_THRESHOLD:
        return "🔥"
    elif minutes <= WARNING_THRESHOLD:
        return "⚠️"
    else:
        return "⏳"


def process_ticket(ticket):
    """Process a single ticket and return urgency data."""
    ticket_id = ticket.get('id')
    timetorespond = ticket.get('CustomFields', {}).get('timetorespond', {})
    due_date_str = timetorespond.get('dueDate')

    try:
        if due_date_str:
            due_date_utc = parse_due_date(due_date_str)
            seconds_remaining = calculate_minutes_remaining(due_date_utc)
        else:
            logger.warning(f"No due date found for ticket {ticket_id}")
            seconds_remaining = 0  # Treat as urgent if no due date

        return seconds_remaining, ticket, timetorespond

    except Exception as e:
        logger.error(f"Error processing ticket {ticket_id}: {e}")
        return 0, ticket, timetorespond  # Treat as urgent if we can't calculate


def build_ticket_message(seconds_remaining, ticket, timetorespond, index):
    """Build formatted message for a single ticket."""
    ticket_id = ticket.get('id')
    ticket_name = ticket.get('name') or ticket.get('title') or 'No Title'
    ticket_owner = ticket.get('owner')
    incident_url = CONFIG.xsoar_prod_ui_base_url + '/Custom/caseinfoid/' + ticket_id

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

    # Format time remaining (XSOAR API only returns at-risk tickets, not overdue ones)
    minutes = seconds_remaining // 60
    seconds = seconds_remaining % 60

    if minutes > 0:
        time_text = f"the next {minutes} min{'s' if minutes != 1 else ''} {seconds} sec{'s' if seconds != 1 else ''}"
    else:
        time_text = f"the next {seconds} sec{'s' if seconds != 1 else ''}"

    return (
        f"{index}. [{ticket_id}]({incident_url}) - {ticket_name}\n"
        f"   {owner_text}, act within {time_text}"
    )


def start(room_id):
    """
    Main function to process response SLA risk tickets.
    This script runs in Eastern time zone but processes UTC timestamps.

    Query explanation:
    - timetorespond.slaStatus:2 = tickets at risk of breaching response SLA
    - timetorespond.runStatus:running = active SLA timers

    Sample timetorespond structure:
    {
        "accumulatedPause": 0,
        "breachTriggered": false,
        "dueDate": "2025-07-19T00:54:36.044959802Z",  # UTC timestamp
        "endDate": "2025-07-19T00:52:33.599694455Z",
        "lastPauseDate": "0001-01-01T00:00:00Z",
        "runStatus": "ended",
        "sla": 3,  # SLA duration in minutes
        "slaStatus": 0,
        "startDate": "2025-07-19T00:51:36.044959802Z",
        "totalDuration": 57
    }
    """
    try:
        ticket_handler = TicketHandler()
        query = '-status:closed -category:job type:METCIRT timetorespond.runStatus:running timetorespond.slaStatus:2 -hostname:""'
        tickets = ticket_handler.get_tickets(query)

        if not tickets:
            return  # Silent when no tickets at risk

        # Get shift information using Eastern time (server timezone)
        eastern = pytz.timezone('US/Eastern')
        now_eastern = datetime.now(eastern)
        day_name = now_eastern.strftime('%A')
        shift_name = get_current_shift()
        staffing_data = get_staffing_data(day_name, shift_name)
        shift_lead = staffing_data.get('SA', ['Unknown'])[0] if staffing_data.get('SA') else 'Unknown'

        # Process all tickets and calculate urgency
        processed_tickets = []
        for ticket in tickets:
            seconds_remaining, ticket_data, timetorespond = process_ticket(ticket)
            processed_tickets.append((seconds_remaining, ticket_data, timetorespond))

        # Sort by urgency (least time remaining first)
        processed_tickets.sort(key=lambda x: x[0])

        # Build messages for each ticket
        messages = []
        for index, (seconds_remaining, ticket, timetorespond) in enumerate(processed_tickets, start=1):
            message = build_ticket_message(seconds_remaining, ticket, timetorespond, index)
            messages.append(message)

        # Create simplified header
        markdown_header = "🚨 Tickets at risk of breaching Response SLA ⏰"
        markdown_message = "\n\n".join(messages)

        # Send notification
        webex_api.messages.create(
            roomId=room_id,
            text=f"Tickets at risk of breaching response SLA - {len(processed_tickets)} tickets",
            markdown=f"{markdown_header}\n\n{markdown_message}"
        )

    except Exception as e:
        error_message = f"❌ **Error processing response SLA tickets:** {str(e)}"
        logger.error(f"Critical error in response SLA processing: {e}", exc_info=True)

        # Send error notification to the room
        try:
            webex_api.messages.create(
                roomId=room_id,
                text="Error processing response SLA tickets",
                markdown=error_message
            )
        except Exception as notification_error:
            logger.error(f"Failed to send error notification: {notification_error}")


if __name__ == "__main__":
    room_id = CONFIG.webex_room_id_vinay_test_space
    start(room_id)
