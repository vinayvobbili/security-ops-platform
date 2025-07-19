from webexpythonsdk import WebexAPI
from datetime import datetime
import pytz
import logging

from config import get_config
from services.xsoar import TicketHandler

CONFIG = get_config()
webex_api = WebexAPI(access_token=CONFIG.webex_bot_access_token_soar)

# Configure logging for better error tracking
logger = logging.getLogger(__name__)

# Urgency thresholds in minutes
# Note: XSOAR only returns tickets with slaStatus:2 (already at risk, typically within 3 mins of breach)
CRITICAL_THRESHOLD = 1  # Critical urgency if <= 1 minute remaining
WARNING_THRESHOLD = 2  # Warning urgency if <= 2 minutes remaining


def parse_due_date(due_date_str):
    """Parse due date string with multiple format support."""
    if not due_date_str:
        return None

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
    """Calculate minutes remaining until SLA breach."""
    now_utc = datetime.now(pytz.utc)
    delta = due_date_utc - now_utc
    return int(delta.total_seconds() // 60)


def format_time_remaining(minutes):
    """Format time remaining with appropriate urgency indicators."""
    if minutes <= 0:
        return "⚠️ **OVERDUE**"
    elif minutes <= CRITICAL_THRESHOLD:
        return f"🔴 **{minutes} min{'s' if minutes != 1 else ''}**"
    elif minutes <= WARNING_THRESHOLD:
        return f"🟡 **{minutes} min{'s' if minutes != 1 else ''}**"
    else:
        return f"🟢 **{minutes} min{'s' if minutes != 1 else ''}**"


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
    timetocontain = ticket.get('CustomFields', {}).get('timetocontain', {})
    due_date_str = timetocontain.get('dueDate')

    try:
        if due_date_str:
            due_date_utc = parse_due_date(due_date_str)
            minutes_remaining = calculate_minutes_remaining(due_date_utc)
        else:
            logger.warning(f"No due date found for ticket {ticket_id}")
            minutes_remaining = 0  # Treat as urgent if no due date

        return minutes_remaining, ticket, timetocontain

    except Exception as e:
        logger.error(f"Error processing ticket {ticket_id}: {e}")
        return 0, ticket, timetocontain  # Treat as urgent if we can't calculate


def build_ticket_message(minutes_remaining, ticket, timetocontain):
    """Build formatted message for a single ticket."""
    ticket_id = ticket.get('id')
    ticket_name = ticket.get('name') or ticket.get('title') or 'No Title'
    ticket_owner = ticket.get('owner')
    incident_url = CONFIG.xsoar_prod_ui_base_url + '/Custom/caseinfoid/' + ticket_id
    sla_minutes = timetocontain.get('sla', 'Unknown')

    # Format owner mention
    if ticket_owner:
        mention = f"<@personEmail:{ticket_owner}>"
    else:
        mention = "🔍 **(No owner assigned)**"

    # Get urgency indicators
    urgency_emoji = get_urgency_emoji(minutes_remaining)
    time_remaining_text = format_time_remaining(minutes_remaining)

    return (
        f"{urgency_emoji} {mention} - [**{ticket_id}**]({incident_url}) - {ticket_name}\n"
        f"   └─ **SLA:** {sla_minutes} mins | **Time remaining:** {time_remaining_text}"
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
            minutes_remaining, ticket_data, timetocontain = process_ticket(ticket)
            processed_tickets.append((minutes_remaining, ticket_data, timetocontain))

        # Sort by urgency (least time remaining first)
        processed_tickets.sort(key=lambda x: x[0])

        # Build messages for each ticket
        messages = []
        for minutes_remaining, ticket, timetocontain in processed_tickets:
            message = build_ticket_message(minutes_remaining, ticket, timetocontain)
            messages.append(message)

        # Create header with urgency metrics
        urgent_count = sum(1 for minutes, _, _ in processed_tickets if minutes <= CRITICAL_THRESHOLD)
        total_count = len(processed_tickets)

        if urgent_count > 0:
            header_emoji = "🚨"
            urgency_text = f"({urgent_count} critically urgent)"
        else:
            header_emoji = "⚠️"
            urgency_text = ""

        # Compose final message
        markdown_header = (
            f"## {header_emoji} Tickets at risk of breaching Containment SLA {urgency_text}\n"
            f"**Total tickets at risk:** {total_count}"
        )
        markdown_message = "\n\n".join(messages)
        footer = (
            f"\n\n---\n💡 **Action required:** Please review and take immediate action "
            f"on tickets marked with 🚨 or 🔥 (≤{CRITICAL_THRESHOLD} min{'s' if CRITICAL_THRESHOLD != 1 else ''} remaining)"
        )

        # Send notification
        webex_api.messages.create(
            roomId=room_id,
            text=f"Tickets at risk of breaching containment SLA - {total_count} tickets",
            markdown=f"{markdown_header}\n\n{markdown_message}{footer}"
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
