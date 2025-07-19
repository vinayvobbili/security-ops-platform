from webexpythonsdk import WebexAPI
from datetime import datetime
import pytz

from config import get_config
from services.xsoar import TicketHandler

CONFIG = get_config()
webex_api = WebexAPI(access_token=CONFIG.webex_bot_access_token_soar)


def format_time_remaining(minutes):
    """Format time remaining in a more readable way with appropriate urgency indicators."""
    if minutes <= 0:
        return "⚠️ **OVERDUE**"
    elif minutes < 60:
        return f"🔴 **{minutes} mins**"
    elif minutes < 120:  # Less than 2 hours
        hours = minutes // 60
        mins = minutes % 60
        return f"🟡 **{hours}h {mins}m**"
    else:
        hours = minutes // 60
        mins = minutes % 60
        return f"🟢 {hours}h {mins}m"


def get_urgency_emoji(minutes):
    """Get urgency emoji based on time remaining."""
    if minutes <= 0:
        return "🚨"
    elif minutes <= 30:
        return "🔥"
    elif minutes <= 60:
        return "⚠️"
    else:
        return "⏳"


def start(room_id):
    """
    Main function to run the scheduled jobs.
    Structure of timetocontain:
        {
            "accumulatedPause": 0,
            "breachTriggered": false,
            "dueDate": "2025-07-19T01:06:36.045064802Z",
            "endDate": "2025-07-19T00:53:25.399036093Z",
            "lastPauseDate": "0001-01-01T00:00:00Z",
            "runStatus": "ended",
            "sla": 15,
            "slaStatus": 0,
            "startDate": "2025-07-19T00:51:36.045064802Z",
            "totalDuration": 109
        }
    """
    try:
        ticket_handler = TicketHandler()
        query = '-status:closed -category:job type:METCIRT timetocontain.runStatus:running timetocontain.slaStatus:2 -hostname:""'
        # query = '-category:job type:METCIRT timetocontain.runStatus:running'
        tickets = ticket_handler.get_tickets(query)

        if not tickets:
            # No tickets at risk - just return silently
            return

        # Sort tickets by time remaining (most urgent first)
        tickets_with_urgency = []

        message = []
        for ticket in tickets:
            incident_url = CONFIG.xsoar_prod_ui_base_url + '/Custom/caseinfoid/' + ticket.get('id')
            ticket_id = ticket.get('id')
            ticket_name = ticket.get('name') or ticket.get('title') or 'No Title'
            ticket_owner = ticket.get('owner')

            # Get SLA information
            timetocontain = ticket.get('CustomFields', {}).get('timetocontain', {})
            due_date_str = timetocontain.get('dueDate')
            sla_minutes = timetocontain.get('sla', 'Unknown')

            time_remaining = 'N/A'
            minutes_remaining = float('inf')  # For sorting

            print(f"Debug - Ticket {ticket_id}: due_date_str = {due_date_str}")

            if due_date_str:
                try:
                    # Handle different possible date formats
                    due_date = None
                    # Try the main format first
                    try:
                        due_date = datetime.strptime(due_date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
                    except ValueError:
                        # Try without microseconds
                        try:
                            due_date = datetime.strptime(due_date_str, "%Y-%m-%dT%H:%M:%SZ")
                        except ValueError:
                            print(f"Debug - Failed to parse date format for ticket {ticket_id}: {due_date_str}")
                            raise

                    if due_date:
                        # Make due_date timezone aware (UTC)
                        due_date = due_date.replace(tzinfo=pytz.utc)
                        now_utc = datetime.now(pytz.utc)
                        delta = due_date - now_utc
                        minutes_remaining = int(delta.total_seconds() // 60)
                        print(f"Debug - Ticket {ticket_id}: delta = {delta}, minutes = {minutes_remaining}")

                        time_remaining = format_time_remaining(minutes_remaining)

                except Exception as e:
                    print(f"Debug - Exception for ticket {ticket_id}: {e}")
                    time_remaining = '❓ **Unable to calculate**'
                    minutes_remaining = 0  # Treat as urgent if we can't calculate
            else:
                print(f"Debug - Ticket {ticket_id}: due_date_str is None or empty")
                time_remaining = '❓ **No due date**'
                minutes_remaining = 0  # Treat as urgent if no due date

            # Store ticket with urgency info for sorting
            tickets_with_urgency.append((minutes_remaining, ticket, time_remaining))

        # Sort by urgency (least time remaining first)
        tickets_with_urgency.sort(key=lambda x: x[0])

        # Build message with sorted tickets
        for minutes_remaining, ticket, time_remaining in tickets_with_urgency:
            ticket_id = ticket.get('id')
            ticket_name = ticket.get('name') or ticket.get('title') or 'No Title'
            ticket_owner = ticket.get('owner')
            incident_url = CONFIG.xsoar_prod_ui_base_url + '/Custom/caseinfoid/' + ticket.get('id')

            # Get additional context
            timetocontain = ticket.get('CustomFields', {}).get('timetocontain', {})
            sla_minutes = timetocontain.get('sla', 'Unknown')

            # Format owner mention
            if ticket_owner:
                mention = f"<@personEmail:{ticket_owner}>"
            else:
                mention = "🔍 **(No owner assigned)**"

            # Get urgency emoji
            urgency_emoji = get_urgency_emoji(minutes_remaining)

            # Create rich ticket entry
            ticket_entry = (
                f"{urgency_emoji} {mention} - [**{ticket_id}**]({incident_url}) - {ticket_name}\n"
                f"   └─ **SLA:** {sla_minutes} mins | **Time remaining:** {time_remaining}"
            )
            message.append(ticket_entry)

        # Create header with count and urgency indicator
        urgent_count = sum(1 for minutes, _, _ in tickets_with_urgency if minutes <= 30)
        total_count = len(tickets_with_urgency)

        if urgent_count > 0:
            header_emoji = "🚨"
            urgency_text = f"({urgent_count} critically urgent)"
        else:
            header_emoji = "⚠️"
            urgency_text = ""

        markdown_header = f"## {header_emoji} Tickets at risk of breaching Containment SLA {urgency_text}\n**Total tickets at risk:** {total_count}"
        markdown_message = "\n\n".join(message)

        # Add footer with instructions
        footer = "\n\n---\n💡 **Action required:** Please review and take immediate action on tickets marked with 🚨 or 🔥"

        webex_api.messages.create(
            roomId=room_id,
            text=f"Tickets at the risk of breaching response SLA - {total_count} tickets",
            markdown=f"{markdown_header}\n\n{markdown_message}{footer}"
        )

    except Exception as e:
        error_message = f"❌ **Error processing containment SLA tickets:** {str(e)}"
        print(f"Error processing tickets: {e}")
        # Send error notification to the room
        try:
            webex_api.messages.create(
                roomId=room_id,
                text="Error processing containment SLA tickets",
                markdown=error_message
            )
        except:
            pass  # Avoid infinite error loops


if __name__ == "__main__":
    room_id = CONFIG.webex_room_id_vinay_test_space
    start(room_id)
