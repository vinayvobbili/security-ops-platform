from datetime import datetime
from zoneinfo import ZoneInfo

from tabulate import tabulate
from webexpythonsdk import WebexAPI

from my_config import get_config
from services.xsoar import TicketHandler, XsoarEnvironment

CONFIG = get_config()
webex_api = WebexAPI(access_token=CONFIG.webex_bot_access_token_soar)


def severity_to_name(severity):
    """Convert severity number to severity name."""
    # Handle both int and float severity values
    try:
        sev = float(severity) if severity else 0
    except (ValueError, TypeError):
        return 'Unknown'

    match sev:
        case 0:
            return 'Unknown'
        case 0.5:
            return 'Informational'
        case 1:
            return 'Low'
        case 2:
            return 'Medium'
        case 3:
            return 'High'
        case 4:
            return 'Critical'
        case _:
            return 'Unknown'


def send_report(room_id):
    try:
        ticket_handler = TicketHandler(XsoarEnvironment.PROD)
        query = '-status:closed -category:job type:METCIRT owner:""'
        tickets = ticket_handler.get_tickets(query)
        if not tickets:
            return

        # Build table rows for tabulate
        rows = []
        for t in tickets:
            created = t.get('created', '')
            if created:
                try:
                    # Handle both string and datetime objects
                    if isinstance(created, str):
                        # Parse the ISO format string
                        created_dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
                    else:
                        created_dt = created
                    # Convert to Eastern Time
                    created_et = created_dt.astimezone(ZoneInfo('America/New_York'))
                    # Format as MM/DD/YYYY HH:MM AM/PM ET
                    created_str = created_et.strftime('%m/%d/%Y %I:%M %p ET')
                except Exception:
                    created_dt = None
                    created_str = str(created)
            else:
                created_dt = None
                created_str = ''
            ticket_type = t.get('type', '').replace('METCIRT', '').strip()
            severity = severity_to_name(t.get('severity', 0))
            status = t.get('status', '')
            row = {
                'ID': t.get('id', ''),
                'Name': truncate_text(t.get('name', ''), 50),
                'Type': ticket_type,
                'Severity': severity,
                'Status': status,
                'Created': created_str,
                'created_dt': created_dt
            }
            rows.append(row)
        # Sort by date (oldest first)
        rows.sort(key=lambda x: (x['created_dt'] is None, x['created_dt']))

        total_tickets = len(rows)
        # Show only first 10 tickets
        display_rows = [[r['ID'], r['Name'], r['Type'], r['Severity'], r['Status'], r['Created']] for r in rows[:10]]
        headers = ['ID', 'Name', 'Type', 'Severity', 'Status', 'Created']

        # Build table string with description above code block
        table_str = f"Orphaned tickets ({query})\n\n" + '````\n' + tabulate(display_rows, headers, tablefmt='github') + '\n````'

        # Add summary if there are more tickets
        if total_tickets > 10:
            remaining = total_tickets - 10
            table_str += f"\n\n... and {remaining} more tickets"
        # Send to Webex
        webex_api.messages.create(
            roomId=room_id,
            text="Orphaned Tickets Summary!",
            markdown=table_str
        )
    except Exception as e:
        print(f"Error in send_report: {e}")


def truncate_text(text, n=50):
    """Truncate text after n characters, adding '...' if needed."""
    if not text:
        return ''
    return text if len(text) <= n else text[:n] + '...'


def main():
    room_id = CONFIG.webex_room_id_vinay_test_space
    send_report(room_id)


if __name__ == "__main__":
    main()
