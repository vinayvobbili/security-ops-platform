from webexpythonsdk import WebexAPI

from config import get_config
from services.xsoar import TicketHandler
from datetime import datetime
from tabulate import tabulate

CONFIG = get_config()
webex_api = WebexAPI(access_token=CONFIG.webex_bot_access_token_soar)


def send_report(room_id):
    ticket_handler = TicketHandler()
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
                created_dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
                created_str = created_dt.strftime('%m/%d/%Y')
            except Exception:
                created_dt = None
                created_str = created
        else:
            created_dt = None
            created_str = ''
        ticket_type = t.get('type', '').replace('METCIRT', '').strip()
        row = {
            'ID': t.get('id', ''),
            'Name': truncate_text(t.get('name', ''), 50),
            'Type': ticket_type,
            'Created': created_str,
            'created_dt': created_dt
        }
        rows.append(row)
    # Sort by date (oldest first)
    rows.sort(key=lambda x: (x['created_dt'] is None, x['created_dt']))
    # Remove 'created_dt' from display
    display_rows = [[r['ID'], r['Name'], r['Type'], r['Created']] for r in rows]
    headers = ['ID', 'Name', 'Type', 'Created']
    # Build table string with description above code block
    table_str = f"Orphaned tickets ({query})\n\n" + '````\n' + tabulate(display_rows, headers, tablefmt='github') + '\n````'
    # Send to Webex
    webex_api.messages.create(
        roomId=room_id,
        text="Orphaned Tickets Summary!",
        markdown=table_str
    )


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
