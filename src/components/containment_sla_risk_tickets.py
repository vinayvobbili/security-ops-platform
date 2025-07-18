from webexpythonsdk import WebexAPI
from datetime import datetime
import pytz

from config import get_config
from services.xsoar import TicketHandler

CONFIG = get_config()
webex_api = WebexAPI(access_token=CONFIG.webex_bot_access_token_soar)


def start(room_id):
    try:
        ticket_handler = TicketHandler()
        query = '-status:closed -category:job type:METCIRT timetocontain.runStatus:running timetocontain.slaStatus:2 -hostname:""'
        # query = '-category:job type:METCIRT timetocontain.runStatus:running'
        tickets = ticket_handler.get_tickets(query)
        if not tickets:
            return
        message = []
        for ticket in tickets:
            incident_url = CONFIG.xsoar_prod_ui_base_url + '/Custom/caseinfoid/' + ticket.get('id')
            ticket_id = ticket.get('id')
            ticket_name = ticket.get('name') or ticket.get('title') or 'No Title'
            ticket_owner = ticket.get('owner')
            due_date_str = ticket.get('CustomFields').get('timetocontain').get('dueDate')
            time_remaining = 'N/A'
            if due_date_str:
                try:
                    due_date = datetime.strptime(due_date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
                    eastern = pytz.timezone('US/Eastern')
                    now_et = datetime.now(eastern)
                    now_utc = now_et.astimezone(pytz.utc)
                    delta = due_date - now_utc
                    minutes = int(delta.total_seconds() // 60)
                    if minutes < 0:
                        minutes = 0
                    time_remaining = f"{minutes} mins"
                except Exception:
                    time_remaining = 'N/A'
            if ticket_owner:
                mention = f"<@personEmail:{ticket_owner}>"
            else:
                mention = "(No owner assigned)"
            message.append(f"{mention} - [**{ticket_id}**]({incident_url}) - {ticket_name} ⏳ Act within the next {time_remaining}")
        markdown_header = "## ⚠️ Tickets at risk of breaching Containment SLA 🚨"
        markdown_message = "\n".join(message)
        webex_api.messages.create(
            roomId=room_id,
            text="Tickets at the risk of breaching response SLA",
            markdown=f"{markdown_header}\n\n{markdown_message}"
        )
    except Exception as e:
        print(f"Error processing tickets: {e}")


if __name__ == "__main__":
    room_id = CONFIG.webex_room_id_vinay_test_space
    start(room_id)
