from webexpythonsdk import WebexAPI
import pytz

from config import get_config
from services.xsoar import TicketHandler
from src.secops import get_staffing_data
from datetime import datetime

CONFIG = get_config()
webex_api = WebexAPI(access_token=CONFIG.webex_bot_access_token_soar)


def get_current_shift():
    now = datetime.now()
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


def start(room_id):
    ticket_handler = TicketHandler()
    query = '-status:closed -category:job type:METCIRT timetorespond.runStatus:running timetorespond.slaStatus:2'
    tickets = ticket_handler.get_tickets(query)
    if not tickets:
        return
    message = []
    day_name = datetime.now().strftime('%A')
    shift_name = get_current_shift()
    staffing_data = get_staffing_data(day_name, shift_name)
    shift_lead = staffing_data['SA'][0] if staffing_data['SA'] else 'Unknown'
    for ticket in tickets:
        incident_url = CONFIG.xsoar_prod_ui_base_url + '/Custom/caseinfoid/' + ticket.get('id')
        ticket_id = ticket.get('id')
        ticket_name = ticket.get('name') or ticket.get('title') or 'No Title'
        due_date_str = ticket.get('CustomFields').get('timetorespond').get('dueDate')
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
        message.append(f"- [**{ticket_id}**]({incident_url}) - {ticket_name} ⏳ {shift_lead}, act within the next {time_remaining}")
    markdown_header = f"## ⚠️ Tickets at risk of Response SLA breach 🚨\n**Shift Lead:** {shift_lead}"
    markdown_message = "\n".join(message)
    webex_api.messages.create(
        roomId=room_id,
        text="Tickets at the risk of breaching response SLA",
        markdown=f"{markdown_header}\n\n{markdown_message}"
    )


if __name__ == "__main__":
    room_id = CONFIG.webex_room_id_vinay_test_space
    start(room_id)
