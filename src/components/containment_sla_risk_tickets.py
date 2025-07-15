from webexpythonsdk import WebexAPI

from config import get_config
from services.xsoar import TicketHandler

CONFIG = get_config()
webex_api = WebexAPI(access_token=CONFIG.webex_bot_access_token_soar)


def start(room_id):
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
        message.append(f"- [**{ticket_id}**]({incident_url}) - {ticket_name}")
    markdown_header = "## ⚠️ Tickets at risk of Containment SLA breach 🚨"
    markdown_message = "\n".join(message)
    webex_api.messages.create(
        roomId=room_id,
        text="Tickets at the risk of breaching response SLA",
        markdown=f"{markdown_header}\n\n{markdown_message}"
    )


if __name__ == "__main__":
    room_id = CONFIG.webex_room_id_vinay_test_space
    start(room_id)
