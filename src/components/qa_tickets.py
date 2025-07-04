from webexpythonsdk import WebexAPI

from config import get_config
from services.xsoar import TicketHandler
import random

CONFIG = get_config()
webex_api = WebexAPI(access_token=CONFIG.webex_bot_access_token_soar)

ticket_qa_leads = [
    "cedric.smith@company.com",
    "chelsea.koester@company.com",
    "kenny.hollis@company.com",
    "kyle.stephens1@company.com",
    "tyler.brescia@company.com",
]


def generate(room_id):
    ticket_handler = TicketHandler()
    query = 'status:closed -category:job type:METCIRT -owner:""'
    period = {
        "byFrom": "days",
        "fromValue": 0
    }

    tickets = ticket_handler.get_tickets(query, period)
    if not tickets:
        print("No tickets found creating QA ticket.")
        return

    tickets_by_impact = {}
    for ticket in tickets:
        impact = ticket['CustomFields'].get('impact', 'Unknown')
        tickets_by_impact.setdefault(impact, []).append(ticket)

    for impact, group in tickets_by_impact.items():
        source_ticket = random.choice(group)
        owner = ticket_qa_leads[group.index(source_ticket) % len(ticket_qa_leads)]
        new_ticket_payload = {
            'type': 'METCIRT Ticket QA',
            'owner': owner,
            'name': source_ticket.get('name'),
            'details': source_ticket.get('details'),
            'CustomFields': {
                'detectionsource': source_ticket.get('CustomFields').get('detectionsource'),
                'isusercontacted': False,
                'securitycategory': 'CAT-7: Investigation',
            }
        }
        qa_ticket = ticket_handler.create(new_ticket_payload)
        qa_ticket_url = CONFIG.xsoar_prod_ui_base_url + "/Custom/caseinfoid/" + qa_ticket['id']
        webex_api.messages.create(room_id, markdown=f"Hello <@personEmail:{owner}>👋🏾 [X#{qa_ticket['id']}]({qa_ticket_url}) has been assigned to you for QA")


if __name__ == "__main__":
    room_id = CONFIG.webex_room_id_vinay_test_space
    generate(room_id)
