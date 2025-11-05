import logging

from tenacity import retry, stop_after_attempt, wait_exponential, before_sleep_log
from webexpythonsdk import WebexAPI

from my_config import get_config
from services.xsoar import TicketHandler, XsoarEnvironment

CONFIG = get_config()
# Configure timeout to prevent hanging if Webex API is slow/down
# Increased from 60s to 180s to handle network congestion
webex_api = WebexAPI(
    access_token=CONFIG.webex_bot_access_token_soar,
    single_request_timeout=180  # 180 second timeout (3 minutes)
)

# Configure logging for better error tracking
logger = logging.getLogger(__name__)


@retry(
    stop=stop_after_attempt(3),  # Retry up to 3 times
    wait=wait_exponential(multiplier=2, min=2, max=10),  # Exponential backoff: 2s, 4s, 8s
    before_sleep=before_sleep_log(logger, logging.WARNING),
)
def start(room_id):
    try:
        ticket_handler = TicketHandler(XsoarEnvironment.PROD)
        query = '-status:closed -category:job type:METCIRT metcirtincidentnotificationsla.runStatus:running metcirtincidentnotificationsla.slaStatus:2'
        # query = '-category:job type:METCIRT timetorespond.runStatus:running'
        tickets = ticket_handler.get_tickets(query)
        if not tickets:
            return
        message = []
        for ticket in tickets:
            incident_url = CONFIG.xsoar_prod_ui_base_url + '/Custom/caseinfoid/' + ticket.get('id')
            ticket_id = ticket.get('id')
            ticket_name = ticket.get('name') or ticket.get('title') or 'No Title'
            message.append(f"- [**{ticket_id}**]({incident_url}) - {ticket_name}")
        markdown_header = "## ⚠️ Tickets at risk of Incident Declaration SLA breach 🚨"
        markdown_message = "\n".join(message)
        webex_api.messages.create(
            roomId=room_id,
            text="Tickets at the risk of breaching Incident Declaration SLA",
            markdown=f"{markdown_header}\n\n{markdown_message}"
        )
    except Exception as e:
        logger.error(f"Critical error in incident declaration SLA processing: {e}", exc_info=True)
        raise  # Reraise to trigger retry


if __name__ == "__main__":
    room_id = CONFIG.webex_room_id_vinay_test_space
    start(room_id)
