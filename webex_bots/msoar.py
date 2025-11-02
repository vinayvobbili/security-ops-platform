import logging

import requests
from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot

from services.xsoar import TicketHandler, ListHandler
from src.utils import XsoarEnvironment

logger = logging.getLogger(__name__)

dev_list_handler = ListHandler(XsoarEnvironment.DEV)
lab_webex = dev_list_handler.get_list_data_by_name("METCIRT Webex")
notification_room_id = lab_webex['channels']['new_ticket_notifs']
BOT_ACCESS_TOKEN = lab_webex['bot_access_token']


class ProcessAcknowledgement(Command):
    """confirm acknowledgement"""

    def __init__(self):
        super().__init__(
            command_keyword="process_acknowledgement",
            help_message="",
            card=None
        )

    def execute(self, message, attachment_actions, activity):
        logger.info("🔔 ProcessAcknowledgement command received")

        # get acknowledger's details and set him as the owner of the incident
        acknowledger_email_address = activity['actor']['emailAddress']
        ticket_id = attachment_actions.inputs.get('ticket_id')

        logger.info(f"📋 Processing acknowledgement for ticket {ticket_id} by {acknowledger_email_address}")

        dev_ticket_handler = TicketHandler(XsoarEnvironment.DEV)
        dev_ticket_handler.assign_owner(ticket_id, acknowledger_email_address)
        logger.info(f"✓ Assigned owner for ticket {ticket_id}")

        # close acknowledgement task
        dev_ticket_handler.complete_task(ticket_id, "Acknowledge Ticket")
        logger.info(f"✓ Completed acknowledgement task for ticket {ticket_id}")


def get_bot_info(access_token):
    """Fetch bot information from Webex API"""
    try:
        response = requests.get(
            'https://webexapis.com/v1/people/me',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"Failed to fetch bot info: {e}")
        return None


def main():
    """the main"""

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    logger.info("🚀 Starting METCIRT SOAR bot")

    # Get and display bot information
    bot_info = get_bot_info(BOT_ACCESS_TOKEN)
    if bot_info:
        logger.info(f"🤖 Bot name: {bot_info.get('displayName', 'METCIRT SOAR')}")
        logger.info(f"📧 Bot email: {bot_info.get('emails', ['Unknown'])[0]}")
    else:
        logger.info(f"🤖 Bot name: METCIRT SOAR")

    logger.info(f"📍 Notification room ID: {notification_room_id}")

    logger.info("🔧 Initializing WebexBot...")
    bot = WebexBot(
        teams_bot_token=BOT_ACCESS_TOKEN,
        approved_domains=['company.com'],
        approved_rooms=[notification_room_id],
        bot_name="METCIRT SOAR",
        log_level="Warning"

    )
    logger.info("✓ WebexBot initialized")

    logger.info("📝 Registering commands...")
    bot.add_command(ProcessAcknowledgement())
    logger.info("✓ Bot commands registered")

    logger.info("👂 Bot is now listening for messages...")
    bot.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
