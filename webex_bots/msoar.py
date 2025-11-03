import logging
import os
import time
from logging.handlers import RotatingFileHandler

import requests
from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot

from my_config import get_config
from services.xsoar import TicketHandler
from src.utils import XsoarEnvironment

logger = logging.getLogger(__name__)

CONFIG = get_config()
BOT_ACCESS_TOKEN = CONFIG.webex_bot_access_token_dev_xsoar
NOTIFICATION_ROOM_ID = CONFIG.webex_room_id_new_ticket_notifications

# Patch the default HTTP timeout for WebSocket device registration calls
# The WebSocket client makes HTTP calls to register/refresh devices, and the default 60s timeout
# is too short for unreliable networks, causing "Read timed out" errors
try:
    import webexpythonsdk.config
    webexpythonsdk.config.DEFAULT_SINGLE_REQUEST_TIMEOUT = 180
    logger.info("⏱️  Increased SDK HTTP timeout from 60s to 180s for device registration")
except Exception as timeout_patch_error:
    logger.warning(f"⚠️  Could not patch SDK timeout: {timeout_patch_error}")


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
        dev_ticket_handler.complete_task(ticket_id, "Acknowledge Ticket", 'Yes')
        logger.info(f"✓ Completed acknowledgement task for ticket {ticket_id}")


class Hi(Command):
    """Simple Hi command to check if bot is alive."""

    def __init__(self):
        super().__init__(
            command_keyword="hi",
            delete_previous_message=False,
            exact_command_keyword_match=False,
        )

    def execute(self, message, attachment_actions, activity):
        return "Hi 👋🏾"


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

    # Configure logging with rotation
    # Max 10MB per file, keep 5 backups (total ~50MB of logs)
    log_dir = 'logs'
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, 'msoar.log')

    # Create rotating file handler
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.INFO)
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_formatter.converter = time.localtime  # Use local timezone instead of UTC
    file_handler.setFormatter(file_formatter)

    # Also log to console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_formatter.converter = time.localtime  # Use local timezone instead of UTC
    console_handler.setFormatter(console_formatter)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    # Suppress verbose library logs
    logging.getLogger('webex_bot').setLevel(logging.WARNING)
    logging.getLogger('webexpythonsdk').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.ERROR)  # Suppress connection pool warnings
    logging.getLogger('asyncio').setLevel(logging.CRITICAL)  # Suppress asyncio future errors

    logger.info("🚀 Starting METCIRT SOAR bot")

    # Get and display bot information
    bot_info = get_bot_info(BOT_ACCESS_TOKEN)
    if bot_info:
        logger.info(f"🤖 Bot name: {bot_info.get('displayName', 'METCIRT SOAR')}")
        logger.info(f"📧 Bot email: {bot_info.get('emails', ['Unknown'])[0]}")
    else:
        logger.info(f"🤖 Bot name: METCIRT SOAR")

    logger.info(f"📍 Notification room ID: {NOTIFICATION_ROOM_ID}")

    logger.info("🔧 Initializing WebexBot...")
    bot = WebexBot(
        teams_bot_token=BOT_ACCESS_TOKEN,
        approved_domains=['company.com'],
        approved_rooms=[NOTIFICATION_ROOM_ID],
        bot_name="METCIRT SOAR",
        log_level="Warning"

    )
    logger.info("✓ WebexBot initialized")

    logger.info("📝 Registering commands...")
    bot.add_command(ProcessAcknowledgement())
    bot.add_command(Hi())
    logger.info("✓ Bot commands registered")

    logger.info("👂 Bot is now listening for messages...")
    bot.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
