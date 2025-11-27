import sys
from pathlib import Path

# Add parent directory to path so we can import my_config
sys.path.insert(0, str(Path(__file__).parent.parent))

import logging
from typing import Any, Dict, Optional

import requests
from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot

from my_config import get_config
from services.xsoar import TicketHandler
from src.utils import XsoarEnvironment
from src.utils.logging_utils import setup_logging
from src.utils.webex_pool_config import configure_webex_bot_session

logger = logging.getLogger(__name__)
# Suppress noisy messages from webex libraries
logging.getLogger('webex_bot').setLevel(logging.ERROR)  # Suppress bot-to-bot and self-message warnings
logging.getLogger('webexteamssdk').setLevel(logging.ERROR)
logging.getLogger('webex_websocket_client').setLevel(logging.WARNING)

CONFIG = get_config()
BOT_ACCESS_TOKEN = getattr(CONFIG, 'webex_bot_access_token_dev_xsoar', None)
NOTIFICATION_ROOM_ID = getattr(CONFIG, 'webex_room_id_new_ticket_notifications', None)
WEBEX_ME_ENDPOINT = 'https://webexapis.com/v1/people/me'


class ProcessAcknowledgement(Command):
    """Confirm acknowledgement of a ticket: assigns owner and completes acknowledgement task."""

    def __init__(self):
        super().__init__(
            command_keyword="process_acknowledgement",
            help_message="",
            card=None
        )

    def execute(self, message: Any, attachment_actions: Any, activity: Dict[str, Any]) -> str:
        logger.info("🔔 ProcessAcknowledgement command received")

        # Defensive extraction of actor email
        acknowledger_email_address = (
                activity.get('actor', {}).get('emailAddress') or
                activity.get('actor', {}).get('email')  # fallback if different key
        )
        if not acknowledger_email_address:
            logger.error("Actor email not found in activity payload")
            return "❌ Unable to determine your email address from activity payload."

        # Validate attachment_actions and ticket_id
        ticket_id: Optional[str] = None
        if attachment_actions and getattr(attachment_actions, 'inputs', None):
            ticket_id = attachment_actions.inputs.get('ticket_id')
        if not ticket_id:
            logger.warning("ticket_id missing in attachment_actions inputs")
            return "⚠️ Please provide a valid ticket_id in the acknowledgement card." + \
                (" (Your email was detected.)" if acknowledger_email_address else "")

        logger.info(f"📋 Processing acknowledgement for ticket {ticket_id} by {acknowledger_email_address}")

        dev_ticket_handler = TicketHandler(XsoarEnvironment.DEV)

        # Assign owner
        try:
            dev_ticket_handler.assign_owner(ticket_id, acknowledger_email_address)
            logger.info(f"✓ Assigned owner for ticket {ticket_id}")
        except Exception as e:
            logger.error(f"Failed assigning owner for {ticket_id}: {e}", exc_info=True)
            return f"❌ Failed to assign owner for ticket {ticket_id}: {e}"[:500]

        # Complete acknowledgement task
        try:
            dev_ticket_handler.complete_task(ticket_id, "Acknowledge Ticket", 'Yes')
            logger.info(f"✓ Completed acknowledgement task for ticket {ticket_id}")
        except ValueError as ve:
            # Task not found scenario
            logger.warning(f"Acknowledgement task not found for ticket {ticket_id}: {ve}")
            return f"⚠️ Owner set, but acknowledgement task not found for ticket {ticket_id}."
        except Exception as e:
            logger.error(f"Failed completing acknowledgement task for {ticket_id}: {e}", exc_info=True)
            return f"❌ Owner set, but failed to complete acknowledgement task for ticket {ticket_id}: {e}"[:500]

        return f"✅ Ticket {ticket_id} acknowledged and assigned to {acknowledger_email_address}."


class Hi(Command):
    """Simple Hi command to check if bot is alive."""

    def __init__(self):
        super().__init__(
            command_keyword="hi",
            delete_previous_message=False,
            exact_command_keyword_match=False,
        )

    def execute(self, message: Any, attachment_actions: Any, activity: Dict[str, Any]) -> str:  # type: ignore[override]
        return "Hi 👋🏾"


def get_bot_info(access_token: Optional[str]) -> Optional[Dict[str, Any]]:
    """Fetch bot information from Webex API safely.

    Args:
        access_token: Bot access token
    Returns:
        JSON dict with bot info or None on failure
    """
    if not access_token:
        logger.error("Bot access token is missing; cannot query Webex API.")
        return None
    try:
        response = requests.get(
            WEBEX_ME_ENDPOINT,
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=15
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error fetching bot info: {e}")
    except requests.exceptions.Timeout:
        logger.error("Timeout fetching bot info from Webex API")
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error fetching bot info: {e}")
    except Exception as e:
        logger.error(f"Unexpected error fetching bot info: {e}")
    return None


def msoar_bot_factory() -> WebexBot:
    """Create MSOAR bot instance"""
    if not BOT_ACCESS_TOKEN:
        raise RuntimeError("Missing Webex bot access token (CONFIG.webex_bot_access_token_dev_xsoar)")
    if not NOTIFICATION_ROOM_ID:
        raise RuntimeError("Missing notification room ID (CONFIG.webex_room_id_new_ticket_notifications)")

    logger.info("🔧 Initializing WebexBot...")

    # Build approved users list: employees + all bots for peer ping communication
    approved_bot_emails = [
        CONFIG.webex_bot_email_toodles,
        CONFIG.webex_bot_email_barnacles,
        CONFIG.webex_bot_email_money_ball,
        CONFIG.webex_bot_email_jarvis,
        CONFIG.webex_bot_email_pokedex,
        CONFIG.webex_bot_email_pinger,  # Pinger bot for keepalive
    ]

    bot = WebexBot(
        teams_bot_token=BOT_ACCESS_TOKEN,
        approved_domains=[CONFIG.my_web_domain],
        approved_users=approved_bot_emails,  # Allow other bots for peer ping
        # approved_rooms disabled - bot lacks spark:memberships_read scope for validation
        # Security: Only add this bot to authorized rooms to control access
        bot_name="METCIRT SOAR",
        log_level="Warning",
        allow_bot_to_bot=True  # Enable peer ping health checks from other bots
    )

    # Configure the bot's internal WebexTeamsAPI session with larger connection pool
    # This prevents timeout issues when processing WebSocket messages concurrently
    configure_webex_bot_session(bot, pool_connections=50, pool_maxsize=50, max_retries=3)

    logger.info("✓ WebexBot initialized with enhanced connection pool")
    return bot


def msoar_initialization(bot_instance: Optional[WebexBot] = None) -> bool:
    """Initialize MSOAR commands.

    Args:
        bot_instance: The WebexBot instance to register commands on.
    Returns:
        True if initialization succeeded, False otherwise.
    """
    if bot_instance is None:
        logger.error("Bot instance is None; cannot register commands.")
        return False
    try:
        logger.info("📝 Registering commands...")
        bot_instance.add_command(ProcessAcknowledgement())
        bot_instance.add_command(Hi())
        logger.info("✓ Bot commands registered")
        return True
    except Exception as e:
        logger.error(f"Failed registering commands: {e}", exc_info=True)
        return False


def main():
    """MSOAR main - uses resilience framework for automatic reconnection and firewall handling"""

    # Configure logging with centralized utility
    setup_logging(
        bot_name='msoar',
        log_level=logging.INFO,
        info_modules=['__main__', 'src.utils.bot_resilience', 'src.utils.webex_device_manager']
    )

    logger.info("🚀 Starting METCIRT SOAR bot")

    # Basic config validation before proceeding
    if not BOT_ACCESS_TOKEN:
        logger.critical("Missing Webex bot access token; aborting startup.")
        return
    if not NOTIFICATION_ROOM_ID:
        logger.critical("Missing notification room ID; aborting startup.")
        return

    # Get and display bot information
    bot_info = get_bot_info(BOT_ACCESS_TOKEN)
    if bot_info:
        logger.info(f"🤖 Bot name: {bot_info.get('displayName', 'METCIRT SOAR')}")
        emails = bot_info.get('emails') or []
        if emails:
            logger.info(f"📧 Bot email: {emails[0]}")
    else:
        logger.info("🤖 Bot name: METCIRT SOAR (fallback)")

    logger.info(f"📍 Notification room ID: {NOTIFICATION_ROOM_ID}")

    # Create bot instance
    bot = msoar_bot_factory()

    # Initialize commands
    msoar_initialization(bot)

    # Run bot (simple and direct)
    logger.info("🚀 MSOAR is up and running...")
    print("🚀 MSOAR is up and running...", flush=True)
    bot.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
