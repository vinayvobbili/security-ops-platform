import json
import logging.handlers
import random
import signal
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import webexpythonsdk.models.cards.inputs as INPUTS
import webexpythonsdk.models.cards.options as OPTIONS
from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot
from webexpythonsdk.models.cards import (
    Colors, TextBlock, FontWeight, FontSize,
    Column, AdaptiveCard, ColumnSet, Image,
    HorizontalAlignment, ActionSet, ImageStyle, ActionStyle, Choice, FactSet, Fact
)
from webexpythonsdk.models.cards.actions import Submit
from webexteamssdk import WebexTeamsAPI

from config import get_config
from src.charts import threatcon_level
from src.utils.logging_utils import log_activity

ROOT_DIRECTORY = Path(__file__).parent.parent

# Ensure logs directory exists
(ROOT_DIRECTORY / "logs").mkdir(exist_ok=True)

# Setup logging with rotation and better formatting
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.handlers.RotatingFileHandler(
            ROOT_DIRECTORY / "logs" / "barnacles.log",
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        ),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

config = get_config()
bot_token = config.webex_bot_access_token_barnacles
webex_api = WebexTeamsAPI(access_token=bot_token)

# Global variables for health monitoring
shutdown_requested = False
HEALTH_CHECK_INTERVAL = 300  # 5 minutes
last_health_check = time.time()
bot_start_time: datetime | None = None

# Timezone constant for consistent usage
EASTERN_TZ = ZoneInfo("America/New_York")

NOTES_FILE = "../data/transient/secOps/management_notes.json"
THREAT_CON_FILE = "../data/transient/secOps/threatcon.json"
COMPANY_LOGO_BASE64 = "../web/static/icons/company_logo.txt"

with open(COMPANY_LOGO_BASE64, "r") as file:
    company_logo = file.read()

ICONS_BY_COLOR = {
    'green': '🟢',
    'yellow': '🟡',
    'orange': '🟠',
    'red': '🔴'
}

# Fun ThreatCon related messages
THREATCON_MESSAGES = {
    "green": ["🌿 All clear! Smooth sailing ahead!", "🍃 Peaceful waters, captain!", "☘️ Green means go!"],
    "yellow": ["⚠️ Caution advised, stay alert!", "🟡 Moderate threat detected!", "🚧 Proceed with awareness!"],
    "orange": ["🚨 Elevated threat level!", "🔥 High alert status!", "⚡ Heightened security mode!"],
    "red": ["🚩 MAXIMUM ALERT! All hands on deck!", "🔴 CRITICAL THREAT LEVEL!", "⭐ Emergency protocols active!"]
}

BARNACLES_QUOTES = [
    "⚓ Anchors aweigh!",
    "🌊 Steady as she goes!",
    "🧭 Charting the course ahead!",
    "⛵ Full speed ahead!",
    "🏴‍☠️ Yo ho ho and a bottle of... data!"
]


def keepalive_ping():
    """Keep the bot connection alive with periodic pings."""
    global last_health_check
    wait = 60  # Start with 1 minute
    max_wait = 1800  # Max wait: 30 minutes
    while not shutdown_requested:
        try:
            webex_api.people.me()
            last_health_check = time.time()  # Update on successful ping
            wait = 240  # Reset to normal interval (4 min) after success
        except Exception as e:
            logger.warning(f"Keepalive ping failed: {e}. Retrying in {wait} seconds.")
            # Don't update last_health_check on failure - this will trigger warning status
            time.sleep(wait)
            wait = min(wait * 2, max_wait)  # Exponential backoff, capped at max_wait
            continue
        time.sleep(wait)


def signal_handler(_sig, _frame):
    """Handle signals for graceful shutdown."""
    global shutdown_requested
    shutdown_requested = True
    logger.info("Shutdown requested. Cleaning up and exiting...")
    sys.exit(0)


class BotStatusCommand(Command):
    """Command to check bot health and status."""

    def __init__(self):
        super().__init__(
            command_keyword="bot_status",
            help_message="🔍 Check bot health and status",
            delete_previous_message=True,
        )

    @log_activity(config.webex_bot_access_token_barnacles, "barnacles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        global bot_start_time, last_health_check

        current_time = datetime.now(EASTERN_TZ)

        # Calculate uptime
        if bot_start_time:
            uptime = current_time - bot_start_time
            uptime_str = f"{uptime.days}d {uptime.seconds // 3600}h {(uptime.seconds // 60) % 60}m"
        else:
            uptime_str = "Unknown"

        # Health check info with better explanations
        time_since_last_check = time.time() - last_health_check
        if time_since_last_check < HEALTH_CHECK_INTERVAL:
            health_status = "🟢 Healthy"
            health_detail = "Webex connection stable"
        else:
            health_status = "🟡 Warning"
            minutes_overdue = int((time_since_last_check - HEALTH_CHECK_INTERVAL) / 60)
            health_detail = f"Webex API connection issues detected ({minutes_overdue}min ago)"

        # Format current time with timezone
        tz_name = "EST" if current_time.dst().total_seconds() == 0 else "EDT"

        # Format last health check time
        last_check_time = datetime.fromtimestamp(last_health_check, EASTERN_TZ)
        last_check_str = last_check_time.strftime(f'%H:%M:%S {tz_name}')

        # Create status card with enhanced details
        status_card = AdaptiveCard(
            body=[
                TextBlock(
                    text="⚓ Barnacles Bot 🤖 Status",
                    color=Colors.GOOD,
                    size=FontSize.LARGE,
                    weight=FontWeight.BOLDER,
                    horizontalAlignment=HorizontalAlignment.CENTER
                ),
                ColumnSet(
                    columns=[
                        Column(
                            width="stretch",
                            items=[
                                TextBlock(text="📊 **Status Information**", weight=FontWeight.BOLDER),
                                TextBlock(text=f"Status: {health_status}"),
                                TextBlock(text=f"Details: {health_detail}"),
                                TextBlock(text=f"Uptime: {uptime_str}"),
                                TextBlock(text=f"Last Health Check: {last_check_str}"),
                                TextBlock(text=f"Current Time: {current_time.strftime(f'%Y-%m-%d %H:%M:%S {tz_name}')}")
                            ]
                        )
                    ]
                )
            ]
        )

        webex_api.messages.create(
            toPersonEmail=activity['actor']['id'],
            text="Bot Status Information",
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": status_card.to_dict()}]
        )


# Command to save notes
class SaveManagementNotes(Command):
    def __init__(self):
        super().__init__(
            command_keyword="save_notes",
            delete_previous_message=True,
            exact_command_keyword_match=True
        )

    @log_activity(config.webex_bot_access_token_barnacles, "barnacles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        try:
            with open(NOTES_FILE, "w") as file:
                file.write(json.dumps({
                    "note": attachment_actions.inputs['management_notes'],
                    "keep_until": attachment_actions.inputs['keep_until']
                }, indent=4))

            card = AdaptiveCard(
                body=[
                    TextBlock(
                        text="Notes Updated Successfully",
                        weight=FontWeight.BOLDER,
                        color=Colors.ACCENT,
                        size=FontSize.DEFAULT,
                        horizontalAlignment=HorizontalAlignment.CENTER,
                    ),
                    FactSet(
                        facts=[
                            Fact(title="Note", value=attachment_actions.inputs['management_notes']),
                            Fact(title="Keep Until", value=attachment_actions.inputs['keep_until'])
                        ]
                    )
                ]
            )

            webex_api.messages.create(
                toPersonEmail=activity['actor']['id'],
                text='Notes Saved Successfully',
                attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}]
            )
            logger.info(f"Management notes saved successfully by {activity['actor']['displayName']}")

        except Exception as e:
            error_msg = f"❌ Failed to save notes: {str(e)}"
            logger.error(error_msg)
            try:
                webex_api.messages.create(
                    toPersonEmail=activity['actor']['id'],
                    text=error_msg
                )
            except Exception as msg_error:
                logger.error(f"Failed to send error message: {msg_error}")


# Command to view/edit notes
class ManagementNotes(Command):
    def __init__(self):
        super().__init__(
            command_keyword="notes",
            help_message="Management Notes",
        )

    @log_activity(config.webex_bot_access_token_barnacles, "barnacles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        try:
            with open(NOTES_FILE, "r") as file:
                management_notes = file.read()
                management_notes = json.loads(management_notes)
                note = management_notes['note']
                keep_until = management_notes['keep_until']

            today = datetime.now().strftime("%Y-%m-%d")
            next_week = (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d")
            tomorrow = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")

            card = AdaptiveCard(
                body=[
                    ColumnSet(
                        columns=[
                            Column(
                                items=[
                                    Image(
                                        url=company_logo,
                                        height="30px",
                                        style=ImageStyle.PERSON
                                    )
                                ],
                                width="auto"
                            ),
                            Column(
                                items=[
                                    TextBlock(
                                        text="Management Notes",
                                        wrap=True,
                                        size=FontSize.MEDIUM,
                                        weight=FontWeight.BOLDER,
                                        color=Colors.ACCENT,
                                        horizontalAlignment=HorizontalAlignment.CENTER,
                                    )
                                ],
                                width="stretch",
                            )
                        ]
                    ),
                    INPUTS.Text(
                        id="management_notes",
                        isMultiline=True,
                        value=note,
                        placeholder="Enter notes here",
                        isRequired=True,
                    ),
                    ColumnSet(
                        columns=[
                            Column(
                                items=[
                                    TextBlock(
                                        text="Keep Until",
                                        horizontalAlignment=HorizontalAlignment.LEFT,
                                        color=OPTIONS.Colors.DARK,
                                        height=OPTIONS.BlockElementHeight.STRETCH
                                    )
                                ],
                                width="auto"
                            ),
                            Column(
                                items=[
                                    INPUTS.Date(
                                        id='keep_until',
                                        max=next_week,
                                        min=today,
                                        value=keep_until or tomorrow,
                                        isRequired=True,
                                        height=OPTIONS.BlockElementHeight.AUTO
                                    )
                                ],
                                width="175px",
                            )
                        ]
                    ),
                    ActionSet(
                        actions=[
                            Submit(
                                title="Update",
                                style=ActionStyle.POSITIVE,
                                data={"callback_keyword": "save_notes"},
                            ),
                        ],
                        spacing=OPTIONS.Spacing.NONE,
                    )
                ]
            )

            webex_api.messages.create(
                toPersonEmail=activity['actor']['id'],
                text='Management Notes',
                attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}]
            )
            logger.info(f"Management notes viewed by {activity['actor']['displayName']}")

        except Exception as e:
            error_msg = f"❌ Failed to load notes: {str(e)}"
            logger.error(error_msg)
            try:
                webex_api.messages.create(
                    toPersonEmail=activity['actor']['id'],
                    text=error_msg
                )
            except Exception as msg_error:
                logger.error(f"Failed to send error message: {msg_error}")


# Command to update threatcon level
class SaveThreatcon(Command):
    def __init__(self):
        super().__init__(
            command_keyword="save_threatcon",
            delete_previous_message=True,
            exact_command_keyword_match=True
        )

    @log_activity(config.webex_bot_access_token_barnacles, "barnacles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        try:
            level = attachment_actions.inputs['threatcon_level']
            reason = attachment_actions.inputs['reason']

            threatcon_details = {
                "level": level,
                "reason": reason
            }

            with open(THREAT_CON_FILE, "w") as file:
                json.dump(threatcon_details, file, indent=4)

            card = AdaptiveCard(
                body=[
                    TextBlock(
                        text="ThreatCon Level Updated Successfully",
                        weight=FontWeight.BOLDER,
                        color=Colors.ACCENT,
                        horizontalAlignment=HorizontalAlignment.CENTER
                    ),
                    TextBlock(
                        text=f"ThreatCon Level: {ICONS_BY_COLOR.get(level, '🟢') + ' ' + level.capitalize()}",
                    ),
                    TextBlock(
                        text=f"Reason: \n {reason}",
                        wrap=True
                    ),
                    ActionSet(
                        actions=[
                            Submit(
                                title="Announce",
                                style=ActionStyle.POSITIVE,
                                data={"callback_keyword": "announce_threatcon"}
                            )
                        ]
                    )
                ]
            )

            webex_api.messages.create(
                toPersonEmail=activity['actor']['id'],
                text='ThreatCon Level Updated Successfully',
                attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}]
            )
            logger.info(f"ThreatCon level updated to {level} by {activity['actor']['displayName']}")

            # Send a fun ThreatCon-related message
            fun_message = get_threatcon_message(level)
            webex_api.messages.create(
                toPersonEmail=activity['actor']['id'],
                text=fun_message
            )

        except Exception as e:
            error_msg = f"❌ Failed to save ThreatCon level: {str(e)}"
            logger.error(error_msg)
            try:
                webex_api.messages.create(
                    toPersonEmail=activity['actor']['id'],
                    text=error_msg
                )
            except Exception as msg_error:
                logger.error(f"Failed to send error message: {msg_error}")


class ThreatconLevel(Command):
    def __init__(self):
        super().__init__(
            command_keyword="threatcon",
            help_message="ThreatCon Level",
        )

    @log_activity(config.webex_bot_access_token_barnacles, "barnacles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        try:
            with open(THREAT_CON_FILE, "r") as file:
                threatcon_details = json.load(file)

            level = threatcon_details.get('level', 'green')
            reason = threatcon_details.get('reason', 'No current threats!')

            card = AdaptiveCard(
                body=[
                    ColumnSet(
                        columns=[
                            Column(
                                items=[
                                    Image(
                                        url=company_logo,
                                        height="30px",
                                        style=ImageStyle.PERSON
                                    )
                                ],
                                width="auto"
                            ),
                            Column(
                                items=[
                                    TextBlock(
                                        text="ThreatCon",
                                        wrap=True,
                                        size=FontSize.LARGE,
                                        weight=FontWeight.BOLDER,
                                        color=Colors.ACCENT,
                                        horizontalAlignment=HorizontalAlignment.CENTER
                                    )
                                ],
                                width="stretch"
                            )
                        ]
                    ),
                    INPUTS.ChoiceSet(
                        id="threatcon_level",
                        value=level,
                        label="Level",
                        choices=[
                            Choice(title="🟢 Green", value="green"),
                            Choice(title="🟡 Yellow", value="yellow"),
                            Choice(title="🟠 Orange", value="orange"),
                            Choice(title="🔴 Red", value="red"),
                        ],
                        style=OPTIONS.ChoiceInputStyle.EXPANDED
                    ),
                    INPUTS.Text(
                        id="reason",
                        label="Reason",
                        isMultiline=True,
                        value=reason,
                        placeholder="Enter reason here",
                        isRequired=True
                    ),
                    ActionSet(
                        spacing=OPTIONS.Spacing.NONE,
                        actions=[
                            Submit(
                                title="Update",
                                style=ActionStyle.POSITIVE,
                                data={"callback_keyword": "save_threatcon"}
                            )
                        ],
                    )
                ]
            )

            webex_api.messages.create(
                toPersonEmail=activity['actor']['id'],
                text='Threatcon Level',
                attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}]
            )
            logger.info(f"ThreatCon level viewed by {activity['actor']['displayName']}")

        except Exception as e:
            error_msg = f"❌ Failed to load ThreatCon level: {str(e)}"
            logger.error(error_msg)
            try:
                webex_api.messages.create(
                    toPersonEmail=activity['actor']['id'],
                    text=error_msg
                )
            except Exception as msg_error:
                logger.error(f"Failed to send error message: {msg_error}")


class AnnounceThreatcon(Command):
    def __init__(self):
        super().__init__(
            command_keyword="announce_threatcon",
            delete_previous_message=True,
            exact_command_keyword_match=True
        )

    @log_activity(config.webex_bot_access_token_barnacles, "barnacles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        try:
            threatcon_level.make_chart()

            today_date = datetime.now().strftime('%m-%d-%Y')
            FILE_PATH = ROOT_DIRECTORY / "web" / "static" / "charts" / today_date / "Threatcon Level.png"

            WebexTeamsAPI(access_token=config.webex_bot_access_token_toodles).messages.create(
                roomId=config.webex_room_id_threatcon_collab,
                text=f"🚨🚨 NEW THREATCON LEVEL ANNOUNCEMENT! 🚨🚨",
                files=[str(FILE_PATH)]
            )

            # Confirm to user
            confirmation_card = AdaptiveCard(
                body=[
                    TextBlock(
                        text="ThreatCon Announcement Sent",
                        weight=FontWeight.BOLDER,
                        color=Colors.GOOD,
                        horizontalAlignment=HorizontalAlignment.CENTER
                    ),
                    TextBlock(
                        text=f"The ThreatCon Level change has been announced.",
                        wrap=True
                    )
                ]
            )

            webex_api.messages.create(
                toPersonEmail=activity['actor']['id'],
                text='ThreatCon Announcement Sent',
                attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": confirmation_card.to_dict()}]
            )
            logger.info(f"ThreatCon announcement sent by {activity['actor']['displayName']}")

        except Exception as e:
            error_msg = f"❌ Failed to announce ThreatCon level: {str(e)}"
            logger.error(error_msg)
            try:
                webex_api.messages.create(
                    toPersonEmail=activity['actor']['id'],
                    text=error_msg
                )
            except Exception as msg_error:
                logger.error(f"Failed to send error message: {msg_error}")


def get_random_barnacles_quote():
    """Get a random nautical quote."""
    return random.choice(BARNACLES_QUOTES)


def get_threatcon_message(level):
    """Get a themed message for ThreatCon levels."""
    return random.choice(THREATCON_MESSAGES.get(level, THREATCON_MESSAGES["green"]))


def run_bot_with_reconnection():
    """Run the bot with automatic reconnection on failures."""
    global bot_start_time
    bot_start_time = datetime.now(EASTERN_TZ)  # Make bot_start_time timezone-aware

    max_retries = 5
    retry_delay = 30  # Start with 30 seconds
    max_delay = 300  # Max delay of 5 minutes

    for attempt in range(max_retries):
        try:
            logger.info(f"Starting Barnacles bot (attempt {attempt + 1}/{max_retries})")

            bot = WebexBot(
                bot_token,
                approved_rooms=[],
                approved_users=config.barnacles_approved_users.split(','),
                bot_name="⚓ Barnacles 🤖\n The Captain's Assistant",
                threads=True,
                log_level="ERROR",
                bot_help_subtitle="🚨 Your ThreatCon and management notes assistant! Click a button to start!"
            )

            # Add commands to the bot
            bot.add_command(ManagementNotes())
            bot.add_command(ThreatconLevel())
            bot.add_command(SaveManagementNotes())
            bot.add_command(SaveThreatcon())
            bot.add_command(AnnounceThreatcon())
            bot.add_command(BotStatusCommand())

            print("⚓ Barnacles is up and running with enhanced features...")
            logger.info(f"Bot started successfully at {bot_start_time}")

            # Start the bot
            bot.run()

            # If we reach here, the bot stopped normally
            logger.info("Bot stopped normally")
            break

        except KeyboardInterrupt:
            logger.info("Bot stopped by user")
            break
        except Exception as e:
            logger.error(f"Bot crashed with error: {e}")

            if attempt < max_retries - 1:
                logger.info(f"Restarting bot in {retry_delay} seconds...")
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, max_delay)  # Exponential backoff
            else:
                logger.error("Max retries exceeded. Bot will not restart.")
                raise


def main():
    """Initialize and run the Webex bot with enhanced features."""

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start keepalive thread
    threading.Thread(target=keepalive_ping, daemon=True).start()

    # Run bot with automatic reconnection
    run_bot_with_reconnection()


if __name__ == "__main__":
    main()
