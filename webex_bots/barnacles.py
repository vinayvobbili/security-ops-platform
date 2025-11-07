#!/usr/bin/python3

import sys
from pathlib import Path

ROOT_DIRECTORY = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT_DIRECTORY))

# Setup logging FIRST before any imports that might use it
import logging

from src.utils.logging_utils import setup_logging

# Configure logging with centralized utility
setup_logging(
    bot_name='barnacles',
    log_level=logging.WARNING,
    log_dir=str(ROOT_DIRECTORY / "logs"),
    info_modules=['__main__', 'src.utils.bot_resilience', 'src.utils.webex_device_manager']
)

# Note: Noisy library logs are suppressed by ResilientBot framework

logger = logging.getLogger(__name__)

# ALWAYS configure SSL for proxy environments (auto-detects ZScaler/proxies)
from src.utils.ssl_config import configure_ssl_if_needed
configure_ssl_if_needed(verbose=True)

# ALWAYS apply enhanced WebSocket patches for connection resilience
# This is critical to prevent the bot from going to sleep
from src.utils.enhanced_websocket_client import patch_websocket_client
patch_websocket_client()

import json
import random
from datetime import datetime, timedelta
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

from my_config import get_config
from src.charts import threatcon_level
from src.utils.logging_utils import log_activity
from src.utils.webex_device_manager import cleanup_devices_on_startup

config = get_config()
bot_token = config.webex_bot_access_token_barnacles
webex_api = WebexTeamsAPI(access_token=bot_token)

# Global variables
bot_instance = None

# Timezone constant for consistent usage
EASTERN_TZ = ZoneInfo("America/New_York")

NOTES_FILE = ROOT_DIRECTORY / "data" / "transient" / "secOps" / "management_notes.json"
THREAT_CON_FILE = ROOT_DIRECTORY / "data" / "transient" / "secOps" / "threatcon.json"
COMPANY_LOGO_BASE64 = ROOT_DIRECTORY / "web" / "static" / "icons" / "company_logo.txt"

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
        current_time = datetime.now(EASTERN_TZ)

        # Simple status using the resilience framework
        health_status = "🟢 Healthy"
        health_detail = "Running with resilience framework"

        # Format current time with timezone
        tz_name = "EST" if current_time.dst().total_seconds() == 0 else "EDT"

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
                                TextBlock(text=f"Framework: BotResilient (auto-reconnect, health monitoring)"),
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


class Hi(Command):
    """Simple Hi command to check if bot is alive."""

    def __init__(self):
        super().__init__(
            command_keyword="hi",
            delete_previous_message=False,
            exact_command_keyword_match=False,
        )

    @log_activity(config.webex_bot_access_token_barnacles, "barnacles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        return "Hi 👋🏾"


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
                                title="Announce in ThreatCon Chat",
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
            file_path = ROOT_DIRECTORY / "web" / "static" / "charts" / today_date / "Threatcon Level.png"

            WebexTeamsAPI(access_token=config.webex_bot_access_token_toodles).messages.create(
                roomId=config.webex_room_id_threatcon_collab,
                text=f"🚨 **NEW THREATCON LEVEL ANNOUNCEMENT!** 🚨",
                files=[str(file_path)]
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


def barnacles_bot_factory():
    """Create Barnacles bot instance"""
    # Clean up stale device registrations before starting
    # (to prevent device buildup from automatic restarts)
    cleanup_devices_on_startup(
        bot_token,
        bot_name="Barnacles"
    )

    return WebexBot(
        bot_token,
        approved_rooms=[],
        approved_users=config.barnacles_approved_users.split(','),
        bot_name="Barnacles - The Captain's Assistant",
        threads=True,
        log_level="ERROR",
        bot_help_subtitle="Click a button to start!"
    )


def barnacles_initialization(bot_instance=None):
    """Initialize Barnacles commands"""
    if bot_instance:
        # Add commands to the bot
        bot_instance.add_command(ManagementNotes())
        bot_instance.add_command(ThreatconLevel())
        bot_instance.add_command(SaveManagementNotes())
        bot_instance.add_command(SaveThreatcon())
        bot_instance.add_command(AnnounceThreatcon())
        bot_instance.add_command(BotStatusCommand())
        bot_instance.add_command(Hi())
        return True
    return False


def main():
    """Barnacles main - always uses resilience framework"""
    from src.utils.bot_resilience import ResilientBot

    logger.info("Starting Barnacles with standard resilience framework")

    resilient_runner = ResilientBot(
        bot_name="Barnacles",
        bot_factory=barnacles_bot_factory,
        initialization_func=barnacles_initialization,
        max_retries=5,
        initial_retry_delay=30,
        max_retry_delay=300,
        keepalive_interval=90,  # Staggered to avoid synchronized API load (60s, 75s, 90s, 105s, 120s)
    )
    resilient_runner.run()


if __name__ == "__main__":
    main()
