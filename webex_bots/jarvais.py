import logging.handlers
import threading
import time
import sys
import signal
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from pathlib import Path

import fasteners
import pandas as pd
from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot
from webexpythonsdk.models.cards import (
    AdaptiveCard, Column, ColumnSet,
    TextBlock, options, HorizontalAlignment, VerticalContentAlignment
)
from webexpythonsdk.models.cards.actions import Submit
from webexteamssdk import WebexTeamsAPI

from config import get_config
from src.epp import ring_tag_cs_hosts, cs_hosts_without_ring_tag, cs_servers_with_invalid_ring_tags
from src.epp.tanium_hosts_without_ring_tag import get_tanium_hosts_without_ring_tag
from src.utils.logging_utils import log_activity

CONFIG = get_config()
ROOT_DIRECTORY = Path(__file__).parent.parent
DATA_DIR = ROOT_DIRECTORY / "data" / "transient" / "epp_device_tagging"

# Ensure logs directory exists
(ROOT_DIRECTORY / "logs").mkdir(exist_ok=True)

# Setup logging with rotation and better formatting
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.handlers.RotatingFileHandler(
            ROOT_DIRECTORY / "logs" / "jarvais.log",
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        ),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

webex_api = WebexTeamsAPI(access_token=CONFIG.webex_bot_access_token_jarvais)

# Global variables
shutdown_requested = False
HEALTH_CHECK_INTERVAL = 300  # 5 minutes
last_health_check = time.time()
bot_start_time: datetime | None = None

# Timezone constant for consistent usage
EASTERN_TZ = ZoneInfo("America/New_York")


def send_report(room_id, filename, message) -> None:
    """Sends the enriched hosts report to a Webex room, including step run times."""
    today_date = datetime.now(timezone.utc).strftime('%m-%d-%Y')
    filepath = DATA_DIR / today_date / filename
    hosts_count = len(pd.read_excel(filepath))

    try:
        report_text = (
            f"{message}. Count={hosts_count}!"
        )
        webex_api.messages.create(
            roomId=room_id,
            text=report_text,
            files=[str(filepath)]
        )
    except FileNotFoundError:
        logger.error(f"Report file not found at {filepath}")
    except Exception as e:
        logger.error(f"Failed to send report: {e}")


def send_report_with_progress(room_id, filename, message, progress_info=None) -> None:
    """Enhanced report sending with progress information and better formatting."""
    today_date = datetime.now(timezone.utc).strftime('%m-%d-%Y')
    filepath = DATA_DIR / today_date / filename

    try:
        if not filepath.exists():
            raise FileNotFoundError(f"Report file not found at {filepath}")

        hosts_count = len(pd.read_excel(filepath))

        # Create rich message with emojis and formatting - use Eastern time for user display
        current_time_eastern = datetime.now(EASTERN_TZ)
        tz_name = "EST" if current_time_eastern.dst().total_seconds() == 0 else "EDT"

        report_text = f"📊 **{message}**\n\n"
        report_text += f"📈 **Count:** {hosts_count:,} hosts\n"
        report_text += f"📅 **Generated:** {current_time_eastern.strftime(f'%Y-%m-%d %H:%M:%S {tz_name}')}\n"

        if progress_info:
            report_text += f"⏱️ **Processing Time:** {progress_info.get('duration', 'N/A')}\n"

        webex_api.messages.create(
            roomId=room_id,
            markdown=report_text,
            files=[str(filepath)]
        )
        logger.info(f"Successfully sent report {filename} with {hosts_count} hosts to room {room_id}")

    except FileNotFoundError:
        error_msg = f"❌ Report file not found at {filepath}"
        logger.error(error_msg)
        webex_api.messages.create(
            roomId=room_id,
            markdown=error_msg
        )
    except Exception as e:
        error_msg = f"❌ Failed to send report: {str(e)}"
        logger.error(error_msg)
        webex_api.messages.create(
            roomId=room_id,
            markdown=error_msg
        )


def seek_approval_to_ring_tag(room_id):
    card = AdaptiveCard(
        body=[
            TextBlock(
                text="Ring Tagging Approval",
                color=options.Colors.ACCENT,
                size=options.FontSize.LARGE,
                weight=options.FontWeight.BOLDER,
                horizontalAlignment=HorizontalAlignment.CENTER),
            ColumnSet(
                columns=[
                    Column(
                        width="stretch",
                        items=[
                            TextBlock(text="Do you want these hosts to be Ring tagged?", wrap=True)
                        ],
                        verticalContentAlignment=VerticalContentAlignment.CENTER
                    )
                ]
            )
        ],
        actions=[
            Submit(title="No!", data={"callback_keyword": "dont_ring_tag_cs_hosts"},
                   style=options.ActionStyle.DESTRUCTIVE),
            Submit(title="Yes! Put a Ring On It!", data={"callback_keyword": "ring_tag_cs_hosts"},
                   style=options.ActionStyle.POSITIVE)
        ]
    )

    try:
        webex_api.messages.create(
            roomId=room_id,
            text="Please approve the tagging action.",
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}]
        )
    except Exception as e:
        logger.error(f"Failed to send approval card: {e}")


def seek_approval_to_delete_invalid_ring_tags(room_id):
    card = AdaptiveCard(
        body=[
            TextBlock(
                text="Invalid Ring Tag Removal Approval",
                color=options.Colors.ACCENT,
                size=options.FontSize.LARGE,
                weight=options.FontWeight.BOLDER,
                horizontalAlignment=HorizontalAlignment.CENTER),
            ColumnSet(
                columns=[
                    Column(
                        width="stretch",
                        items=[
                            TextBlock(text="Do you want these invalid Ring tags to be dropped?", wrap=True)
                        ],
                        verticalContentAlignment=VerticalContentAlignment.CENTER
                    )
                ]
            )
        ],
        actions=[
            Submit(title="No!", data={"callback_keyword": "dont_drop_invalid_ring_tags"},
                   style=options.ActionStyle.DESTRUCTIVE),
            Submit(title="Yes! Drop the invalid Ring tags!", data={"callback_keyword": "drop_invalid_ring_tags"},
                   style=options.ActionStyle.POSITIVE)
        ]
    )

    try:
        webex_api.messages.create(
            roomId=room_id,
            text="Please approve the tagging action.",
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}]
        )
    except Exception as e:
        logger.error(f"Failed to send approval card: {e}")


class CSHostsWithoutRingTag(Command):
    def __init__(self):
        super().__init__(
            command_keyword="cs_no_ring_tag",
            help_message="Get CS Hosts without a Ring Tag",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais, log_file_name="jarvais_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId
        webex_api.messages.create(
            roomId=room_id,
            markdown=f"Hello {activity['actor']['displayName']}! I've started the report generation process for CS Hosts without a Ring Tag. It is running in the background and will complete in about 5 mins."
        )
        lock_path = ROOT_DIRECTORY / "src" / "epp" / "cs_hosts_without_ring_tag.lock"
        with fasteners.InterProcessLock(lock_path):
            cs_hosts_without_ring_tag.generate_report()
            filename = "cs_hosts_last_seen_without_ring_tag.xlsx"
            message = 'Unique CS hosts without Ring tags'
            send_report(room_id, filename, message)
            seek_approval_to_ring_tag(room_id)


class RingTagCSHosts(Command):
    def __init__(self):
        super().__init__(
            command_keyword="ring_tag_cs_hosts",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais, log_file_name="jarvais_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId
        webex_api.messages.create(
            roomId=room_id,
            markdown=f"Hello {activity['actor']['displayName']}! I've started the ring tagging process for CS Hosts. It is running in the background and will complete in about 20 mins."
        )
        lock_path = ROOT_DIRECTORY / "src" / "epp" / "ring_tag_cs_hosts.lock"
        with fasteners.InterProcessLock(lock_path):
            ring_tag_cs_hosts.run_workflow(room_id)


class DontRingTagCSHosts(Command):
    def __init__(self):
        super().__init__(
            command_keyword="dont_ring_tag_cs_hosts",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais, log_file_name="jarvais_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        return f"Alright {activity['actor']['displayName']}, I won't tag no more. Until next time!👋🏾"


class CSHostsWithInvalidRingTags(Command):
    def __init__(self):
        super().__init__(
            command_keyword="cs_invalid_ring_tag",
            help_message="Get CS Servers with Invalid Ring Tags",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais, log_file_name="jarvais_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        try:
            today_date = datetime.now(timezone.utc).strftime('%m-%d-%Y')
            room_id = attachment_actions.roomId
            message = 'Unique CS servers with Invalid Ring tags'
            filename = DATA_DIR / today_date / "cs_servers_with_invalid_ring_tags_only.xlsx"
            if filename.exists():
                send_report(room_id, filename, message)
                seek_approval_to_delete_invalid_ring_tags(room_id)
                return

            webex_api.messages.create(
                roomId=room_id,
                markdown=f"Hello {activity['actor']['displayName']}! I've started the report generation process for CS Servers with Invalid Ring Tags. It is running in the background and will complete in about 15 mins."
            )
            lock_path = ROOT_DIRECTORY / "src" / "epp" / "cs_servers_with_invalid_ring_tags.lock"
            with fasteners.InterProcessLock(lock_path):
                cs_servers_with_invalid_ring_tags.generate_report()

                send_report(room_id, filename, message)
                seek_approval_to_delete_invalid_ring_tags(room_id)
        except Exception as e:
            logger.error(f"Error in CSHostsWithInvalidRingTags execute: {e}")
            try:
                webex_api.messages.create(
                    roomId=attachment_actions.roomId,
                    markdown=f"Sorry, an error occurred while generating the report: {str(e)}"
                )
            except Exception as msg_error:
                logger.error(f"Failed to send error message: {msg_error}")


class DontRemoveInvalidRings(Command):
    def __init__(self):
        super().__init__(
            command_keyword="dont_drop_invalid_ring_tag_cs_hosts",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais, log_file_name="jarvais_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        return f"Alright {activity['actor']['displayName']}, I won't remove invalid Rings. Until next time!👋🏾"


class RemoveInvalidRings(Command):
    def __init__(self):
        super().__init__(
            command_keyword="drop_invalid_ring_tags",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais, log_file_name="jarvais_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId
        today_date = datetime.now(timezone.utc).strftime('%m-%d-%Y')
        report_path = DATA_DIR / today_date / "cs_servers_with_invalid_ring_tags_only.xlsx"
        webex_api.messages.create(
            roomId=room_id,
            markdown=f"Hello {activity['actor']['displayName']}! Starting removal of invalid ring tags. This may take a few minutes."
        )
        lock_path = ROOT_DIRECTORY / "src" / "epp" / "drop_invalid_ring_tag_cs_hosts.lock"
        with fasteners.InterProcessLock(lock_path):
            try:
                df = pd.read_excel(report_path)
                # Prepare list of dicts: device_id and tags to remove
                hosts_with_tags_to_remove = []
                for _, row in df.iterrows():
                    device_id = row.get('host_id')
                    invalid_tags = row.get('invalid_tags')
                    if pd.isna(device_id) or pd.isna(invalid_tags):
                        continue
                    tags = [tag.strip() for tag in str(invalid_tags).split(',') if tag.strip()]
                    if tags:
                        hosts_with_tags_to_remove.append({'device_id': device_id, 'tags': tags})
                if not hosts_with_tags_to_remove:
                    webex_api.messages.create(
                        roomId=room_id,
                        markdown="No hosts with invalid tags found to remove."
                    )
                    return
                ring_tag_cs_hosts.TagManager.remove_tags(hosts_with_tags_to_remove)
                webex_api.messages.create(
                    roomId=room_id,
                    markdown=f"Invalid ring tags removed from {len(hosts_with_tags_to_remove)} hosts."
                )
            except Exception as e:
                logger.error(f"Error removing invalid ring tags: {e}")
                webex_api.messages.create(
                    roomId=room_id,
                    markdown=f"Failed to remove invalid ring tags: {str(e)}"
                )


class GetTaniumHostsWithoutRingTag(Command):
    def __init__(self):
        super().__init__(
            command_keyword="tanium_hosts_without_ring_tag",
            help_message="Get Tanium Hosts without a Ring Tag",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais, log_file_name="jarvais_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId
        today_date = datetime.now().strftime('%m-%d-%Y')
        filepath = DATA_DIR / today_date / "all_tanium_hosts.xlsx"
        if not filepath.exists():
            webex_api.messages.create(
                roomId=room_id,
                markdown=f"Hello {activity['actor']['displayName']}! I've started the report generation process for Tanium Hosts without a ring tag. It is running in the background and will complete in about 15 mins",
            )
            lock_path = ROOT_DIRECTORY / "src" / "epp" / "all_tanium_hosts.lock"
            with fasteners.InterProcessLock(lock_path):
                filepath = get_tanium_hosts_without_ring_tag(filename="Tanium hosts without ring tag.xlsx")

        message = f"Hello {activity['actor']['displayName']}! Here's the list of Tanium hosts without a Ring Tag. Ring tags have also been generated for your review. Count = {len(pd.read_excel(filepath))}"

        webex_api.messages.create(
            roomId=room_id,
            markdown=message,
            files=[str(filepath)]
        )


def keepalive_ping():
    wait = 60  # Start with 1 minute
    max_wait = 1800  # Max wait: 30 minutes
    while True:
        try:
            webex_api.people.me()
            wait = 240  # Reset to normal interval (4 min) after success
        except Exception as e:
            logger.warning(f"Keepalive ping failed: {e}. Retrying in {wait} seconds.")
            time.sleep(wait)
            wait = min(wait * 2, max_wait)  # Exponential backoff, capped at max_wait
            continue
        time.sleep(wait)


class GetTaniumUnhealthyHosts(Command):
    def __init__(self):
        super().__init__(
            command_keyword="tanium_unhealthy_hosts",
            help_message="Get Tanium Unhealthy Hosts",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais, log_file_name="jarvais_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId
        message = f"Hello {activity['actor']['displayName']}! This is still work in progress. Please try again later."

        webex_api.messages.create(
            roomId=room_id,
            markdown=message,
        )


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

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais, log_file_name="jarvais_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        global bot_start_time, last_health_check

        room_id = attachment_actions.roomId
        current_time = datetime.now(EASTERN_TZ)

        # Calculate uptime
        if bot_start_time:
            uptime = current_time - bot_start_time
            uptime_str = f"{uptime.days}d {uptime.seconds // 3600}h {(uptime.seconds // 60) % 60}m"
        else:
            uptime_str = "Unknown"

        # Health check info
        health_status = "🟢 Healthy" if (time.time() - last_health_check) < HEALTH_CHECK_INTERVAL else "🟡 Warning"

        # Format current time with timezone
        tz_name = "EST" if current_time.dst().total_seconds() == 0 else "EDT"

        # Create status card
        status_card = AdaptiveCard(
            body=[
                TextBlock(
                    text="🤖 Jarvais Bot Status",
                    color=options.Colors.GOOD,
                    size=options.FontSize.LARGE,
                    weight=options.FontWeight.BOLDER,
                    horizontalAlignment=HorizontalAlignment.CENTER
                ),
                ColumnSet(
                    columns=[
                        Column(
                            width="stretch",
                            items=[
                                TextBlock(text="📊 **Status Information**", weight=options.FontWeight.BOLDER),
                                TextBlock(text=f"Status: {health_status}"),
                                TextBlock(text=f"Uptime: {uptime_str}"),
                                TextBlock(text=f"Last Check: {current_time.strftime(f'%Y-%m-%d %H:%M:%S {tz_name}')}")
                            ]
                        )
                    ]
                )
            ]
        )

        webex_api.messages.create(
            roomId=room_id,
            text="Bot Status Information",
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": status_card.to_dict()}]
        )


def run_bot_with_reconnection():
    """Run the bot with automatic reconnection on failures."""
    global bot_start_time
    bot_start_time = datetime.now(EASTERN_TZ)  # Make bot_start_time timezone-aware

    max_retries = 5
    retry_delay = 30  # Start with 30 seconds
    max_delay = 300  # Max delay of 5 minutes

    for attempt in range(max_retries):
        try:
            logger.info(f"Starting Webex bot (attempt {attempt + 1}/{max_retries})")

            bot = WebexBot(
                CONFIG.webex_bot_access_token_jarvais,
                approved_rooms=[CONFIG.webex_room_id_epp_tagging, CONFIG.webex_room_id_vinay_test_space],
                bot_name="🤖 Jarvais 👋🏾\n The Ring Tagging Assistant",
                threads=True,
                log_level="ERROR",
                bot_help_subtitle="🏷️ Your friendly neighborhood tagging bot! Click a button to start!"
            )

            # Add commands to the bot
            bot.add_command(CSHostsWithoutRingTag())
            bot.add_command(RingTagCSHosts())
            bot.add_command(DontRingTagCSHosts())
            bot.add_command(CSHostsWithInvalidRingTags())
            bot.add_command(RemoveInvalidRings())
            bot.add_command(DontRemoveInvalidRings())
            bot.add_command(GetTaniumHostsWithoutRingTag())
            bot.add_command(GetTaniumUnhealthyHosts())
            bot.add_command(BotStatusCommand())

            print("🤖 Jarvais is up and running with enhanced features...")
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
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    threading.Thread(target=keepalive_ping, daemon=True).start()

    # Run bot with automatic reconnection
    run_bot_with_reconnection()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
