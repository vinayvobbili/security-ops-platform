#!/usr/bin/python3

# Configure SSL for corporate proxy environments (Zscaler, etc.) - MUST BE FIRST
import sys
from pathlib import Path

ROOT_DIRECTORY = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT_DIRECTORY))

# Setup logging FIRST before any imports that might use it
import logging

from src.utils.logging_utils import setup_logging

# Configure logging with centralized utility
setup_logging(
    bot_name='jarvis',
    log_level=logging.WARNING,
    log_dir=str(ROOT_DIRECTORY / "logs"),
    info_modules=['__main__', 'src.utils.bot_resilience', 'src.utils.webex_device_manager']
)

logger = logging.getLogger(__name__)
# Suppress noisy INFO messages from webex libraries
logging.getLogger('webex_bot').setLevel(logging.WARNING)
logging.getLogger('webexteamssdk').setLevel(logging.ERROR)
logging.getLogger('webex_websocket_client').setLevel(logging.WARNING)

from src.utils.ssl_config import configure_ssl_if_needed

configure_ssl_if_needed(verbose=True)  # Re-enabled due to ZScaler connectivity issues

# Apply enhanced WebSocket client patch for better connection resilience
from src.utils.enhanced_websocket_client import patch_websocket_client

patch_websocket_client()

import random
from datetime import datetime
from zoneinfo import ZoneInfo

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

from my_config import get_config
from src.epp import ring_tag_cs_hosts, cs_hosts_without_ring_tag, cs_servers_with_invalid_ring_tags
from src.utils.logging_utils import log_activity
from src.utils.webex_device_manager import cleanup_devices_on_startup
from src.utils.webex_pool_config import configure_webex_api_session

CONFIG = get_config()
DATA_DIR = ROOT_DIRECTORY / "data" / "transient" / "epp_device_tagging"

# Configure WebexTeamsAPI with larger connection pool to prevent timeout issues
# Multiple bots on same VM + concurrent message processing can exhaust default 10-connection pool
webex_api = configure_webex_api_session(
    WebexTeamsAPI(
        access_token=CONFIG.webex_bot_access_token_jarvis,
        single_request_timeout=120,  # Increased from default 60s to handle VM network latency
    ),
    pool_connections=50,  # Increased from default 10
    pool_maxsize=50,      # Increased from default 10
    max_retries=3         # Enable automatic retry on transient failures
)

# Timezone constant for consistent usage
EASTERN_TZ = ZoneInfo("America/New_York")

# Global resilient bot runner instance (set in main())
_resilient_runner = None

# Fun loading messages
LOADING_MESSAGES = [
    "🔮 Consulting the digital crystal ball...",
    "🧙‍♂️ Casting data summoning spells...",
    "🚀 Launching rockets to data planet...",
    "🕵️‍♂️ Investigating the mysteries of your data...",
    "🎯 Targeting the perfect metrics...",
    "🧠 Teaching AI to count really, really fast...",
    "☕ Brewing fresh analytics (with extra caffeine)...",
    "🎪 Orchestrating a spectacular data circus...",
    "🏃‍♂️ Running marathons through databases...",
    "🎨 Painting beautiful charts with data brushes...",
    "🛠️ Assembling data with precision tools...",
    "🌐 Surfing the waves of information...",
    "🔎 Zooming in on the tiniest details...",
    "📦 Unpacking boxes of insights...",
    "🦾 Deploying robot assistants for your data...",
    "🧩 Piecing together the data puzzle...",
    "🛰️ Beaming up your data to the cloud...",
    "🦉 Consulting the wise data owl...",
    "🧬 Sequencing the DNA of your datasets...",
    "🦄 Searching for unicorns in your data...",
    "🧊 Chilling with cool analytics...",
    "🦖 Digging up data fossils...",
    "🧗‍♂️ Climbing the mountain of information...",
    "🛸 Abducting anomalies for analysis...",
    "🦋 Transforming raw data into insights...",
    "🧹 Sweeping up data dust...",
    "🧲 Attracting the most relevant facts...",
    "🦜 Parroting back the best results...",
    "🦩 Flamingling with fancy metrics...",
    "🦦 Otterly focused on your request...",
    "🦔 Prickling through the data haystack..."
]


def get_random_loading_message():
    """Get a random fun loading message."""
    return random.choice(LOADING_MESSAGES)


def send_report(room_id, filename, message) -> None:
    """Sends the enriched hosts report to a Webex room, including step run times."""
    today_date = datetime.now(EASTERN_TZ).strftime('%m-%d-%Y')
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
    today_date = datetime.now(EASTERN_TZ).strftime('%m-%d-%Y')
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
    import time

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
            Submit(title="Yes! Put a 💍 On It!", data={"callback_keyword": "ring_tag_cs_hosts"},
                   style=options.ActionStyle.POSITIVE)
        ]
    )

    # Retry logic for transient API failures
    max_retries = 3
    retry_delay = 2

    for attempt in range(max_retries):
        try:
            webex_api.messages.create(
                roomId=room_id,
                text="Please approve the tagging action.",
                attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}]
            )
            return
        except Exception as e:
            error_msg = str(e)
            is_retryable = any(code in error_msg for code in ['503', '429', '502', '504'])

            if is_retryable and attempt < max_retries - 1:
                wait_time = retry_delay * (2 ** attempt)
                logger.warning(f"Transient error sending CS approval card (attempt {attempt + 1}/{max_retries}): {e}. Retrying in {wait_time}s...")
                time.sleep(wait_time)
                continue
            else:
                logger.error(f"Failed to send CS approval card after {attempt + 1} attempts: {e}")
                # Try to send error notification with its own retry logic
                for notify_attempt in range(2):  # Try twice to send error notification
                    try:
                        if is_retryable:
                            webex_api.messages.create(
                                roomId=room_id,
                                markdown=f"❌ **Error**: Webex API is temporarily unavailable (tried {max_retries} times). Please try your command again in a few minutes.\n\nError: {error_msg}"
                            )
                        else:
                            webex_api.messages.create(
                                roomId=room_id,
                                markdown=f"❌ **Error**: Failed to send approval card. Please check the logs or contact support.\n\nError details: {error_msg}"
                            )
                        break  # Success, exit retry loop
                    except Exception as notify_error:
                        if notify_attempt < 1:  # One more try
                            logger.warning(f"Failed to send error notification (attempt {notify_attempt + 1}/2): {notify_error}. Retrying...")
                            time.sleep(3)
                        else:
                            logger.error(f"Failed to send error notification after 2 attempts: {notify_error}")
                            logger.error(f"⚠️ IMPORTANT: User was NOT notified about approval card failure. Check Webex room manually.")
                return


def seek_approval_to_delete_invalid_ring_tags(room_id):
    import time

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

    # Retry logic for transient API failures
    max_retries = 3
    retry_delay = 2

    for attempt in range(max_retries):
        try:
            webex_api.messages.create(
                roomId=room_id,
                text="Please approve the tagging action.",
                attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}]
            )
            return
        except Exception as e:
            error_msg = str(e)
            is_retryable = any(code in error_msg for code in ['503', '429', '502', '504'])

            if is_retryable and attempt < max_retries - 1:
                wait_time = retry_delay * (2 ** attempt)
                logger.warning(f"Transient error sending invalid ring tags approval card (attempt {attempt + 1}/{max_retries}): {e}. Retrying in {wait_time}s...")
                time.sleep(wait_time)
                continue
            else:
                logger.error(f"Failed to send invalid ring tags approval card after {attempt + 1} attempts: {e}")
                # Try to send error notification with its own retry logic
                for notify_attempt in range(2):  # Try twice to send error notification
                    try:
                        if is_retryable:
                            webex_api.messages.create(
                                roomId=room_id,
                                markdown=f"❌ **Error**: Webex API is temporarily unavailable (tried {max_retries} times). Please try your command again in a few minutes.\n\nError: {error_msg}"
                            )
                        else:
                            webex_api.messages.create(
                                roomId=room_id,
                                markdown=f"❌ **Error**: Failed to send approval card. Please check the logs or contact support.\n\nError details: {error_msg}"
                            )
                        break  # Success, exit retry loop
                    except Exception as notify_error:
                        if notify_attempt < 1:  # One more try
                            logger.warning(f"Failed to send error notification (attempt {notify_attempt + 1}/2): {notify_error}. Retrying...")
                            time.sleep(3)
                        else:
                            logger.error(f"Failed to send error notification after 2 attempts: {notify_error}")
                            logger.error(f"⚠️ IMPORTANT: User was NOT notified about approval card failure. Check Webex room manually.")
                return


class GetCSHostsWithoutRingTag(Command):
    def __init__(self):
        super().__init__(
            command_keyword="cs_no_ring_tag",
            help_message="Get CS Hosts without a Ring Tag 🛡️💍",
            delete_previous_message=False,  # Keep the command visible for reuse
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvis, log_file_name="jarvis_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId
        loading_msg = get_random_loading_message()
        webex_api.messages.create(
            roomId=room_id,
            markdown=(
                f"Hello {activity['actor']['displayName']}! {loading_msg}\n\n"
                "🛡️ **CrowdStrike Hosts Without Ring Tag Report** 🏷️\n"
                "Estimated completion: ~5 minutes ⏰"
            )
        )
        lock_path = ROOT_DIRECTORY / "src" / "epp" / "cs_hosts_without_ring_tag.lock"
        try:
            with fasteners.InterProcessLock(lock_path):
                cs_hosts_without_ring_tag.generate_report()
                filename = "cs_hosts_last_seen_without_ring_tag.xlsx"
                message = 'Unique CS hosts without Ring tags'
                send_report(room_id, filename, message)
                seek_approval_to_ring_tag(room_id)
        except Exception as e:
            logger.error(f"Error in CSHostsWithoutRingTag execute: {e}")
            webex_api.messages.create(
                roomId=room_id,
                markdown=f"❌ An error occurred while processing your request: {e}"
            )
        finally:
            # Ensure the lock file is removed to prevent stale locks
            if lock_path.exists():
                try:
                    lock_path.unlink()
                except Exception as e:
                    logger.error(f"Failed to remove lock file {lock_path}: {e}")


class RingTagCSHosts(Command):
    def __init__(self):
        super().__init__(
            command_keyword="ring_tag_cs_hosts",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvis, log_file_name="jarvis_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId
        loading_msg = get_random_loading_message()
        webex_api.messages.create(
            roomId=room_id,
            markdown=f"Hello {activity['actor']['displayName']}! {loading_msg}\n\n🏷️**I've started ring tagging the CS Hosts and it is running in the background**\nEstimated completion: ~15 minutes ⏰"
        )
        lock_path = ROOT_DIRECTORY / "src" / "epp" / "ring_tag_cs_hosts.lock"
        try:
            with fasteners.InterProcessLock(lock_path):
                ring_tag_cs_hosts.run_workflow(room_id)
        except Exception as e:
            logger.error(f"Error in RingTagCSHosts execute: {e}")
            webex_api.messages.create(
                roomId=room_id,
                markdown=f"❌ An error occurred while processing your request: {e}"
            )
        finally:
            if lock_path.exists():
                try:
                    lock_path.unlink()
                except Exception as e:
                    logger.error(f"Failed to remove lock file {lock_path}: {e}")


class DontRingTagCSHosts(Command):
    def __init__(self):
        super().__init__(
            command_keyword="dont_ring_tag_cs_hosts",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvis, log_file_name="jarvis_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        return f"Alright {activity['actor']['displayName']}, I won't tag no more. Until next time!👋🏾"


class GetCSHostsWithInvalidRingTags(Command):
    def __init__(self):
        super().__init__(
            command_keyword="cs_invalid_ring_tag",
            help_message="Get CS Servers with Invalid Ring Tags 🛡️❌💍",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvis, log_file_name="jarvis_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        today_date = datetime.now(EASTERN_TZ).strftime('%m-%d-%Y')
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
        try:
            with fasteners.InterProcessLock(lock_path):
                cs_servers_with_invalid_ring_tags.generate_report()
                send_report(room_id, filename, message)
                seek_approval_to_delete_invalid_ring_tags(room_id)
        except Exception as e:
            logger.error(f"Error in CSHostsWithInvalidRingTags execute: {e}")
            try:
                webex_api.messages.create(
                    roomId=room_id,
                    markdown=f"Sorry, an error occurred while generating the report: {str(e)}"
                )
            except Exception as msg_error:
                logger.error(f"Failed to send error message: {msg_error}")
        finally:
            if lock_path.exists():
                try:
                    lock_path.unlink()
                except Exception as e:
                    logger.error(f"Failed to remove lock file {lock_path}: {e}")


class DontRemoveInvalidRings(Command):
    def __init__(self):
        super().__init__(
            command_keyword="dont_drop_invalid_ring_tag_cs_hosts",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvis, log_file_name="jarvis_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        return f"Alright {activity['actor']['displayName']}, I won't remove invalid Rings. Until next time!👋🏾"


class RemoveInvalidRings(Command):
    def __init__(self):
        super().__init__(
            command_keyword="drop_invalid_ring_tags",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvis, log_file_name="jarvis_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId
        today_date = datetime.now(EASTERN_TZ).strftime('%m-%d-%Y')
        report_path = DATA_DIR / today_date / "cs_servers_with_invalid_ring_tags_only.xlsx"
        webex_api.messages.create(
            roomId=room_id,
            markdown=f"Hello {activity['actor']['displayName']}! Starting removal of invalid ring tags. This may take a few minutes."
        )
        lock_path = ROOT_DIRECTORY / "src" / "epp" / "drop_invalid_ring_tag_cs_hosts.lock"
        try:
            with fasteners.InterProcessLock(lock_path):
                try:
                    df = pd.read_excel(report_path)
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
        finally:
            if lock_path.exists():
                try:
                    lock_path.unlink()
                except Exception as e:
                    logger.error(f"Failed to remove lock file {lock_path}: {e}")


class GetBotHealth(Command):
    """Command to check bot health and status."""

    def __init__(self):
        super().__init__(
            command_keyword="bot_status",
            help_message="Bot Health 🌡️",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvis, log_file_name="jarvis_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId
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
                    text="🤖 Jarvis Bot Status",
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
            roomId=room_id,
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

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvis, log_file_name="jarvis_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        return "Hi 👋🏾"


def jarvis_bot_factory():
    """Create Jarvis bot instance"""
    # Clean up stale device registrations before creating bot
    cleanup_devices_on_startup(
        CONFIG.webex_bot_access_token_jarvis,
        bot_name="Jarvis"
    )

    # Build approved users list: employees + all bots for peer ping communication
    approved_bot_emails = [
        CONFIG.webex_bot_email_toodles,
        CONFIG.webex_bot_email_msoar,
        CONFIG.webex_bot_email_barnacles,
        CONFIG.webex_bot_email_money_ball,
        CONFIG.webex_bot_email_pokedex,
        CONFIG.webex_bot_email_pinger,  # Pinger bot for keepalive
        CONFIG.webex_bot_email_tars,  # TARS bot for Tanium operations
    ]

    return WebexBot(
        CONFIG.webex_bot_access_token_jarvis,
        approved_domains=[CONFIG.my_web_domain],
        approved_users=approved_bot_emails,  # Allow other bots for peer ping
        # approved_rooms disabled - bot lacks spark:memberships_read scope for validation
        # Security: Only add this bot to authorized rooms to control access
        bot_name="Jarvis - The Ring Tagging Assistant",
        threads=True,
        log_level="ERROR",
        bot_help_subtitle="Your friendly tagging bot!",
        allow_bot_to_bot=True  # Enable peer ping health checks from other bots
    )


def jarvis_initialization(bot):
    """Initialize Jarvis commands"""
    if bot:
        # Add commands to the bot
        bot.add_command(GetCSHostsWithoutRingTag())
        bot.add_command(RingTagCSHosts())
        bot.add_command(DontRingTagCSHosts())
        bot.add_command(GetCSHostsWithInvalidRingTags())
        bot.add_command(RemoveInvalidRings())
        bot.add_command(DontRemoveInvalidRings())
        bot.add_command(GetBotHealth())
        bot.add_command(Hi())
        return True
    return False


def main():
    """Jarvis main - simplified to use basic WebexBot (keepalive handled by peer_ping_keepalive.py)"""
    logger.info("Starting Jarvis with basic WebexBot")

    # Create bot instance
    bot = jarvis_bot_factory()

    # Initialize commands
    jarvis_initialization(bot)

    # Run bot (simple and direct)
    logger.info("🚀 Jarvis is up and running...")
    print("🚀 Jarvis is up and running...", flush=True)
    bot.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
