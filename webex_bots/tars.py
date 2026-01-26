#!/usr/bin/python3
"""
TARS - Tanium Cloud tagging bot.

Handles Tanium Cloud instance operations for ring tagging.
For On-Prem operations, see CASE bot.
"""

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
    bot_name='tars',
    log_level=logging.INFO,
    log_dir=str(ROOT_DIRECTORY / "logs"),
    info_modules=['__main__', 'src.utils.bot_resilience', 'src.utils.webex_device_manager'],
    rotate_on_startup=False
)

logger = logging.getLogger(__name__)
logging.getLogger('webex_bot').setLevel(logging.ERROR)
logging.getLogger('webexteamssdk').setLevel(logging.ERROR)
logging.getLogger('webex_websocket_client').setLevel(logging.WARNING)

from src.utils.ssl_config import configure_ssl_if_needed

configure_ssl_if_needed(verbose=True)

from src.utils.enhanced_websocket_client import patch_websocket_client

patch_websocket_client()

from datetime import datetime, timezone, timedelta
import signal
import atexit

logger.warning("=" * 100)
logger.warning(f"🚀 TARS BOT STARTED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
logger.warning("=" * 100)

import fasteners
import pandas as pd
from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot
from webexteamssdk import WebexTeamsAPI

from my_config import get_config
from src.epp.tanium_hosts_without_ring_tag import create_processor
from src.utils.logging_utils import log_activity
from src.utils.webex_device_manager import cleanup_devices_on_startup
from src.utils.webex_utils import send_message_with_retry, send_card_with_retry
from src.utils.webex_pool_config import configure_webex_api_session

# Import shared Tanium bot functionality
from webex_bots.tanium_bot_base import (
    TaniumBotConfig,
    get_random_loading_message,
    seek_approval_to_ring_tag_tanium,
    apply_tags_to_hosts,
    create_bot_health_card,
    EASTERN_TZ,
    run_automated_ring_tagging_workflow as _run_automated_ring_tagging_workflow,
)

# Default batch size for TARS (Cloud) ring tagging
DEFAULT_BATCH_SIZE = 1000

# Data directory for transient files (flag files, etc.)
DATA_DIR = ROOT_DIRECTORY / "data" / "transient" / "epp_device_tagging"

CONFIG = get_config()

# Safety window for automated ring tagging (minutes) - loaded from config
SAFETY_WINDOW_MINUTES = CONFIG.ring_tagging_safety_window_minutes

# Configure WebexTeamsAPI with larger connection pool
webex_api = configure_webex_api_session(
    WebexTeamsAPI(
        access_token=CONFIG.webex_bot_access_token_tars,
        single_request_timeout=120
    ),
    pool_connections=50,
    pool_maxsize=50,
    max_retries=3
)

# Bot configuration for TARS (Cloud instance)
BOT_CONFIG = TaniumBotConfig(
    bot_name="TARS",
    instance_type="cloud",
    webex_api=webex_api,
    root_directory=ROOT_DIRECTORY,
    activity_log_file="tars_activity_log.csv"
)


def run_automated_ring_tagging_workflow():
    """Wrapper for automated Tanium Cloud ring tagging workflow.

    Calls the shared workflow from tanium_bot_base with Cloud-specific parameters.
    """
    _run_automated_ring_tagging_workflow(
        config=BOT_CONFIG,
        room_id=CONFIG.webex_room_id_epp_tanium_cloud_tagging,
        safety_window_minutes=SAFETY_WINDOW_MINUTES,
        default_batch_size=DEFAULT_BATCH_SIZE
    )


class GetTaniumHostsWithoutRingTag(Command):
    def __init__(self):
        super().__init__(
            command_keyword="tanium_hosts_without_ring_tag",
            help_message="Get Tanium Cloud Hosts without a Ring Tag 🔍💍",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_tars, log_file_name="tars_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId
        loading_msg = get_random_loading_message()
        send_message_with_retry(webex_api,
                                room_id=room_id,
                                markdown=(
                                    f"Hello {activity['actor']['displayName']}! {loading_msg}\n\n"
                                    "🔍 **Tanium Cloud Hosts Without Ring Tag Report** 🏷️\n"
                                    "Estimated completion: ~15 minutes ⏰"
                                )
                                )
        lock_path = ROOT_DIRECTORY / "src" / "epp" / "all_tanium_hosts.lock"
        filepath = None
        try:
            with fasteners.InterProcessLock(lock_path):
                processor = create_processor(instance_filter="cloud")
                report_path = processor.process_hosts_without_ring_tags(test_limit=None)
                filepath = report_path
        except Exception as e:
            logger.error(f"Error in GetTaniumHostsWithoutRingTag execute: {e}")
            send_message_with_retry(webex_api,
                                    room_id=room_id,
                                    markdown=f"❌ An error occurred while processing your request: {e}"
                                    )
            filepath = None
        finally:
            if lock_path.exists():
                try:
                    lock_path.unlink()
                except Exception as e:
                    logger.error(f"Failed to remove lock file {lock_path}: {e}")

        if not filepath or not Path(filepath).exists():
            error_msg = filepath if filepath else "Unknown error occurred during report generation"
            send_message_with_retry(webex_api,
                                    room_id=room_id,
                                    markdown=f"Hello {activity['actor']['displayName']}! ❌ **Error generating Tanium Cloud hosts report**: {error_msg}"
                                    )
            return

        # Count total hosts in report and hosts with successfully generated tags
        df = pd.read_excel(filepath)
        total_hosts_in_report = len(df)
        hosts_with_generated_tags = df[
            (df['Generated Tag'].notna()) &
            (df['Generated Tag'] != '') &
            (~df['Comments'].str.contains('missing|couldn\'t be generated|error', case=False, na=False))
            ]
        hosts_with_generated_tags_count = len(hosts_with_generated_tags)

        # Count Cloud hosts
        cloud_count = len(hosts_with_generated_tags[hosts_with_generated_tags['Source'].str.contains('Cloud', case=False, na=False)])

        # Check which instances were actually used in the report
        from services.tanium import TaniumClient
        client = TaniumClient()
        available_instances = [i for i in client.list_available_instances() if 'cloud' in i.lower()]
        instances_msg = f"📡 **Active Cloud instance:** {', '.join(available_instances) if available_instances else 'None available'}"
        if not available_instances:
            instances_msg += "\n⚠️ **Warning:** Cloud instance is not accessible from this server"

        # Calculate hosts with issues
        hosts_with_issues = total_hosts_in_report - hosts_with_generated_tags_count

        # Calculate number of hosts seen within last 2 hours
        report_file_time = datetime.fromtimestamp(Path(filepath).stat().st_mtime, tz=timezone.utc)
        two_hours_before_report = report_file_time - timedelta(hours=2)

        def is_recently_online(last_seen_str):
            if pd.isna(last_seen_str) or not last_seen_str:
                return False
            try:
                last_seen = datetime.fromisoformat(str(last_seen_str).replace('Z', '+00:00'))
                return last_seen >= two_hours_before_report
            except (ValueError, AttributeError):
                return False

        recently_online_count = 0
        if 'Last Seen' in hosts_with_generated_tags.columns:
            recently_online_count = len(hosts_with_generated_tags[hosts_with_generated_tags['Last Seen'].apply(is_recently_online)])

        message = f"Hello {activity['actor']['displayName']}! Here's the list of Tanium Cloud hosts without a Ring Tag. Ring tags have also been generated for your review.\n\n"
        message += f"{instances_msg}\n\n"
        message += f"**Summary:**\n"
        message += f"- Total hosts without ring tags: {total_hosts_in_report:,}\n"
        message += f"- Hosts with ring tags generated: {hosts_with_generated_tags_count:,}\n"
        message += f"  - Cloud: {cloud_count:,}\n"
        message += f"- Hosts seen within last 2 hours: {recently_online_count:,}\n"
        message += f"- Hosts with errors/missing data: {hosts_with_issues:,}"

        result = send_message_with_retry(webex_api, room_id=room_id, markdown=message, files=[str(filepath)])

        if result:
            seek_approval_to_ring_tag_tanium(BOT_CONFIG, room_id, total_hosts=hosts_with_generated_tags_count, default_batch_size=DEFAULT_BATCH_SIZE)


class RingTagTaniumHosts(Command):
    def __init__(self):
        super().__init__(
            command_keyword="ring_tag_tanium_hosts",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_tars, log_file_name="tars_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId
        batch_size = DEFAULT_BATCH_SIZE

        loading_msg = get_random_loading_message()
        if batch_size is None:
            batch_info = " (tagging ALL hosts)"
        else:
            batch_info = f" (batch of {batch_size:,} hosts)"
        send_message_with_retry(webex_api,
                                room_id=room_id,
                                markdown=f"Hello {activity['actor']['displayName']}! {loading_msg}\n\n🏷️**Starting ring tagging for Tanium Cloud hosts{batch_info}...**\nEstimated completion: ~5 minutes ⏰"
                                )

        lock_path = ROOT_DIRECTORY / "src" / "epp" / "ring_tag_tanium_hosts.lock"
        user_name = activity['actor']['displayName']
        try:
            with fasteners.InterProcessLock(lock_path):
                apply_tags_to_hosts(BOT_CONFIG, room_id, batch_size=batch_size, run_by=user_name)
        except Exception as e:
            logger.error(f"Error in RingTagTaniumHosts execute: {e}")
            send_message_with_retry(webex_api,
                                    room_id=room_id,
                                    markdown=f"❌ An error occurred while processing your request: {e}"
                                    )
        finally:
            if lock_path.exists():
                try:
                    lock_path.unlink()
                except Exception as e:
                    logger.error(f"Failed to remove lock file {lock_path}: {e}")


class DontRingTagTaniumHosts(Command):
    def __init__(self):
        super().__init__(
            command_keyword="dont_ring_tag_tanium_hosts",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_tars, log_file_name="tars_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        return f"Alright {activity['actor']['displayName']}, I won't tag Tanium Cloud hosts. Until next time!👋🏾"


class StopAutomatedTaniumRingTagging(Command):
    """Command to stop automated Tanium Cloud ring tagging during safety window."""

    def __init__(self):
        super().__init__(
            command_keyword="stop_automated_tanium_ring_tagging",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_tars, log_file_name="tars_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId

        # Create flag file to signal cancellation
        flag_file = DATA_DIR / "stop_automated_tanium_tagging.flag"
        flag_file.parent.mkdir(parents=True, exist_ok=True)
        flag_file.write_text(f"Stopped by {activity['actor']['displayName']} at {datetime.now(EASTERN_TZ).isoformat()}")

        logger.info(f"Automated Tanium tagging stopped by {activity['actor']['displayName']}")

        send_message_with_retry(
            webex_api, room_id,
            markdown=f"🛑 **Automated Tanium Cloud ring tagging has been STOPPED** by {activity['actor']['displayName']}.\n\nNo hosts will be tagged in this run."
        )


class GetTaniumUnhealthyHosts(Command):
    def __init__(self):
        super().__init__(
            command_keyword="tanium_unhealthy_hosts",
            help_message="Get Tanium Cloud Unhealthy Hosts 🔍🤒",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_tars, log_file_name="tars_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        from src.epp.tanium_unhealthy_hosts import create_processor as create_unhealthy_processor

        room_id = attachment_actions.roomId
        loading_msg = get_random_loading_message()
        send_message_with_retry(webex_api,
                                room_id=room_id,
                                markdown=(
                                    f"Hello {activity['actor']['displayName']}! {loading_msg}\n\n"
                                    "🔍 **Tanium Cloud Unhealthy Hosts Report** 🤒\n"
                                    "Checking unhealthy hosts (servers: >1 day, workstations: >3 days), enriching with ServiceNow & CrowdStrike...\n"
                                    "Estimated completion: ~10-15 minutes ⏰"
                                )
                                )

        lock_path = ROOT_DIRECTORY / "src" / "epp" / "tanium_unhealthy_hosts.lock"
        filepath = None
        try:
            with fasteners.InterProcessLock(lock_path):
                processor = create_unhealthy_processor(instance_filter="cloud")
                filepath = processor.process(test_limit=None)
        except Exception as e:
            logger.error(f"Error in GetTaniumUnhealthyHosts execute: {e}")
            send_message_with_retry(webex_api,
                                    room_id=room_id,
                                    markdown=f"❌ An error occurred while processing your request: {e}"
                                    )
            filepath = None
        finally:
            if lock_path.exists():
                try:
                    lock_path.unlink()
                except Exception as e:
                    logger.error(f"Failed to remove lock file {lock_path}: {e}")

        if not filepath or not Path(filepath).exists():
            error_msg = filepath if filepath else "Unknown error occurred during report generation"
            send_message_with_retry(webex_api,
                                    room_id=room_id,
                                    markdown=f"Hello {activity['actor']['displayName']}! ❌ **Error generating unhealthy hosts report**: {error_msg}"
                                    )
            return

        # Read report and generate summary
        df = pd.read_excel(filepath)
        total_unhealthy = len(df)

        if total_unhealthy == 0:
            send_message_with_retry(webex_api,
                                    room_id=room_id,
                                    markdown=f"Hello {activity['actor']['displayName']}! 🎉 **Great news!** No unhealthy Tanium Cloud hosts found (servers seen within 1 day, workstations within 3 days)."
                                    )
            return

        # Count statistics
        snow_found = len(df[df['SNOW Status'] == 'Found'])
        operational_or_pipeline = len(df[df['SNOW Lifecycle'].str.lower().isin(['operational', 'pipeline'])])
        cs_online = len(df[df['CS Online State'] == 'online'])
        rtr_candidates = len(df[df['RTR Candidate'] == 'Yes'])

        message = f"Hello {activity['actor']['displayName']}! Here's the **Tanium Cloud Unhealthy Hosts Report** 🤒\n\n"
        message += f"**Summary:**\n"
        message += f"- Total unhealthy hosts (servers: >1 day, workstations: >3 days): **{total_unhealthy:,}**\n"
        message += f"- Found in ServiceNow CMDB: {snow_found:,}\n"
        message += f"- Lifecycle = Operational/Pipeline: {operational_or_pipeline:,}\n"
        message += f"- Online in CrowdStrike: {cs_online:,}\n"
        message += f"- **RTR Remediation Candidates: {rtr_candidates:,}** ✅\n\n"
        message += "_RTR candidates are hosts that are operational/pipeline in SNOW and online in CrowdStrike - ready for automated Tanium agent reinstallation._"

        send_message_with_retry(webex_api, room_id=room_id, markdown=message, files=[str(filepath)])


class GetBotHealth(Command):
    """Command to check bot health and status."""

    def __init__(self):
        super().__init__(
            command_keyword="bot_status",
            help_message="Bot Health 🌡️",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_tars, log_file_name="tars_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId
        current_time = datetime.now(EASTERN_TZ)

        status_card = create_bot_health_card("TARS", current_time)

        send_card_with_retry(webex_api,
                             room_id=room_id,
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

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_tars, log_file_name="tars_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        return "Hi 👋🏾"


def tars_bot_factory():
    """Create TARS bot instance"""
    cleanup_devices_on_startup(
        CONFIG.webex_bot_access_token_tars,
        bot_name="TARS"
    )

    approved_bot_emails = [
        CONFIG.webex_bot_email_toodles,
        CONFIG.webex_bot_email_msoar,
        CONFIG.webex_bot_email_barnacles,
        CONFIG.webex_bot_email_money_ball,
        CONFIG.webex_bot_email_pokedex,
        CONFIG.webex_bot_email_pinger,
        CONFIG.webex_bot_email_jarvis,
        CONFIG.webex_bot_email_case,  # CASE bot (On-Prem counterpart)
    ]

    return WebexBot(
        CONFIG.webex_bot_access_token_tars,
        approved_domains=[CONFIG.my_web_domain],
        approved_users=approved_bot_emails,
        bot_name="TARS - The Tanium Cloud Assistant",
        threads=True,
        log_level="ERROR",
        bot_help_subtitle="Your friendly Tanium Cloud tagging bot!",
        allow_bot_to_bot=True
    )


def tars_initialization(bot):
    """Initialize TARS commands"""
    if bot:
        bot.add_command(GetTaniumHostsWithoutRingTag())
        bot.add_command(RingTagTaniumHosts())  # Hidden - triggered via adaptive card
        bot.add_command(DontRingTagTaniumHosts())  # Hidden - triggered via adaptive card
        bot.add_command(StopAutomatedTaniumRingTagging())  # Hidden - triggered via adaptive card
        bot.add_command(GetTaniumUnhealthyHosts())
        return True
    return False


def _shutdown_handler(_signum=None, _frame=None):
    """Log shutdown marker before exit"""
    logger.warning("=" * 100)
    logger.warning(f"🛑 TARS BOT STOPPED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.warning("=" * 100)


def main():
    """TARS main - Tanium Cloud tagging bot"""
    logger.info("Starting TARS with basic WebexBot")

    atexit.register(_shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    bot = tars_bot_factory()
    tars_initialization(bot)

    logger.info("🚀 TARS is up and running...")
    print("🚀 TARS is up and running...", flush=True)
    bot.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
