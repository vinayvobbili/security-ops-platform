# Configure SSL for corporate proxy environments (Zscaler, etc.) - MUST BE FIRST
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from src.utils.ssl_config import configure_ssl_if_needed

configure_ssl_if_needed(verbose=True)  # Re-enabled due to ZScaler connectivity issues

import logging.handlers
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
from src.epp.tanium_hosts_without_ring_tag import create_processor
from src.utils.logging_utils import log_activity

CONFIG = get_config()
ROOT_DIRECTORY = Path(__file__).parent.parent
DATA_DIR = ROOT_DIRECTORY / "data" / "transient" / "epp_device_tagging"

# Ensure logs directory exists
(ROOT_DIRECTORY / "logs").mkdir(exist_ok=True)

# Setup logging with rotation and better formatting
logging.basicConfig(
    level=logging.WARNING,
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
bot_instance = None

# Timezone constant for consistent usage
EASTERN_TZ = ZoneInfo("America/New_York")

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

    try:
        webex_api.messages.create(
            roomId=room_id,
            text="Please approve the tagging action.",
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}]
        )
    except Exception as e:
        logger.error(f"Failed to send approval card: {e}")


def seek_approval_to_ring_tag_tanium(room_id):
    card = AdaptiveCard(
        body=[
            TextBlock(
                text="Tanium Ring Tagging Approval",
                color=options.Colors.ACCENT,
                size=options.FontSize.LARGE,
                weight=options.FontWeight.BOLDER,
                horizontalAlignment=HorizontalAlignment.CENTER),
            ColumnSet(
                columns=[
                    Column(
                        width="stretch",
                        items=[
                            TextBlock(text="Since we are still in Testing phase, do you want 10 random Tanium hosts to be Ring tagged?", wrap=True)
                        ],
                        verticalContentAlignment=VerticalContentAlignment.CENTER
                    )
                ]
            )
        ],
        actions=[
            Submit(title="No!", data={"callback_keyword": "dont_ring_tag_tanium_hosts"},
                   style=options.ActionStyle.DESTRUCTIVE),
            Submit(title="Yes! Put a 💍 On It!", data={"callback_keyword": "ring_tag_tanium_hosts"},
                   style=options.ActionStyle.POSITIVE)
        ]
    )

    try:
        webex_api.messages.create(
            roomId=room_id,
            text="Please approve the Tanium tagging action.",
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}]
        )
    except Exception as e:
        logger.error(f"Failed to send Tanium approval card: {e}")


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


class GetCSHostsWithoutRingTag(Command):
    def __init__(self):
        super().__init__(
            command_keyword="cs_no_ring_tag",
            help_message="Get CS Hosts without a Ring Tag 🛡️💍",
            delete_previous_message=False,  # Keep the command visible for reuse
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais, log_file_name="jarvais_activity_log.csv")
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

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais, log_file_name="jarvais_activity_log.csv")
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

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais, log_file_name="jarvais_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        return f"Alright {activity['actor']['displayName']}, I won't tag no more. Until next time!👋🏾"


class GetCSHostsWithInvalidRingTags(Command):
    def __init__(self):
        super().__init__(
            command_keyword="cs_invalid_ring_tag",
            help_message="Get CS Servers with Invalid Ring Tags 🛡️❌💍",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais, log_file_name="jarvais_activity_log.csv")
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


class GetTaniumHostsWithoutRingTag(Command):
    def __init__(self):
        super().__init__(
            command_keyword="tanium_hosts_without_ring_tag",
            help_message="Get Tanium Hosts without a Ring Tag 🔍💍",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais, log_file_name="jarvais_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId
        loading_msg = get_random_loading_message()
        webex_api.messages.create(
            roomId=room_id,
            markdown=(
                f"Hello {activity['actor']['displayName']}! {loading_msg}\n\n"
                "🔍 **Tanium Hosts Without Ring Tag Report** 🏷️\n"
                "Estimated completion: ~15 minutes ⏰"
            )
        )
        lock_path = ROOT_DIRECTORY / "src" / "epp" / "all_tanium_hosts.lock"
        filepath = None  # Ensure filepath is always defined
        try:
            with fasteners.InterProcessLock(lock_path):
                processor = create_processor()
                report_path = processor.process_hosts_without_ring_tags(test_limit=None)
                filepath = report_path  # Use the returned report path
        except Exception as e:
            logger.error(f"Error in GetTaniumHostsWithoutRingTag execute: {e}")
            webex_api.messages.create(
                roomId=room_id,
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
            webex_api.messages.create(
                roomId=room_id,
                markdown=f"Hello {activity['actor']['displayName']}! ❌ **Error generating Tanium hosts report**: {error_msg}"
            )
            return

        message = f"Hello {activity['actor']['displayName']}! Here's the list of Tanium hosts without a Ring Tag. Ring tags have also been generated for your review. Count = {len(pd.read_excel(filepath))}"

        webex_api.messages.create(
            roomId=room_id,
            markdown=message,
            files=[str(filepath)]
        )
        seek_approval_to_ring_tag_tanium(room_id)


class RingTagTaniumHosts(Command):
    def __init__(self):
        super().__init__(
            command_keyword="ring_tag_tanium_hosts",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais, log_file_name="jarvais_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId
        loading_msg = get_random_loading_message()
        webex_api.messages.create(
            roomId=room_id,
            markdown=f"Hello {activity['actor']['displayName']}! {loading_msg}\n\n🏷️**Starting ring tagging for 10 random Tanium hosts...**\nEstimated completion: ~5 minutes ⏰"
        )

        lock_path = ROOT_DIRECTORY / "src" / "epp" / "ring_tag_tanium_hosts.lock"
        try:
            with fasteners.InterProcessLock(lock_path):
                self._apply_tags_to_random_hosts(room_id)
        except Exception as e:
            logger.error(f"Error in RingTagTaniumHosts execute: {e}")
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

    @staticmethod
    def _apply_tags_to_random_hosts(room_id):
        """Apply ring tags to 10 random Tanium hosts"""
        from services.tanium import TaniumClient

        today_date = datetime.now(EASTERN_TZ).strftime('%m-%d-%Y')
        report_dir = ROOT_DIRECTORY / "web" / "static" / "charts" / today_date
        report_path = report_dir / "Tanium_Ring_Tags_Report.xlsx"

        if not report_path.exists():
            webex_api.messages.create(
                roomId=room_id,
                markdown=f"❌ **Error**: Ring tags report not found. Please run the 'tanium_hosts_without_ring_tag' command first to generate the report."
            )
            return

        try:
            # Read the report
            df = pd.read_excel(report_path)

            # Filter hosts that have generated tags and no errors
            hosts_to_tag = df[
                (df['Generated Tag'].notna()) &
                (df['Generated Tag'] != '') &
                (~df['Comments'].str.contains('missing|couldn\'t be generated|error', case=False, na=False))
            ]

            if len(hosts_to_tag) == 0:
                webex_api.messages.create(
                    roomId=room_id,
                    markdown=f"❌ **No hosts available for tagging**. All hosts in the report have issues that prevent tagging."
                )
                return

            # Select 10 random hosts (or fewer if less than 10 available)
            num_to_tag = min(10, len(hosts_to_tag))
            random_hosts = hosts_to_tag.sample(n=num_to_tag, random_state=random.randint(0, 10000))

            # Initialize Tanium client
            tanium_client = TaniumClient()

            # Track results
            successful_tags = []
            failed_tags = []

            # Apply tags to each host
            for idx, row in random_hosts.iterrows():
                computer_name = str(row['Computer Name'])
                source = str(row['Source'])
                ring_tag = str(row['Generated Tag'])
                current_tags = str(row.get('Current Tags', ''))
                comments = str(row.get('Comments', ''))

                try:
                    # Get the appropriate instance
                    instance = tanium_client.get_instance_by_name(source)
                    if not instance:
                        failed_tags.append({
                            'name': computer_name,
                            'tag': ring_tag,
                            'source': source,
                            'current_tags': current_tags,
                            'comments': comments,
                            'error': f"Instance '{source}' not found"
                        })
                        continue

                    # Add the tag
                    logger.info(f"Tagging {computer_name} with {ring_tag} in {source}")
                    result = instance.add_tag_by_name(computer_name, ring_tag)

                    # Extract action ID from result
                    action_id = result.get('action', {}).get('scheduledAction', {}).get('id', 'N/A')

                    successful_tags.append({
                        'name': computer_name,
                        'tag': ring_tag,
                        'source': source,
                        'current_tags': current_tags,
                        'comments': comments,
                        'action_id': action_id
                    })

                except Exception as e:
                    logger.error(f"Failed to tag {computer_name}: {e}")
                    failed_tags.append({
                        'name': computer_name,
                        'tag': ring_tag,
                        'source': source,
                        'current_tags': current_tags,
                        'comments': comments,
                        'error': str(e)
                    })

            # Send summary report
            summary_md = f"## 🎉 Tanium Ring Tagging Complete!\n\n"
            summary_md += f"**Successfully tagged:** {len(successful_tags)}/{num_to_tag} hosts\n\n"

            if successful_tags:
                summary_md += "### ✅ Successfully Tagged Hosts:\n"
                for host in successful_tags:
                    summary_md += f"\n**{host['name']}**\n"
                    summary_md += f"  - Instance: `{host['source']}`\n"
                    summary_md += f"  - New Tag: `{host['tag']}`\n"
                    summary_md += f"  - Action ID: `{host['action_id']}`\n"
                    if host['current_tags'] and str(host['current_tags']).strip():
                        summary_md += f"  - Current Tags: `{host['current_tags']}`\n"
                    if host['comments'] and str(host['comments']).strip():
                        summary_md += f"  - Notes: {host['comments']}\n"
                summary_md += "\n"

            if failed_tags:
                summary_md += "### ❌ Failed to Tag:\n"
                for host in failed_tags:
                    summary_md += f"\n**{host['name']}**\n"
                    summary_md += f"  - Instance: `{host['source']}`\n"
                    summary_md += f"  - Attempted Tag: `{host['tag']}`\n"
                    summary_md += f"  - Error: {host['error']}\n"
                    if host['current_tags'] and str(host['current_tags']).strip():
                        summary_md += f"  - Current Tags: `{host['current_tags']}`\n"
                    if host['comments'] and str(host['comments']).strip():
                        summary_md += f"  - Notes: {host['comments']}\n"

            webex_api.messages.create(
                roomId=room_id,
                markdown=summary_md
            )

        except Exception as e:
            logger.error(f"Error applying Tanium ring tags: {e}")
            webex_api.messages.create(
                roomId=room_id,
                markdown=f"❌ Failed to apply ring tags: {str(e)}"
            )


class DontRingTagTaniumHosts(Command):
    def __init__(self):
        super().__init__(
            command_keyword="dont_ring_tag_tanium_hosts",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais, log_file_name="jarvais_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        return f"Alright {activity['actor']['displayName']}, I won't tag Tanium hosts. Until next time!👋🏾"


class GetTaniumUnhealthyHosts(Command):
    def __init__(self):
        super().__init__(
            command_keyword="tanium_unhealthy_hosts",
            help_message="Get Tanium Unhealthy Hosts 🔍🤒",
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


class GetBotHealth(Command):
    """Command to check bot health and status."""

    def __init__(self):
        super().__init__(
            command_keyword="bot_status",
            help_message="Bot Health 🌡️",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais, log_file_name="jarvais_activity_log.csv")
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

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais, log_file_name="jarvais_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        return "Hi 👋"


def jarvais_bot_factory():
    """Create Jarvais bot instance"""
    return WebexBot(
        CONFIG.webex_bot_access_token_jarvais,
        approved_rooms=[CONFIG.webex_room_id_epp_tagging, CONFIG.webex_room_id_vinay_test_space],
        bot_name="Jarvais - The Ring Tagging Assistant",
        threads=True,
        log_level="ERROR",
        bot_help_subtitle="Your friendly tagging bot!"
    )


def jarvais_initialization(bot_instance=None):
    """Initialize Jarvais commands"""
    if bot_instance:
        # Add commands to the bot
        bot_instance.add_command(GetCSHostsWithoutRingTag())
        bot_instance.add_command(RingTagCSHosts())
        bot_instance.add_command(DontRingTagCSHosts())
        bot_instance.add_command(GetCSHostsWithInvalidRingTags())
        bot_instance.add_command(RemoveInvalidRings())
        bot_instance.add_command(DontRemoveInvalidRings())
        bot_instance.add_command(GetTaniumHostsWithoutRingTag())
        bot_instance.add_command(RingTagTaniumHosts())
        bot_instance.add_command(DontRingTagTaniumHosts())
        bot_instance.add_command(GetTaniumUnhealthyHosts())
        bot_instance.add_command(GetBotHealth())
        bot_instance.add_command(Hi())
        return True
    return False


def main():
    """Jarvais main with resilience framework"""
    from src.utils.bot_resilience import ResilientBot

    resilient_runner = ResilientBot(
        bot_name="Jarvais",
        bot_factory=jarvais_bot_factory,
        initialization_func=jarvais_initialization,
        max_retries=5,
        initial_retry_delay=30,
        max_retry_delay=300
    )
    resilient_runner.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
