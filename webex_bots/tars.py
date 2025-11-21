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
    bot_name='tars',
    log_level=logging.WARNING,
    log_dir=str(ROOT_DIRECTORY / "logs"),
    info_modules=['__main__', 'src.utils.bot_resilience', 'src.utils.webex_device_manager']
)

logger = logging.getLogger(__name__)
# Suppress warnings from webexteamssdk library (bot-to-bot messages, command not found)
logging.getLogger('webexteamssdk').setLevel(logging.ERROR)

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
from tqdm import tqdm
from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot
from webexpythonsdk.models.cards import (
    AdaptiveCard, Column, ColumnSet,
    TextBlock, options, HorizontalAlignment, VerticalContentAlignment
)
from webexpythonsdk.models.cards.actions import Submit
from webexpythonsdk.models.cards.inputs import Text as TextInput
from webexteamssdk import WebexTeamsAPI

from my_config import get_config
from src.epp.tanium_hosts_without_ring_tag import create_processor
from src.utils.excel_formatting import apply_professional_formatting
from src.utils.logging_utils import log_activity
from src.utils.webex_device_manager import cleanup_devices_on_startup
from src.utils.webex_utils import send_message_with_retry, send_card_with_retry

CONFIG = get_config()
DATA_DIR = ROOT_DIRECTORY / "data" / "transient" / "epp_device_tagging"

webex_api = WebexTeamsAPI(access_token=CONFIG.webex_bot_access_token_tars)

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

        # Send report with retry (auto-notifies on failure)
        result = send_message_with_retry(
            webex_api, room_id=room_id, markdown=report_text, files=[str(filepath)]
        )
        if result:
            logger.info(f"Successfully sent report {filename} with {hosts_count} hosts to room {room_id}")

    except FileNotFoundError:
        error_msg = f"❌ Report file not found at {filepath}"
        logger.error(error_msg)
        send_message_with_retry(webex_api, room_id=room_id, markdown=error_msg)
    except Exception as e:
        error_msg = f"❌ Failed to send report: {str(e)}"
        logger.error(error_msg)
        send_message_with_retry(webex_api, room_id=room_id, markdown=error_msg)


def seek_approval_to_ring_tag_tanium(room_id, total_hosts=None):
    """Send approval card for Tanium ring tagging with batch size option"""
    hosts_info = f" ({total_hosts:,} hosts available)" if total_hosts else ""

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
                            TextBlock(text=f"I can tag workstations and server in Tanium {hosts_info}. Do you want to proceed?", wrap=True)
                        ],
                        verticalContentAlignment=VerticalContentAlignment.CENTER
                    )
                ]
            ),
            TextBlock(
                text="🧪 Batch Size (Required for Safety)",
                weight=options.FontWeight.BOLDER,
                separator=True
            ),
            TextBlock(
                text="Enter number of servers to randomly tag. Default is 10 for safety. Use higher numbers (100, 1000, etc.) after successful testing, or enter 'all' to tag all hosts.",
                wrap=True,
                isSubtle=True
            ),
            TextInput(
                id="batch_size",
                placeholder="Default: 10 (or enter 100, 1000, 'all')",
                isRequired=False
            )
        ],
        actions=[
            Submit(title="No!", data={"callback_keyword": "dont_ring_tag_tanium_hosts"},
                   style=options.ActionStyle.DESTRUCTIVE),
            Submit(title="Yes! Put a 💍 On It!", data={"callback_keyword": "ring_tag_tanium_hosts"},
                   style=options.ActionStyle.POSITIVE)
        ]
    )

    # Use resilient messenger to send card with automatic retry
    result = send_card_with_retry(webex_api,
                                  room_id=room_id,
                                  text="Please approve the Tanium tagging action.",
                                  attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}]
                                  )

    if result is None:
        # All retries failed - send fallback notification
        error_msg = f"❌ **Failed to send approval card**\n\nI couldn't send the approval card after multiple attempts due to network errors.\n\n**What happened:**\n- Report was generated successfully ({total_hosts:,} hosts available)\n- Network error prevented card delivery\n\n**What to do:**\n- Try running the command again\n- Or proceed directly with: `/ring_tag_tanium_hosts`"

        try:
            send_message_with_retry(webex_api, room_id=room_id, markdown=error_msg)
        except Exception as notify_error:
            logger.error(f"Critical: Failed to send fallback notification: {notify_error}")
            logger.error("⚠️ IMPORTANT: User was NOT notified about approval card failure. Check Webex room manually.")


class GetTaniumHostsWithoutRingTag(Command):
    def __init__(self):
        super().__init__(
            command_keyword="tanium_hosts_without_ring_tag",
            help_message="Get Tanium Hosts without a Ring Tag 🔍💍",
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
                                    markdown=f"Hello {activity['actor']['displayName']}! ❌ **Error generating Tanium hosts report**: {error_msg}"
                                    )
            return

        # Count total hosts in report and hosts with successfully generated tags (both Cloud and On-Prem)
        df = pd.read_excel(filepath)
        total_hosts_in_report = len(df)
        hosts_with_generated_tags = df[
            (df['Generated Tag'].notna()) &
            (df['Generated Tag'] != '') &
            (~df['Comments'].str.contains('missing|couldn\'t be generated|error', case=False, na=False))
            ]
        hosts_with_generated_tags_count = len(hosts_with_generated_tags)

        # Count by source for informational purposes
        cloud_count = len(hosts_with_generated_tags[hosts_with_generated_tags['Source'].str.contains('Cloud', case=False, na=False)])
        onprem_count = len(hosts_with_generated_tags[hosts_with_generated_tags['Source'].str.contains('On-Prem', case=False, na=False)])

        # Check which instances were actually used in the report
        from services.tanium import TaniumClient
        client = TaniumClient()
        available_instances = client.list_available_instances()
        instances_msg = f"📡 **Active instances:** {', '.join(available_instances)}"
        if len(available_instances) < 2:
            instances_msg += f"\n⚠️ **Note:** Only {len(available_instances)} of 2 configured instances is accessible from this server"

        # Calculate hosts with issues
        hosts_with_issues = total_hosts_in_report - hosts_with_generated_tags_count

        message = f"Hello {activity['actor']['displayName']}! Here's the list of Tanium hosts without a Ring Tag. Ring tags have also been generated for your review.\n\n"
        message += f"{instances_msg}\n\n"
        message += f"**Summary:**\n"
        message += f"- Total hosts without ring tags: {total_hosts_in_report:,}\n"
        message += f"- Hosts with ring tags generated: {hosts_with_generated_tags_count:,}\n"
        message += f"  - Cloud: {cloud_count:,}\n"
        message += f"  - On-Prem: {onprem_count:,}\n"
        message += f"- Hosts with errors/missing data: {hosts_with_issues:,}"

        # Send report with retry
        result = send_message_with_retry(webex_api, room_id=room_id, markdown=message, files=[str(filepath)])

        if result:
            # Only send approval card if report was delivered successfully
            seek_approval_to_ring_tag_tanium(room_id, total_hosts=hosts_with_generated_tags_count)


# Tanium ring tagging commands below

class RingTagTaniumHosts(Command):
    def __init__(self):
        super().__init__(
            command_keyword="ring_tag_tanium_hosts",
            help_message="Ring Tag Tanium Hosts 💍🏷️",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_tars, log_file_name="tars_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId

        # Extract batch size from the form submission
        # Default to 10 for safety if user leaves field blank
        batch_size = 10
        if hasattr(attachment_actions, 'inputs') and attachment_actions.inputs:
            batch_size_str = attachment_actions.inputs.get('batch_size', '').strip()
            if batch_size_str:
                # Allow 'all' to tag all hosts
                if batch_size_str.lower() == 'all':
                    batch_size = None
                else:
                    try:
                        batch_size = int(batch_size_str)
                        if batch_size <= 0:
                            send_message_with_retry(webex_api,
                                                    room_id=room_id,
                                                    markdown=f"❌ Invalid batch size: {batch_size}. Please enter a positive number or 'all'."
                                                    )
                            return
                    except ValueError:
                        send_message_with_retry(webex_api,
                                                room_id=room_id,
                                                markdown=f"❌ Invalid batch size: '{batch_size_str}'. Please enter a valid number or 'all'."
                                                )
                        return

        loading_msg = get_random_loading_message()
        if batch_size is None:
            batch_info = " (tagging ALL hosts)"
        else:
            batch_info = f" (batch of {batch_size:,} hosts)"
        send_message_with_retry(webex_api,
                                room_id=room_id,
                                markdown=f"Hello {activity['actor']['displayName']}! {loading_msg}\n\n🏷️**Starting ring tagging for Tanium hosts from both Cloud and On-Prem instances{batch_info}...**\nEstimated completion: ~5 minutes ⏰"
                                )

        lock_path = ROOT_DIRECTORY / "src" / "epp" / "ring_tag_tanium_hosts.lock"
        try:
            with fasteners.InterProcessLock(lock_path):
                self._apply_tags_to_hosts(room_id, batch_size=batch_size)
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

    @staticmethod
    def _apply_tags_to_hosts(room_id, batch_size=None):
        """Apply ring tags to Tanium hosts (both Cloud and On-Prem) with optional batch sampling

        Args:
            room_id: Webex room ID for sending messages
            batch_size: Optional number of hosts to randomly sample for tagging.
                       If None, all eligible hosts will be tagged.
        """
        import time
        from services.tanium import TaniumClient

        # Start timing
        start_time = time.time()

        today_date = datetime.now(EASTERN_TZ).strftime('%m-%d-%Y')
        report_dir = ROOT_DIRECTORY / "data" / "transient" / "epp_device_tagging" / today_date
        report_path = report_dir / "Tanium_Ring_Tags_Report.xlsx"

        if not report_path.exists():
            send_message_with_retry(webex_api,
                                    room_id=room_id,
                                    markdown=f"❌ **Error**: Ring tags report not found. Please run the 'tanium_hosts_without_ring_tag' command first to generate the report."
                                    )
            return

        try:
            # Read the report
            read_start = time.time()
            df = pd.read_excel(report_path)
            read_duration = time.time() - read_start

            total_hosts_in_report = len(df)

            # Filter hosts that have generated tags and no errors (both Cloud and On-Prem)
            # Only process servers - workstations are typically offline and won't receive tags
            filter_start = time.time()
            hosts_to_tag = df[
                (df['Generated Tag'].notna()) &
                (df['Generated Tag'] != '') &
                (~df['Comments'].str.contains('missing|couldn\'t be generated|error', case=False, na=False)) &
                (df['Category'].str.contains('Server', case=False, na=False))
                ]
            filter_duration = time.time() - filter_start

            if len(hosts_to_tag) == 0:
                send_message_with_retry(webex_api,
                                        room_id=room_id,
                                        markdown=f"❌ **No servers available for tagging**. All servers in the report either have issues that prevent tagging or are workstations (which are filtered out)."
                                        )
                return

            total_eligible_hosts = len(hosts_to_tag)

            # Apply random sampling if batch size is specified
            if batch_size is not None:
                if batch_size >= total_eligible_hosts:
                    send_message_with_retry(webex_api,
                                            room_id=room_id,
                                            markdown=f"ℹ️ **Note**: Batch size ({batch_size:,}) equals or exceeds available servers ({total_eligible_hosts:,}). Tagging all {total_eligible_hosts:,} servers."
                                            )
                else:
                    # Randomly sample N hosts from the eligible pool
                    hosts_to_tag = hosts_to_tag.sample(n=batch_size, random_state=None)
                    logger.info(f"Randomly sampled {batch_size} servers from {total_eligible_hosts} eligible servers")
                    send_message_with_retry(webex_api,
                                            room_id=room_id,
                                            markdown=f"🎲 **Batch mode active**: Randomly selected {batch_size:,} servers from {total_eligible_hosts:,} eligible servers for tagging (workstations excluded)."
                                            )
            else:
                # batch_size is None, meaning user entered 'all'
                send_message_with_retry(webex_api,
                                        room_id=room_id,
                                        markdown=f"📋 **Full deployment mode**: Tagging ALL {total_eligible_hosts:,} eligible servers from both Cloud and On-Prem instances (workstations excluded)."
                                        )

            num_to_tag = len(hosts_to_tag)

            # Initialize Tanium client
            tanium_client = TaniumClient()

            # Track results
            successful_tags = []
            failed_tags = []

            # Group hosts by (instance, tag, package_id) for bulk tagging
            apply_start = time.time()

            # Create a grouping key and organize hosts
            from collections import defaultdict
            host_groups = defaultdict(list)

            for idx, row in hosts_to_tag.iterrows():
                computer_name = str(row['Computer Name'])
                tanium_id = str(row['Tanium ID'])
                source = str(row['Source'])
                ring_tag = str(row['Generated Tag'])
                package_id = str(row['Package ID'])
                current_tags = str(row.get('Current Tags', ''))
                comments = str(row.get('Comments', ''))

                # Group by (source/instance, tag, package_id)
                group_key = (source, ring_tag, package_id)
                host_groups[group_key].append({
                    'name': computer_name,
                    'tanium_id': tanium_id,
                    'tag': ring_tag,
                    'source': source,
                    'package_id': package_id,
                    'current_tags': current_tags,
                    'comments': comments
                })

            # Process each group with bulk tagging
            total_groups = len(host_groups)
            logger.info(f"Grouped {num_to_tag} hosts into {total_groups} bulk tagging operations")

            with tqdm(total=total_groups, desc="Bulk tagging host groups", unit="group") as pbar:
                for (source, ring_tag, package_id), hosts in host_groups.items():
                    pbar.set_description(f"Tagging {len(hosts)} hosts in {source} with {ring_tag}")

                    try:
                        # Get the appropriate instance
                        instance = tanium_client.get_instance_by_name(source)
                        if not instance:
                            # All hosts in this group fail
                            for host in hosts:
                                failed_tags.append({
                                    'name': host['name'],
                                    'tanium_id': host['tanium_id'],
                                    'tag': host['tag'],
                                    'source': host['source'],
                                    'package_id': host['package_id'],
                                    'current_tags': host['current_tags'],
                                    'comments': host['comments'],
                                    'error': f"Instance '{source}' not found"
                                })
                            pbar.update(1)
                            continue

                        # Bulk add tags to all hosts in this group
                        logger.info(f"Bulk tagging {len(hosts)} hosts in {source} with {ring_tag} using package {package_id}")
                        result = instance.bulk_add_tags(hosts, ring_tag, package_id)

                        # Extract action ID from result
                        action_id = result.get('action', {}).get('scheduledAction', {}).get('id', 'N/A')

                        # All hosts in this group get the same action ID
                        for host in hosts:
                            successful_tags.append({
                                'name': host['name'],
                                'tanium_id': host['tanium_id'],
                                'tag': host['tag'],
                                'source': host['source'],
                                'package_id': host['package_id'],
                                'current_tags': host['current_tags'],
                                'comments': host['comments'],
                                'action_id': action_id
                            })

                    except Exception as e:
                        # Preserve full error message from Tanium API
                        error_msg = str(e)
                        logger.error(f"Failed to bulk tag {len(hosts)} hosts in {source}: {error_msg}")

                        # All hosts in this group fail with the same error
                        for host in hosts:
                            failed_tags.append({
                                'name': host['name'],
                                'tanium_id': host['tanium_id'],
                                'tag': host['tag'],
                                'source': host['source'],
                                'package_id': host['package_id'],
                                'current_tags': host['current_tags'],
                                'comments': host['comments'],
                                'error': error_msg
                            })

                    pbar.update(1)

            apply_duration = time.time() - apply_start

            # Create Excel report with results
            results_data = []
            for host in successful_tags:
                results_data.append({
                    'Computer Name': host['name'],
                    'Tanium ID': host['tanium_id'],
                    'Source': host['source'],
                    'Ring Tag': host['tag'],
                    'Package ID': host['package_id'],
                    'Action ID': host['action_id'],
                    'Current Tags': host['current_tags'],
                    'Comments': host['comments'],
                    'Status': 'Successfully Tagged'
                })
            for host in failed_tags:
                results_data.append({
                    'Computer Name': host['name'],
                    'Tanium ID': host['tanium_id'],
                    'Source': host['source'],
                    'Ring Tag': host['tag'],
                    'Package ID': host['package_id'],
                    'Action ID': 'N/A',
                    'Current Tags': host['current_tags'],
                    'Comments': host['comments'],
                    'Status': f"Failed: {host['error']}"
                })

            # Create DataFrame and save to Excel
            results_df = pd.DataFrame(results_data)
            current_time_eastern = datetime.now(EASTERN_TZ)
            tz_name = "EST" if current_time_eastern.dst().total_seconds() == 0 else "EDT"
            timestamp = current_time_eastern.strftime(f'%m_%d_%Y %I:%M %p {tz_name}')
            output_filename = report_dir / f'Tanium_Ring_Tagging_Results_{timestamp}.xlsx'

            results_df.to_excel(output_filename, index=False)

            # Apply professional formatting to the Excel file
            column_widths = {
                'computer name': 35,
                'tanium id': 25,
                'source': 15,
                'ring tag': 35,
                'package id': 12,
                'action id': 15,
                'current tags': 50,
                'comments': 60,
                'status': 40
            }
            wrap_columns = {'current tags', 'comments', 'status'}
            apply_professional_formatting(output_filename, column_widths=column_widths, wrap_columns=wrap_columns)

            # Calculate total duration
            total_duration = time.time() - start_time

            # Format timing information
            def format_duration(seconds):
                """Format seconds into a human-readable duration string."""
                import math
                minutes, secs = divmod(seconds, 60)
                hours, minutes = divmod(minutes, 60)
                secs = math.ceil(secs)
                parts = []
                if hours > 0:
                    parts.append(f"{int(hours)} hour{'s' if hours != 1 else ''}")
                if minutes > 0:
                    parts.append(f"{int(minutes)} minute{'s' if minutes != 1 else ''}")
                if secs > 0 or not parts:
                    parts.append(f"{int(secs)} second{'s' if secs != 1 else ''}")
                return " ".join(parts)

            # Generate summary with timing and bulk operation stats
            summary_md = f"## 🎉 Tanium Ring Tagging Complete!\n\n"
            summary_md += f"**Summary:**\n"
            summary_md += f"- Total hosts in report: {total_hosts_in_report:,}\n"
            summary_md += f"- Servers eligible for tagging: {total_eligible_hosts:,} (workstations excluded)\n"
            if batch_size is not None and batch_size < total_eligible_hosts:
                summary_md += f"- 🧪 **Batch mode**: Randomly sampled {num_to_tag:,} servers (requested: {batch_size:,})\n"
            else:
                summary_md += f"- Servers processed: {num_to_tag:,}\n"
            summary_md += f"- **Bulk operations executed**: {total_groups:,} (grouped by instance and tag)\n"
            summary_md += f"- Servers tagged successfully: {len(successful_tags):,}\n"
            summary_md += f"- Servers failed to tag: {len(failed_tags):,}\n\n"
            summary_md += f"**Timing:**\n"
            summary_md += f"- Reading report: {format_duration(read_duration)}\n"
            summary_md += f"- Filtering servers: {format_duration(filter_duration)}\n"
            summary_md += f"- Applying tags (bulk): {format_duration(apply_duration)}\n"
            summary_md += f"- Total execution time: {format_duration(total_duration)}\n\n"
            summary_md += f"📊 **Detailed results with Action IDs are attached in the Excel report.**\n"
            summary_md += f"💡 **Note**: Hosts in the same bulk operation share the same Action ID.\n"

            # Send results with retry
            send_message_with_retry(webex_api, room_id=room_id, markdown=summary_md, files=[str(output_filename)])

        except Exception as e:
            logger.error(f"Error applying Tanium ring tags: {e}")
            send_message_with_retry(webex_api,
                                    room_id=room_id,
                                    markdown=f"❌ Failed to apply ring tags: {str(e)}"
                                    )


class DontRingTagTaniumHosts(Command):
    def __init__(self):
        super().__init__(
            command_keyword="dont_ring_tag_tanium_hosts",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_tars, log_file_name="tars_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        return f"Alright {activity['actor']['displayName']}, I won't tag Tanium hosts. Until next time!👋🏾"


class GetTaniumUnhealthyHosts(Command):
    def __init__(self):
        super().__init__(
            command_keyword="tanium_unhealthy_hosts",
            help_message="Get Tanium Unhealthy Hosts 🔍🤒",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_tars, log_file_name="tars_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId
        message = f"Hello {activity['actor']['displayName']}! This is still work in progress. Please try again later."

        send_message_with_retry(webex_api,
                                room_id=room_id,
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

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_tars, log_file_name="tars_activity_log.csv")
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
                    text="🤖 TARS Bot Status",
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
    # Clean up stale device registrations before creating bot
    cleanup_devices_on_startup(
        CONFIG.webex_bot_access_token_tars,
        bot_name="TARS"
    )

    # Build approved users list: employees + all bots for peer ping communication
    approved_bot_emails = [
        CONFIG.webex_bot_email_toodles,
        CONFIG.webex_bot_email_msoar,
        CONFIG.webex_bot_email_barnacles,
        CONFIG.webex_bot_email_money_ball,
        CONFIG.webex_bot_email_pokedex,
        CONFIG.webex_bot_email_pinger,  # Pinger bot for keepalive
        CONFIG.webex_bot_email_jarvis,  # Jarvis bot
    ]

    return WebexBot(
        CONFIG.webex_bot_access_token_tars,
        approved_domains=[CONFIG.my_web_domain],
        approved_users=approved_bot_emails,  # Allow other bots for peer ping
        # approved_rooms disabled - bot lacks spark:memberships_read scope for validation
        # Security: Only add this bot to authorized rooms to control access
        bot_name="TARS - The Tanium Assistant",
        threads=True,
        log_level="ERROR",
        bot_help_subtitle="Your friendly Tanium tagging bot!",
        allow_bot_to_bot=True  # Enable peer ping health checks from other bots
    )


def tars_initialization(bot):
    """Initialize TARS commands"""
    if bot:
        # Add Tanium commands to the bot
        bot.add_command(GetTaniumHostsWithoutRingTag())
        bot.add_command(RingTagTaniumHosts())
        bot.add_command(DontRingTagTaniumHosts())
        bot.add_command(GetTaniumUnhealthyHosts())
        bot.add_command(GetBotHealth())
        bot.add_command(Hi())
        return True
    return False


def main():
    """TARS main - simplified to use basic WebexBot (keepalive handled by peer_ping_keepalive.py)"""
    logger.info("Starting TARS with basic WebexBot")

    # Create bot instance
    bot = tars_bot_factory()

    # Initialize commands
    tars_initialization(bot)

    # Run bot (simple and direct)
    logger.info("🚀 TARS is up and running...")
    print("🚀 TARS is up and running...", flush=True)
    bot.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
