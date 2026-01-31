#!/usr/bin/python3
"""
Shared base module for Tanium tagging bots (TARS and CASE).

This module contains common functionality used by both:
- TARS: Tanium Cloud tagging bot
- CASE: Tanium On-Prem tagging bot
"""

import logging
import random
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pandas as pd
from tqdm import tqdm
from webex_bot.models.command import Command
from webexpythonsdk.models.cards import (
    AdaptiveCard, Column, ColumnSet,
    TextBlock, options, HorizontalAlignment, VerticalContentAlignment
)
from webexpythonsdk.models.cards.actions import Submit
from webexpythonsdk.models.cards.inputs import Text as TextInput
from zoneinfo import ZoneInfo

from src.utils.webex_utils import send_message_with_retry, send_card_with_retry

logger = logging.getLogger(__name__)

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


def is_recently_online(last_seen_str, reference_time):
    """Check if a host was seen within the last 2 hours of the reference time.

    Args:
        last_seen_str: ISO format timestamp string from Tanium
        reference_time: datetime object to compare against (usually report generation time)

    Returns:
        bool: True if host was seen within 2 hours of reference_time
    """
    if pd.isna(last_seen_str) or not last_seen_str:
        return False
    try:
        last_seen = datetime.fromisoformat(str(last_seen_str).replace('Z', '+00:00'))
        two_hours_before = reference_time - timedelta(hours=2)
        return last_seen >= two_hours_before
    except (ValueError, AttributeError):
        return False


class TaniumBotConfig:
    """Configuration for a Tanium bot instance."""

    def __init__(
        self,
        bot_name: str,
        instance_type: str,  # "cloud" or "on-prem"
        webex_api,
        root_directory: Path,
        activity_log_file: str
    ):
        self.bot_name = bot_name
        self.instance_type = instance_type
        self.instance_filter = instance_type.lower()
        self.webex_api = webex_api
        self.root_directory = root_directory
        self.data_dir = root_directory / "data" / "transient" / "epp_device_tagging"
        self.activity_log_file = activity_log_file

        # Display names and instance-specific settings
        if instance_type.lower() == "cloud":
            self.display_name = "Cloud"
            self.source_filter = "Cloud"
            self.stop_flag_filename = "stop_automated_tanium_tagging.flag"
            self.stop_callback_keyword = "stop_automated_tanium_ring_tagging"
        else:
            self.display_name = "On-Prem"
            self.source_filter = "On-Prem"
            self.stop_flag_filename = "stop_automated_tanium_onprem_tagging.flag"
            self.stop_callback_keyword = "stop_automated_tanium_onprem_ring_tagging"


def send_report(config: TaniumBotConfig, room_id, filename, message) -> None:
    """Sends the enriched hosts report to a Webex room."""
    today_date = datetime.now(EASTERN_TZ).strftime('%m-%d-%Y')
    filepath = config.data_dir / today_date / filename
    hosts_count = len(pd.read_excel(filepath))

    try:
        report_text = f"{message}. Count={hosts_count}!"
        config.webex_api.messages.create(
            roomId=room_id,
            text=report_text,
            files=[str(filepath)]
        )
    except FileNotFoundError:
        logger.error(f"Report file not found at {filepath}")
    except Exception as e:
        logger.error(f"Failed to send report: {e}")


def send_report_with_progress(config: TaniumBotConfig, room_id, filename, message, progress_info=None) -> None:
    """Enhanced report sending with progress information and better formatting."""
    today_date = datetime.now(EASTERN_TZ).strftime('%m-%d-%Y')
    filepath = config.data_dir / today_date / filename

    try:
        if not filepath.exists():
            raise FileNotFoundError(f"Report file not found at {filepath}")

        hosts_count = len(pd.read_excel(filepath))

        current_time_eastern = datetime.now(EASTERN_TZ)
        tz_name = "EST" if current_time_eastern.dst().total_seconds() == 0 else "EDT"

        report_text = f"📊 **{message}**\n\n"
        report_text += f"📈 **Count:** {hosts_count:,} hosts\n"
        report_text += f"📅 **Generated:** {current_time_eastern.strftime(f'%Y-%m-%d %H:%M:%S {tz_name}')}\n"

        if progress_info:
            report_text += f"⏱️ **Processing Time:** {progress_info.get('duration', 'N/A')}\n"

        result = send_message_with_retry(
            config.webex_api, room_id=room_id, markdown=report_text, files=[str(filepath)]
        )
        if result:
            logger.info(f"Successfully sent report {filename} with {hosts_count} hosts to room {room_id}")

    except FileNotFoundError:
        error_msg = f"❌ Report file not found at {filepath}"
        logger.error(error_msg)
        send_message_with_retry(config.webex_api, room_id=room_id, markdown=error_msg)
    except Exception as e:
        error_msg = f"❌ Failed to send report: {str(e)}"
        logger.error(error_msg)
        send_message_with_retry(config.webex_api, room_id=room_id, markdown=error_msg)


def seek_approval_to_ring_tag_tanium(config: TaniumBotConfig, room_id, total_hosts=None, default_batch_size=1000):
    """Send approval card for Tanium ring tagging with batch size option."""
    hosts_info = f" ({total_hosts:,} hosts available)" if total_hosts else ""

    card = AdaptiveCard(
        body=[
            TextBlock(
                text=f"Tanium {config.display_name} Ring Tagging Approval",
                color=options.Colors.ACCENT,
                size=options.FontSize.LARGE,
                weight=options.FontWeight.BOLDER,
                horizontalAlignment=HorizontalAlignment.CENTER),
            ColumnSet(
                columns=[
                    Column(
                        width="stretch",
                        items=[
                            TextBlock(text=f"I can tag workstations and servers in Tanium {config.display_name}{hosts_info}. Do you want to proceed?", wrap=True)
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
                text=f"Enter number of servers to randomly tag. Default is {default_batch_size:,}. Use higher numbers (1000, 5000, etc.) for larger deployments, or enter 'all' to tag all hosts.",
                wrap=True,
                isSubtle=True
            ),
            TextInput(
                id="batch_size",
                placeholder=f"Default: {default_batch_size:,} (or enter 1000, 5000, 'all')",
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

    result = send_card_with_retry(
        config.webex_api,
        room_id=room_id,
        text=f"Please approve the Tanium {config.display_name} tagging action.",
        attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}]
    )

    if result is None:
        error_msg = f"❌ **Failed to send approval card**\n\nI couldn't send the approval card after multiple attempts due to network errors.\n\n**What happened:**\n- Report was generated successfully ({total_hosts:,} hosts available)\n- Network error prevented card delivery\n\n**What to do:**\n- Try running the command again\n- Or proceed directly with: `/ring_tag_tanium_hosts`"

        try:
            send_message_with_retry(config.webex_api, room_id=room_id, markdown=error_msg)
        except Exception as notify_error:
            logger.error(f"Critical: Failed to send fallback notification: {notify_error}")
            logger.error("⚠️ IMPORTANT: User was NOT notified about approval card failure. Check Webex room manually.")


def apply_tags_to_hosts(config: TaniumBotConfig, room_id, batch_size=None, run_by: str = None):
    """Apply ring tags to Tanium hosts with optional batch sampling.

    Args:
        config: TaniumBotConfig with instance-specific settings
        room_id: Webex room ID for sending messages
        batch_size: Optional number of hosts to randomly sample for tagging.
                   If None, all eligible hosts will be tagged.
        run_by: Who initiated the tagging (user name or 'scheduled job')
    """
    from services.tanium import TaniumClient
    from src.utils.excel_formatting import apply_professional_formatting
    from services.epp_tagging_db import insert_tagging_run, bulk_insert_results

    start_time = time.time()

    today_date = datetime.now(EASTERN_TZ).strftime('%m-%d-%Y')
    report_dir = config.data_dir / today_date
    report_path = report_dir / "Tanium_Ring_Tags_Report.xlsx"

    if not report_path.exists():
        send_message_with_retry(
            config.webex_api,
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

        # Filter hosts that have generated tags for the specific instance type
        filter_start = time.time()
        hosts_to_tag = df[
            (df['Generated Tag'].notna()) &
            (df['Generated Tag'] != '') &
            (df['Source'].str.contains(config.source_filter, case=False, na=False))
        ]
        filter_duration = time.time() - filter_start

        if len(hosts_to_tag) == 0:
            send_message_with_retry(
                config.webex_api,
                room_id=room_id,
                markdown=f"❌ **No {config.display_name} hosts available for tagging**. All hosts in the report are either missing generated tags or are from a different instance."
            )
            return

        # Filter for hosts seen within the last 2 hours (currently online)
        hosts_before_online_filter = len(hosts_to_tag)
        report_file_time = datetime.fromtimestamp(report_path.stat().st_mtime, tz=timezone.utc)

        logger.debug(f"DEBUG: Available columns in report: {list(hosts_to_tag.columns)}")
        logger.debug(f"DEBUG: Report file time (data fetch reference): {report_file_time}")

        if 'Last Seen' in hosts_to_tag.columns:
            hosts_to_tag = hosts_to_tag[hosts_to_tag['Last Seen'].apply(
                lambda x: is_recently_online(x, report_file_time)
            )]
            hosts_after_online_filter = len(hosts_to_tag)

            logger.debug(f"DEBUG: After filtering - {hosts_after_online_filter} hosts out of {hosts_before_online_filter} passed the 2-hour filter")

            if hosts_after_online_filter == 0:
                send_message_with_retry(
                    config.webex_api,
                    room_id=room_id,
                    markdown=f"❌ **No currently online {config.display_name} hosts available for tagging**. Found {hosts_before_online_filter:,} eligible hosts, but none were seen within 2 hours of when the report was generated."
                )
                return

            logger.info(f"Filtered to {hosts_after_online_filter} online hosts from {hosts_before_online_filter} eligible hosts")
            if hosts_after_online_filter < hosts_before_online_filter:
                send_message_with_retry(
                    config.webex_api,
                    room_id=room_id,
                    markdown=f"ℹ️ **Online host filter**: Selected {hosts_after_online_filter:,} hosts seen within 2 hours of report generation from {hosts_before_online_filter:,} eligible hosts."
                )

        total_eligible_hosts = len(hosts_to_tag)

        # Apply random sampling if batch size is specified
        if batch_size is not None:
            if batch_size >= total_eligible_hosts:
                send_message_with_retry(
                    config.webex_api,
                    room_id=room_id,
                    markdown=f"ℹ️ **Note**: Batch size ({batch_size:,}) equals or exceeds available hosts ({total_eligible_hosts:,}). Tagging all {total_eligible_hosts:,} hosts."
                )
            else:
                hosts_to_tag = hosts_to_tag.sample(n=batch_size, random_state=None)
                logger.info(f"Randomly sampled {batch_size} hosts from {total_eligible_hosts} eligible hosts")
                send_message_with_retry(
                    config.webex_api,
                    room_id=room_id,
                    markdown=f"🎲 **Batch mode active**: Randomly selected {batch_size:,} hosts from {total_eligible_hosts:,} eligible hosts for tagging."
                )
        else:
            send_message_with_retry(
                config.webex_api,
                room_id=room_id,
                markdown=f"📋 **Full deployment mode**: Tagging ALL {total_eligible_hosts:,} eligible {config.display_name} hosts."
            )

        num_to_tag = len(hosts_to_tag)

        # Initialize Tanium client
        tanium_client = TaniumClient()

        # Track results
        successful_tags = []
        failed_tags = []

        # Group hosts by (instance, tag, package_id) for bulk tagging
        apply_start = time.time()
        host_groups = defaultdict(list)

        total_hosts_to_group = len(hosts_to_tag)
        logger.info(f"Grouping {total_hosts_to_group} hosts by instance/tag/package for bulk operations...")

        for host_count, (idx, row) in enumerate(hosts_to_tag.iterrows(), 1):
            computer_name = str(row['Computer Name'])
            tanium_id = str(row['Tanium ID'])
            source = str(row['Source'])
            ring_tag = str(row['Generated Tag'])
            package_id = str(row['Package ID'])
            current_tags = str(row.get('Current Tags', ''))
            comments = str(row.get('Comments', ''))
            country = str(row.get('Country', ''))
            region = str(row.get('Region', ''))
            environment = str(row.get('Environment', ''))

            group_key = (source, ring_tag, package_id)
            host_groups[group_key].append({
                'name': computer_name,
                'tanium_id': tanium_id,
                'tag': ring_tag,
                'source': source,
                'package_id': package_id,
                'current_tags': current_tags,
                'comments': comments,
                'country': country,
                'region': region,
                'environment': environment
            })

            if host_count % 100 == 0 or host_count == total_hosts_to_group:
                logger.info(f"Grouped {host_count}/{total_hosts_to_group} hosts ({host_count * 100 / total_hosts_to_group:.1f}%)")

        # Process each group with bulk tagging (respecting Tanium's 25 endpoint limit per call)
        TANIUM_BULK_TAG_LIMIT = 25

        batched_groups = []
        for (source, ring_tag, package_id), hosts in host_groups.items():
            for i in range(0, len(hosts), TANIUM_BULK_TAG_LIMIT):
                batch = hosts[i:i + TANIUM_BULK_TAG_LIMIT]
                batched_groups.append(((source, ring_tag, package_id), batch))

        total_batches = len(batched_groups)
        logger.info(f"Grouped {num_to_tag} hosts into {len(host_groups)} groups, split into {total_batches} API calls (max 25 hosts per call)")

        import sys
        disable_tqdm = not sys.stdout.isatty()

        batch_counter = 0
        with tqdm(total=total_batches, desc="Bulk tagging host batches", unit="batch", disable=disable_tqdm) as pbar:
            for (source, ring_tag, package_id), hosts in batched_groups:
                batch_counter += 1
                pbar.set_description(f"Tagging {len(hosts)} hosts in {source} with {ring_tag}")

                try:
                    instance = tanium_client.get_instance_by_name(source)
                    if not instance:
                        for host in hosts:
                            failed_tags.append({
                                **host,
                                'error': f"Instance '{source}' not found"
                            })
                        pbar.update(1)
                        continue

                    result = instance.bulk_add_tags(hosts, ring_tag, package_id)
                    action_id = result.get('action', {}).get('scheduledAction', {}).get('id', 'N/A')

                    for host in hosts:
                        successful_tags.append({
                            **host,
                            'action_id': action_id
                        })

                except Exception as e:
                    error_msg = str(e)
                    logger.error(f"Failed to bulk tag {len(hosts)} hosts in {source}: {error_msg}")

                    for host in hosts:
                        failed_tags.append({
                            **host,
                            'error': error_msg
                        })

                if batch_counter % 10 == 0 or batch_counter == total_batches:
                    logger.info(f"Processed batch {batch_counter}/{total_batches} ({batch_counter * 100 / total_batches:.1f}%) - {len(successful_tags)} successful, {len(failed_tags)} failed")

                pbar.update(1)

        apply_duration = time.time() - apply_start

        # Create Excel report with results
        results_data = []
        for host in successful_tags:
            results_data.append({
                'Computer Name': host['name'],
                'Tanium ID': host['tanium_id'],
                'Source': host['source'],
                'Country': host['country'],
                'Region': host['region'],
                'Environment': host['environment'],
                'Ring Tag': host['tag'],
                'Package ID': host['package_id'],
                'Action ID': host['action_id'],
                'Current Tags': host['current_tags'],
                'Status': 'Successfully Tagged'
            })
        for host in failed_tags:
            results_data.append({
                'Computer Name': host['name'],
                'Tanium ID': host['tanium_id'],
                'Source': host['source'],
                'Country': host['country'],
                'Region': host['region'],
                'Environment': host['environment'],
                'Ring Tag': host['tag'],
                'Package ID': host['package_id'],
                'Action ID': 'N/A',
                'Current Tags': host['current_tags'],
                'Status': f"Failed: {host['error']}"
            })

        results_df = pd.DataFrame(results_data)
        current_time_eastern = datetime.now(EASTERN_TZ)
        tz_name = "EST" if current_time_eastern.dst().total_seconds() == 0 else "EDT"
        timestamp = current_time_eastern.strftime(f'%m_%d_%Y %I:%M %p {tz_name}')
        output_filename = report_dir / f'Tanium_Ring_Tagging_Results_{timestamp}.xlsx'

        results_df.to_excel(output_filename, index=False)

        column_widths = {
            'computer name': 35,
            'tanium id': 25,
            'source': 15,
            'country': 22,
            'region': 18,
            'environment': 22,
            'ring tag': 35,
            'package id': 12,
            'action id': 15,
            'current tags': 50,
            'status': 40
        }
        wrap_columns = {'current tags', 'status'}
        apply_professional_formatting(output_filename, column_widths=column_widths, wrap_columns=wrap_columns)

        total_duration = time.time() - start_time

        # Generate summary and send notification first (before DB write to reduce user wait time)
        summary_md = f"## 🎉 Tanium {config.display_name} Ring Tagging Complete!\n\n"
        summary_md += f"**Summary:**\n"
        summary_md += f"- Hosts without ring tag: {total_hosts_in_report:,}\n"
        summary_md += f"- Hosts eligible for tagging: {total_eligible_hosts:,}\n"
        if batch_size is not None and batch_size < total_eligible_hosts:
            summary_md += f"- 🧪 **Batch mode**: Randomly sampled {num_to_tag:,} hosts (requested: {batch_size:,})\n"
        else:
            summary_md += f"- Hosts processed: {num_to_tag:,}\n"
        summary_md += f"- **API calls executed**: {total_batches:,} (max 25 hosts per call)\n"
        summary_md += f"- Hosts tagged successfully: {len(successful_tags):,}\n"
        summary_md += f"- Hosts failed to tag: {len(failed_tags):,}\n\n"
        summary_md += f"**Timing:**\n"
        summary_md += f"- Reading report: {format_duration(read_duration)}\n"
        summary_md += f"- Filtering hosts: {format_duration(filter_duration)}\n"
        summary_md += f"- Applying tags (bulk): {format_duration(apply_duration)}\n"
        summary_md += f"- Total execution time: {format_duration(total_duration)}\n\n"
        summary_md += f"📊 **Detailed results with Action IDs are attached in the Excel report.**\n\n"
        summary_md += f"💡 **Note**: \n"
        summary_md += f"- Hosts in the same API batch (up to 25) share the same Action ID.\n"
        summary_md += f"- ⏰ **Tanium takes about 30 minutes to fully apply the tags.** Please wait for 30 minutes before running the next round of tagging.\n"

        send_message_with_retry(config.webex_api, room_id=room_id, markdown=summary_md, files=[str(output_filename)])

        # Write results to database (after notification to reduce user wait time)
        try:
            run_timestamp = datetime.now(EASTERN_TZ).replace(tzinfo=None)  # SQLite doesn't handle tz-aware datetimes well
            run_id = insert_tagging_run(
                run_date=run_timestamp.date(),
                platform=f'Tanium {config.display_name}',  # 'Tanium Cloud' or 'Tanium On-Prem'
                run_timestamp=run_timestamp,
                source_file=output_filename.name,
                total_devices=num_to_tag,
                successfully_tagged=len(successful_tags),
                failed=len(failed_tags),
                run_by=run_by or 'unknown'
            )

            # Aggregate results by country/region/ring_tag for database
            db_results = []
            for country, country_group in results_df.groupby('Country', dropna=False):
                country_val = country if pd.notna(country) else 'Unknown'
                for region, region_group in country_group.groupby('Region', dropna=False):
                    region_val = region if pd.notna(region) else None
                    for ring_tag, tag_group in region_group.groupby('Ring Tag', dropna=False):
                        ring_tag_val = ring_tag if pd.notna(ring_tag) else None
                        success_count = len(tag_group[tag_group['Status'] == 'Successfully Tagged'])
                        fail_count = len(tag_group) - success_count
                        db_results.append({
                            'country': country_val,
                            'region': region_val,
                            'category': None,
                            'ring_tag': ring_tag_val,
                            'total_devices': len(tag_group),
                            'successfully_tagged': success_count,
                            'failed': fail_count,
                            'country_guessed': 0
                        })

            if db_results:
                bulk_insert_results(run_id, db_results)

            logger.info(f"Saved tagging results to database: run_id={run_id}, run_by={run_by}")
        except Exception as db_err:
            logger.error(f"Failed to save tagging results to database: {db_err}")

    except Exception as e:
        logger.error(f"Error applying Tanium ring tags: {e}")
        send_message_with_retry(
            config.webex_api,
            room_id=room_id,
            markdown=f"❌ Failed to apply ring tags: {str(e)}"
        )


def create_bot_health_card(bot_name: str, current_time: datetime):
    """Create a health status card for the bot."""
    health_status = "🟢 Healthy"
    health_detail = "Running with resilience framework"
    tz_name = "EST" if current_time.dst().total_seconds() == 0 else "EDT"

    return AdaptiveCard(
        body=[
            TextBlock(
                text=f"🤖 {bot_name} Bot Status",
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


def send_automated_tagging_safety_window_card(config: TaniumBotConfig, room_id, hosts_count, safety_window_minutes):
    """Send a safety window card for automated Tanium ring tagging.

    Args:
        config: TaniumBotConfig with instance-specific settings
        room_id: Webex room ID to send to
        hosts_count: Number of hosts to be tagged
        safety_window_minutes: Minutes to wait before proceeding

    Returns:
        The message object if successful, None otherwise
    """
    current_time = datetime.now(EASTERN_TZ)
    proceed_time = current_time + timedelta(minutes=safety_window_minutes)
    tz_name = "EST" if current_time.dst().total_seconds() == 0 else "EDT"

    card = AdaptiveCard(
        body=[
            TextBlock(
                text=f"🤖 Automated Tanium {config.display_name} Ring Tagging - Safety Window",
                color=options.Colors.WARNING,
                size=options.FontSize.LARGE,
                weight=options.FontWeight.BOLDER,
                horizontalAlignment=HorizontalAlignment.CENTER),
            ColumnSet(
                columns=[
                    Column(
                        width="stretch",
                        items=[
                            TextBlock(
                                text=f"**{hosts_count:,} hosts** are about to be ring-tagged automatically.",
                                wrap=True,
                                weight=options.FontWeight.BOLDER
                            ),
                            TextBlock(
                                text=f"⏰ **Proceed Time:** {proceed_time.strftime(f'%H:%M:%S {tz_name}')}",
                                wrap=True
                            ),
                            TextBlock(
                                text=f"If you see an issue in the report above, click STOP below within {safety_window_minutes} minutes.",
                                wrap=True,
                                color=options.Colors.ATTENTION
                            ),
                            TextBlock(
                                text="Otherwise, tagging will proceed automatically.",
                                wrap=True
                            )
                        ],
                        verticalContentAlignment=VerticalContentAlignment.CENTER
                    )
                ]
            )
        ],
        actions=[
            Submit(
                title="🛑 STOP - Do NOT tag these hosts!",
                data={"callback_keyword": config.stop_callback_keyword},
                style=options.ActionStyle.DESTRUCTIVE
            )
        ]
    )

    result = send_card_with_retry(
        config.webex_api,
        room_id,
        text=f"Automated Tanium {config.display_name} ring tagging will proceed in {safety_window_minutes} minutes unless stopped.",
        attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}],
        max_retries=3
    )

    if not result:
        logger.error(f"⚠️ Failed to send automated Tanium {config.display_name} tagging safety window card after retries.")

    return result


def run_automated_ring_tagging_workflow(config: TaniumBotConfig, room_id: str, safety_window_minutes: int, default_batch_size: int):
    """Automated Tanium ring tagging workflow with safety window.

    This is the full workflow called by the scheduler. It handles:
    1. Report generation
    2. Sending report with safety window card
    3. Waiting for the safety window
    4. Checking for stop signal
    5. Proceeding with tagging (or aborting)
    6. Sending completion notification

    Args:
        config: TaniumBotConfig with instance-specific settings
        room_id: Webex room ID to send notifications
        safety_window_minutes: Minutes to wait before proceeding with tagging
        default_batch_size: Number of hosts to tag per batch
    """
    import time
    import os
    import fasteners

    from src.epp.tanium_hosts_without_ring_tag import create_processor

    if not room_id:
        logger.error(f"Room ID not configured for {config.display_name}. Skipping automated tagging.")
        return

    logger.info("=" * 80)
    logger.info(f"Starting automated Tanium {config.display_name} ring tagging workflow")
    logger.info("=" * 80)

    # Send initial notification
    try:
        send_message_with_retry(
            config.webex_api, room_id,
            markdown=f"🚀 **Automated Tanium {config.display_name} Ring Tagging Job Starting Now**\n\nGenerating report of hosts without ring tags..."
        )
    except Exception as e:
        logger.error(f"Failed to send job start notification: {e}")

    # Step 1: Generate report
    logger.info(f"Step 1: Generating Tanium {config.display_name} hosts without ring tag report...")
    lock_path = config.root_directory / "src" / "epp" / "all_tanium_hosts.lock"

    try:
        with fasteners.InterProcessLock(lock_path):
            processor = create_processor(instance_filter=config.instance_filter)
            report_path = processor.process_hosts_without_ring_tags(test_limit=None)

            if not report_path or not Path(report_path).exists():
                logger.error(f"Report file not found at {report_path}. Aborting automated tagging.")
                send_message_with_retry(
                    config.webex_api, room_id,
                    markdown=f"❌ Automated Tanium {config.display_name} ring tagging failed: Report file not found."
                )
                return

            hosts_df = pd.read_excel(report_path)
            total_hosts_without_ring_tag = len(hosts_df)

            # Filter to hosts with successfully generated tags
            hosts_with_generated_tags = hosts_df[
                (hosts_df['Generated Tag'].notna()) &
                (hosts_df['Generated Tag'] != '') &
                (~hosts_df['Comments'].str.contains('missing|couldn\'t be generated|error', case=False, na=False))
            ]
            total_eligible_hosts = len(hosts_with_generated_tags)

            if total_eligible_hosts == 0:
                logger.info("No hosts without ring tags found. Nothing to tag.")
                send_message_with_retry(
                    config.webex_api, room_id,
                    markdown=f"✅ Automated Tanium {config.display_name} ring tagging check complete: No hosts need tagging."
                )
                return

            # Apply the same 2-hour "recently online" filter that apply_tags_to_hosts uses
            # This ensures the count shown in the safety window matches what will actually be tagged
            report_file_time = datetime.fromtimestamp(Path(report_path).stat().st_mtime, tz=timezone.utc)

            if 'Last Seen' in hosts_with_generated_tags.columns:
                online_hosts = hosts_with_generated_tags[hosts_with_generated_tags['Last Seen'].apply(
                    lambda x: is_recently_online(x, report_file_time)
                )]
                hosts_count = len(online_hosts)
                logger.info(f"After 2-hour online filter: {hosts_count} hosts (from {total_eligible_hosts} eligible)")
            else:
                hosts_count = total_eligible_hosts
                logger.warning("'Last Seen' column not found - using total eligible hosts count")

            if hosts_count == 0:
                logger.info(f"No hosts seen within last 2 hours. {total_eligible_hosts} hosts have generated tags but none are currently online.")
                send_message_with_retry(
                    config.webex_api, room_id,
                    markdown=f"✅ Automated Tanium {config.display_name} ring tagging check complete: {total_eligible_hosts:,} hosts have generated tags, but none were seen within the last 2 hours. Nothing to tag."
                )
                return

            logger.info(f"Found {hosts_count} hosts without ring tags")

    except Exception as e:
        logger.error(f"Failed to generate report: {e}", exc_info=True)
        send_message_with_retry(
            config.webex_api, room_id,
            markdown=f"❌ Automated Tanium {config.display_name} ring tagging failed during report generation: {str(e)}"
        )
        return
    finally:
        if lock_path.exists():
            try:
                lock_path.unlink()
            except Exception as e:
                logger.error(f"Failed to remove lock file {lock_path}: {e}")

    # Step 2: Send report with safety window card
    logger.info("Step 2: Sending report with safety window notification...")
    try:
        file_size_mb = os.path.getsize(report_path) / (1024 * 1024)
        current_time = datetime.now(EASTERN_TZ)
        tz_name = "EST" if current_time.dst().total_seconds() == 0 else "EDT"

        report_text = f"📊 **Automated Tanium {config.display_name} Ring Tagging Report**\n\n"
        report_text += f"📈 **Hosts currently without a Ring tag:** {total_hosts_without_ring_tag:,}\n"
        report_text += f"🟢 **Hosts online in last 2 hours (eligible):** {hosts_count:,}\n"
        report_text += f"📅 **Generated:** {current_time.strftime(f'%Y-%m-%d %H:%M:%S {tz_name}')}\n"
        report_text += f"📦 **File Size:** {file_size_mb:.2f} MB\n"

        send_message_with_retry(config.webex_api, room_id, markdown=report_text, files=[str(report_path)])

        # Send safety window card
        flag_file = config.data_dir / config.stop_flag_filename

        # Remove any stale flag file from previous runs
        if flag_file.exists():
            flag_file.unlink()
            logger.info("Removed stale stop flag from previous run")

        safety_card_message = send_automated_tagging_safety_window_card(config, room_id, hosts_count, safety_window_minutes)

    except Exception as e:
        logger.error(f"Failed to send report and safety window: {e}", exc_info=True)
        return

    # Step 3: Wait for safety window
    logger.info(f"Step 3: Waiting {safety_window_minutes} minutes for user review...")
    time.sleep(safety_window_minutes * 60)

    # Step 4: Check if stopped
    logger.info("Step 4: Checking if tagging was stopped...")
    if flag_file.exists():
        logger.info(f"Automated Tanium {config.display_name} tagging was stopped by user. Aborting.")
        flag_file.unlink()  # Clean up flag
        send_message_with_retry(
            config.webex_api, room_id,
            markdown=f"🛑 Automated Tanium {config.display_name} ring tagging was stopped. No tags were applied."
        )
        return

    # Step 5: Proceed with tagging
    logger.info(f"Step 5: No stop signal received. Proceeding with automated Tanium {config.display_name} ring tagging...")

    # Delete the safety window card to avoid confusion
    try:
        if safety_card_message and hasattr(safety_card_message, 'id'):
            config.webex_api.messages.delete(safety_card_message.id)
            logger.info("Deleted safety window card after expiration")
    except Exception as e:
        logger.warning(f"Failed to delete safety window card: {e}")

    send_message_with_retry(
        config.webex_api, room_id,
        markdown=f"✅ Safety window expired. Starting automated Tanium {config.display_name} ring tagging now..."
    )

    ring_tag_lock_path = config.root_directory / "src" / "epp" / "ring_tag_tanium_hosts.lock"
    try:
        with fasteners.InterProcessLock(ring_tag_lock_path):
            apply_tags_to_hosts(config, room_id, batch_size=default_batch_size, run_by='scheduled job')
            logger.info(f"Automated Tanium {config.display_name} ring tagging completed successfully")
    except Exception as e:
        logger.error(f"Failed to execute ring tagging: {e}", exc_info=True)
        send_message_with_retry(
            config.webex_api, room_id,
            markdown=f"❌ Automated Tanium {config.display_name} ring tagging failed during execution: {str(e)}"
        )
    finally:
        if ring_tag_lock_path.exists():
            try:
                ring_tag_lock_path.unlink()
            except Exception as e:
                logger.error(f"Failed to remove lock file {ring_tag_lock_path}: {e}")

    # Send next run notification
    try:
        current_time = datetime.now(EASTERN_TZ)
        hour = current_time.hour
        weekday = current_time.weekday()  # 0=Monday, 3=Thursday

        # Calculate next run datetime (Mon/Thu at 4 AM, 12 PM, or 8 PM)
        if weekday == 0:  # Monday
            if hour < 4:
                next_run = current_time.replace(hour=4, minute=0, second=0, microsecond=0)
            elif hour < 12:
                next_run = current_time.replace(hour=12, minute=0, second=0, microsecond=0)
            elif hour < 20:
                next_run = current_time.replace(hour=20, minute=0, second=0, microsecond=0)
            else:
                # Next is Thursday 4 AM
                days_until_thursday = 3 - weekday  # 3 days
                next_run = (current_time + timedelta(days=days_until_thursday)).replace(hour=4, minute=0, second=0, microsecond=0)
        elif weekday == 3:  # Thursday
            if hour < 4:
                next_run = current_time.replace(hour=4, minute=0, second=0, microsecond=0)
            elif hour < 12:
                next_run = current_time.replace(hour=12, minute=0, second=0, microsecond=0)
            elif hour < 20:
                next_run = current_time.replace(hour=20, minute=0, second=0, microsecond=0)
            else:
                # Next is Monday 4 AM
                days_until_monday = 7 - weekday  # 4 days
                next_run = (current_time + timedelta(days=days_until_monday)).replace(hour=4, minute=0, second=0, microsecond=0)
        elif weekday < 3:  # Tue, Wed (1, 2)
            days_until_thursday = 3 - weekday
            next_run = (current_time + timedelta(days=days_until_thursday)).replace(hour=4, minute=0, second=0, microsecond=0)
        else:  # Fri, Sat, Sun (4, 5, 6)
            days_until_monday = 7 - weekday
            next_run = (current_time + timedelta(days=days_until_monday)).replace(hour=4, minute=0, second=0, microsecond=0)

        next_run_day = next_run.strftime('%A')
        tz_name = "EST" if next_run.dst().total_seconds() == 0 else "EDT"

        send_message_with_retry(
            config.webex_api, room_id,
            markdown=f"📅 **Next Automated Run:** {next_run_day}, {next_run.strftime('%B %d, %Y at %I:%M %p')} {tz_name}"
        )
    except Exception as e:
        logger.warning(f"Failed to send next run notification: {e}")
