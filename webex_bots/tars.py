#!/usr/bin/python3
"""
the threat-intel service - Tanium Cloud tagging bot.

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
logger.warning(f"🚀 the threat-intel service BOT STARTED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
logger.warning("=" * 100)

import fasteners
import pandas as pd
from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot
from webex_bots.room_gated_bot import RoomGatedWebexBot
from webexteamssdk import WebexTeamsAPI
from webexpythonsdk.models.cards import (
    AdaptiveCard, Column, ColumnSet, Container,
    TextBlock, FactSet, Fact, options, HorizontalAlignment, VerticalContentAlignment
)
from webexpythonsdk.models.cards.actions import Submit
from webexpythonsdk.models.cards.inputs import Text as TextInput

from my_config import get_config
from src.epp.tanium_hosts_without_ring_tag import create_processor
from src.utils.logging_utils import log_activity
from src.utils.webex_device_manager import cleanup_devices_on_startup
from src.utils.webex_utils import send_message_with_retry, send_card_with_retry, format_eta, clear_stale_lock, periodic_progress_pinger
from src.utils.webex_pool_config import configure_webex_api_session

# Import shared Tanium bot functionality
from webex_bots.tanium_bot_base import (
    TaniumBotConfig,
    get_random_loading_message,
    seek_approval_to_ring_tag_tanium,
    apply_tags_to_hosts,
    create_bot_health_card,
    is_recently_online,
    EASTERN_TZ,
    run_automated_ring_tagging_workflow as _run_automated_ring_tagging_workflow,
)

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

# Bot configuration for the threat-intel service (Cloud instance)
BOT_CONFIG = TaniumBotConfig(
    bot_name="the threat-intel service",
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
        default_batch_size=None  # Tag all eligible hosts
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
                                    f"Estimated completion: {format_eta(15)} ⏰"
                                )
                                )
        lock_path = ROOT_DIRECTORY / "src" / "epp" / "all_tanium_hosts.lock"
        clear_stale_lock(lock_path)
        filepath = None
        try:
            with periodic_progress_pinger(webex_api, room_id), fasteners.InterProcessLock(lock_path):
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
            seek_approval_to_ring_tag_tanium(BOT_CONFIG, room_id, total_hosts=hosts_with_generated_tags_count)


class RingTagTaniumHosts(Command):
    def __init__(self):
        super().__init__(
            command_keyword="ring_tag_tanium_hosts",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_tars, log_file_name="tars_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId

        loading_msg = get_random_loading_message()
        send_message_with_retry(webex_api,
                                room_id=room_id,
                                markdown=f"Hello {activity['actor']['displayName']}! {loading_msg}\n\n🏷️**Starting ring tagging for Tanium Cloud hosts (tagging all online hosts)...**\nEstimated completion: {format_eta(5)} ⏰"
                                )

        lock_path = ROOT_DIRECTORY / "src" / "epp" / "ring_tag_tanium_hosts.lock"
        clear_stale_lock(lock_path)
        user_name = activity['actor']['displayName']
        try:
            with periodic_progress_pinger(webex_api, room_id), fasteners.InterProcessLock(lock_path):
                apply_tags_to_hosts(BOT_CONFIG, room_id, batch_size=None, run_by=user_name)
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
                                    "Checking unhealthy hosts (servers: >1 day, workstations: >3 days), cross-referencing with CrowdStrike (seen within 24h), enriching with ServiceNow...\n"
                                    f"Estimated completion: {format_eta(5)} ⏰"
                                )
                                )

        lock_path = ROOT_DIRECTORY / "src" / "epp" / "tanium_unhealthy_hosts.lock"
        clear_stale_lock(lock_path)
        filepath = None
        try:
            with periodic_progress_pinger(webex_api, room_id), fasteners.InterProcessLock(lock_path):
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
                                    markdown=f"Hello {activity['actor']['displayName']}! 🎉 **Great news!** No truly unhealthy Tanium Cloud hosts found (servers: >1 day, workstations: >3 days in Tanium + seen in CrowdStrike within 24h)."
                                    )
            return

        # Count statistics
        cs_not_found = len(df[df['CS Status'] == 'Not Found'])
        cs_online = len(df[df['CS Online State'] == 'online'])
        snow_found = len(df[df['SNOW Status'] == 'Found'])
        operational_or_pipeline = len(df[df['SNOW Lifecycle'].str.lower().isin(['operational', 'pipeline'])])
        rtr_candidates = len(df[df['RTR Candidate'] == 'Yes'])
        pingable = len(df[df['Pingable'] == 'Yes']) if 'Pingable' in df.columns else 0
        not_pingable = len(df[df['Pingable'] == 'No']) if 'Pingable' in df.columns else 0

        # Server vs workstation breakdown
        workstations = df[df['OS Platform'].isin(['Windows', 'Mac'])]
        servers = df[~df['OS Platform'].isin(['Windows', 'Mac'])]
        prod_servers = servers[servers['SNOW Environment'].str.lower() == 'production']
        non_prod_servers = servers[servers['SNOW Environment'].str.lower() != 'production']

        message = f"Hello {activity['actor']['displayName']}! Here's the **Tanium Cloud Unhealthy Hosts Report** 🤒\n\n"
        message += f"**Summary:**\n"
        message += f"- Truly unhealthy hosts (Tanium last seen: servers >1 day, workstations >3 days + seen in CrowdStrike within 24h or not in CS): **{total_unhealthy:,}**\n"
        message += f"  - Servers: {len(servers):,} (Prod: {len(prod_servers):,} | Non-Prod: {len(non_prod_servers):,}) | Workstations: {len(workstations):,}\n"
        message += f"- Pingable: {pingable:,} | Not pingable: {not_pingable:,}\n"
        if cs_not_found > 0:
            message += f"- ⚠️ **Not found in CrowdStrike: {cs_not_found:,}** (no EDR visibility — risk)\n"
        message += f"- Currently online in CrowdStrike: {cs_online:,}\n"
        message += f"- Found in ServiceNow CMDB: {snow_found:,}\n"
        message += f"- Lifecycle = Operational/Pipeline: {operational_or_pipeline:,}\n"
        message += f"- **RTR Remediation Candidates: {rtr_candidates:,}** ✅\n\n"
        message += "_RTR candidates are hosts that are operational/pipeline in SNOW and online in CrowdStrike — ready for automated Tanium agent reinstallation._"

        send_message_with_retry(webex_api, room_id=room_id, markdown=message, files=[str(filepath)])


class GetTaniumPMLIHosts(Command):
    def __init__(self):
        super().__init__(
            command_keyword="tanium_pmli_hosts",
            help_message="Get Tanium Cloud PMLI Hosts 🔍🇮🇳",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_tars, log_file_name="tars_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        from src.epp.tanium_pmli_hosts import create_processor as create_pmli_processor

        room_id = attachment_actions.roomId
        loading_msg = get_random_loading_message()
        send_message_with_retry(webex_api,
                                room_id=room_id,
                                markdown=(
                                    f"Hello {activity['actor']['displayName']}! {loading_msg}\n\n"
                                    "🔍 **Tanium Cloud PMLI Hosts Report** 🇮🇳\n"
                                    "Fetching PMLI hosts and enriching with ServiceNow data...\n"
                                    f"Estimated completion: {format_eta(15)} ⏰"
                                )
                                )

        lock_path = ROOT_DIRECTORY / "src" / "epp" / "tanium_pmli_hosts.lock"
        clear_stale_lock(lock_path)
        filepath = None
        try:
            with periodic_progress_pinger(webex_api, room_id), fasteners.InterProcessLock(lock_path):
                processor = create_pmli_processor(instance_filter="cloud")
                filepath = processor.process(test_limit=None)
        except Exception as e:
            logger.error(f"Error in GetTaniumPMLIHosts execute: {e}")
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
                                    markdown=f"Hello {activity['actor']['displayName']}! ❌ **Error generating PMLI hosts report**: {error_msg}"
                                    )
            return

        # Read report and generate summary
        df = pd.read_excel(filepath)
        total_pmli = len(df)

        if total_pmli == 0:
            send_message_with_retry(webex_api,
                                    room_id=room_id,
                                    markdown=f"Hello {activity['actor']['displayName']}! 🎉 **Great news!** No PMLI hosts found in Tanium Cloud."
                                    )
            return

        # Count statistics
        snow_found = len(df[df['SNOW Status'] == 'Found'])
        by_reason = df['PMLI Match Reason'].str.split(' \\+ ').str[0].value_counts()

        message = f"Hello {activity['actor']['displayName']}! Here's the **Tanium Cloud PMLI Hosts Report** 🇮🇳\n\n"
        message += f"**Summary:**\n"
        message += f"- Total PMLI hosts: **{total_pmli:,}**\n"
        message += f"- Found in ServiceNow CMDB: {snow_found:,}\n"
        message += f"\n**Detection breakdown:**\n"
        for reason, count in by_reason.items():
            message += f"- {reason}: {count:,}\n"

        report_msg = send_message_with_retry(webex_api, room_id=room_id, markdown=message, files=[str(filepath)])

        # Check if any hosts have APAC ring tags — if so, offer to remove them
        if report_msg and 'Current Tags' in df.columns:
            apac_count = _count_apac_ring_tag_hosts(df)
            if apac_count > 0:
                # Reset progress tracker for new report
                _reset_apac_removal_progress()
                _send_apac_removal_card(room_id, apac_count, parent_id=report_msg.id)


def _get_apac_removal_progress_path() -> Path:
    """Path to the JSON file tracking which hosts have had APAC tags removed."""
    today_date = datetime.now(EASTERN_TZ).strftime('%m-%d-%Y')
    return ROOT_DIRECTORY / "data" / "transient" / "epp_device_tagging" / today_date / "pmli_apac_removal_progress.json"


def _load_apac_removal_progress() -> set:
    """Load set of hostnames already processed."""
    import json
    progress_path = _get_apac_removal_progress_path()
    if progress_path.exists():
        try:
            data = json.loads(progress_path.read_text())
            return set(data.get('processed_hostnames', []))
        except Exception:
            return set()
    return set()


def _save_apac_removal_progress(processed_hostnames: set):
    """Save the set of processed hostnames."""
    import json
    progress_path = _get_apac_removal_progress_path()
    progress_path.parent.mkdir(parents=True, exist_ok=True)
    progress_path.write_text(json.dumps({
        'processed_hostnames': sorted(processed_hostnames),
        'updated_at': datetime.now(EASTERN_TZ).isoformat()
    }, indent=2))


def _reset_apac_removal_progress():
    """Reset progress when a new PMLI report is generated."""
    progress_path = _get_apac_removal_progress_path()
    if progress_path.exists():
        progress_path.unlink()


def _count_apac_ring_tag_hosts(df) -> int:
    """Count hosts in a DataFrame that have an APAC ring tag."""
    import re
    pattern = re.compile(r'EPP_ECMTag_APAC_', re.IGNORECASE)
    return int(df['Current Tags'].fillna('').astype(str).apply(lambda t: bool(pattern.search(t))).sum())


def _send_apac_removal_card(room_id, remaining_count, parent_id=None):
    """Send the APAC Ring tag removal approval card."""
    card = AdaptiveCard(
        body=[
            Container(
                items=[
                    TextBlock(
                        text="🇮🇳  PMLI Hosts — APAC Ring Tag Removal",
                        size=options.FontSize.LARGE,
                        weight=options.FontWeight.BOLDER,
                        color=options.Colors.LIGHT,
                        horizontalAlignment=HorizontalAlignment.CENTER,
                    ),
                ],
                style=options.ContainerStyle.ACCENT,
                bleed=True,
            ),
            ColumnSet(
                columns=[
                    Column(
                        width="auto",
                        items=[
                            TextBlock(
                                text=f"{remaining_count:,}",
                                size=options.FontSize.EXTRA_LARGE,
                                weight=options.FontWeight.BOLDER,
                                color=options.Colors.ATTENTION,
                                horizontalAlignment=HorizontalAlignment.CENTER,
                            ),
                            TextBlock(
                                text="hosts remaining",
                                size=options.FontSize.SMALL,
                                isSubtle=True,
                                horizontalAlignment=HorizontalAlignment.CENTER,
                                spacing=options.Spacing.NONE,
                            ),
                        ],
                        verticalContentAlignment=VerticalContentAlignment.CENTER,
                    ),
                    Column(
                        width="stretch",
                        items=[
                            TextBlock(
                                text="These PMLI hosts still have an **APAC Ring tag** that needs to be removed. Only hosts seen online in the last 2 hours will be targeted.",
                                wrap=True,
                            ),
                        ],
                        verticalContentAlignment=VerticalContentAlignment.CENTER,
                    ),
                ],
                separator=True,
                spacing=options.Spacing.MEDIUM,
            ),
            TextBlock(
                text="Batch Size",
                weight=options.FontWeight.BOLDER,
                separator=True,
                spacing=options.Spacing.MEDIUM,
            ),
            TextInput(
                id="batch_size",
                placeholder="Default: 100 (max 500)",
                isRequired=False,
            ),
        ],
        actions=[
            Submit(title="Skip ✋", data={"callback_keyword": "dont_remove_apac_ring_tag"},
                   style=options.ActionStyle.DESTRUCTIVE),
            Submit(title="Remove Tags 🏷️", data={"callback_keyword": "remove_apac_ring_tag"},
                   style=options.ActionStyle.POSITIVE),
        ],
    )

    kwargs = {}
    if parent_id:
        kwargs['parentId'] = parent_id

    send_card_with_retry(
        webex_api,
        room_id=room_id,
        text="PMLI Hosts — APAC Ring Tag Removal",
        attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}],
        **kwargs
    )


class RemoveApacRingTag(Command):
    """Remove APAC Ring tags from PMLI hosts per button click."""

    DEFAULT_BATCH_SIZE = 100
    MAX_BATCH_SIZE = 500

    def __init__(self):
        super().__init__(
            command_keyword="remove_apac_ring_tag",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_tars, log_file_name="tars_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        import re
        from services.tanium import TaniumClient

        room_id = attachment_actions.roomId

        # Parse batch size from card input
        batch_size = self.DEFAULT_BATCH_SIZE
        raw_input = (attachment_actions.inputs or {}).get('batch_size', '').strip()
        if raw_input:
            try:
                batch_size = max(1, min(int(raw_input), self.MAX_BATCH_SIZE))
            except ValueError:
                send_message_with_retry(webex_api, room_id=room_id,
                                        markdown=f"⚠️ Invalid batch size '{raw_input}'. Using default of {self.DEFAULT_BATCH_SIZE}.")

        loading_msg = get_random_loading_message()
        send_message_with_retry(webex_api, room_id=room_id,
                                markdown=f"Hello {activity['actor']['displayName']}! {loading_msg}\n\n🏷️ **Removing APAC Ring tag from the next {batch_size} PMLI hosts...**")

        # Find today's PMLI report
        today_date = datetime.now(EASTERN_TZ).strftime('%m-%d-%Y')
        report_dir = ROOT_DIRECTORY / "data" / "transient" / "epp_device_tagging" / today_date
        report_path = report_dir / "Tanium_PMLI_Hosts_cloud.xlsx"

        if not report_path.exists():
            send_message_with_retry(webex_api, room_id=room_id,
                                    markdown="❌ **Error**: PMLI report not found for today. Please run the PMLI hosts report first.")
            return

        try:
            df = pd.read_excel(report_path)
        except Exception as e:
            send_message_with_retry(webex_api, room_id=room_id,
                                    markdown=f"❌ **Error reading PMLI report**: {e}")
            return

        # Filter hosts with APAC ring tags that haven't been processed yet
        apac_ring_pattern = re.compile(r'EPP_ECMTag_APAC_', re.IGNORECASE)
        df['_has_apac_tag'] = df['Current Tags'].fillna('').astype(str).apply(lambda t: bool(apac_ring_pattern.search(t)))
        all_apac_hosts = df[df['_has_apac_tag']].copy()

        already_processed = _load_apac_removal_progress()
        remaining_hosts = all_apac_hosts[~all_apac_hosts['Hostname'].isin(already_processed)]

        if len(remaining_hosts) == 0:
            send_message_with_retry(webex_api, room_id=room_id,
                                    markdown="✅ All PMLI hosts with APAC Ring tags have already been processed. Nothing left to remove!")
            return

        # Filter for hosts seen within last 2 hours (likely online)
        total_before_online_filter = len(remaining_hosts)
        report_file_time = datetime.fromtimestamp(report_path.stat().st_mtime, tz=timezone.utc)
        if 'Last Seen' in remaining_hosts.columns:
            remaining_hosts = remaining_hosts[remaining_hosts['Last Seen'].apply(
                lambda x: is_recently_online(x, report_file_time)
            )]

        if len(remaining_hosts) == 0:
            offline_count = total_before_online_filter
            send_message_with_retry(webex_api, room_id=room_id,
                                    markdown=f"⚠️ **No online PMLI hosts available.** {offline_count:,} hosts have APAC Ring tags but none were seen within 2 hours of report generation. Try running a fresh PMLI report first.")
            return

        # Take the next batch
        batch = remaining_hosts.head(batch_size)
        total_remaining = len(remaining_hosts)

        tanium_client = TaniumClient()
        cloud_instance = tanium_client.get_instance_by_name("Cloud")
        if not cloud_instance:
            send_message_with_retry(webex_api, room_id=room_id,
                                    markdown="❌ **Error**: Could not connect to Tanium Cloud instance.")
            return

        successful = []
        failed = []
        tanium_portal_url = CONFIG.tanium_cloud_ui_url or cloud_instance.server_url

        for _, row in batch.iterrows():
            hostname = str(row['Hostname'])
            tanium_id = str(int(float(row['Tanium ID']))) if row.get('Tanium ID') not in (None, '', float('nan')) else ''
            current_tags_str = str(row.get('Current Tags', ''))

            # Find the specific APAC ring tag(s) on this host
            apac_tags = [t.strip() for t in current_tags_str.split(',')
                         if apac_ring_pattern.search(t.strip())]

            host_ok = True
            for tag in apac_tags:
                try:
                    result = cloud_instance.remove_tag_by_name(hostname, tag)
                    action_data = result.get('action', {})
                    action_id = action_data.get('id', '')
                    scheduled_action_id = action_data.get('scheduledAction', {}).get('id', '')
                    successful.append({'hostname': hostname, 'tag_removed': tag,
                                       'tanium_id': tanium_id, 'action_id': action_id,
                                       'scheduled_action_id': scheduled_action_id})
                except Exception as e:
                    failed.append({'hostname': hostname, 'tag': tag, 'error': str(e),
                                   'tanium_id': tanium_id})
                    logger.warning(f"Failed to remove tag '{tag}' from {hostname}: {e}")
                    host_ok = False

            # Mark host as processed regardless of success/failure (don't retry automatically)
            already_processed.add(hostname)

        _save_apac_removal_progress(already_processed)

        # Build batch report
        batch_count = len(batch)
        new_remaining = total_remaining - batch_count

        summary = f"**APAC Ring Tag Removal — Batch Results**\n\n"
        summary += f"- Hosts in this batch: **{batch_count:,}**\n"
        summary += f"- Tags successfully removed: **{len(successful):,}**\n"
        if failed:
            summary += f"- Failed removals: **{len(failed):,}** _(see attached Excel for details)_\n"
        summary += f"\n- **Remaining online hosts with APAC Ring tag: {new_remaining:,}**"
        if successful:
            summary += "\n\n⏱️ Tag removal actions have been created. Allow ~5 minutes for Tanium to distribute and execute on endpoints before verifying."
        if new_remaining == 0:
            summary += "\n\n✅ **All done!** No more online PMLI hosts with APAC Ring tags."

        # Generate Excel report of processed hosts for analyst verification
        excel_file = None
        try:
            from src.utils.excel_formatting import apply_professional_formatting, add_tanium_hyperlinks

            # Build a DataFrame of processed hosts with their status
            report_rows = []
            success_hostnames = {s['hostname'] for s in successful}
            # Map hostname -> action IDs from successful removals
            action_id_map = {}
            scheduled_action_id_map = {}
            for s in successful:
                if s.get('action_id'):
                    action_id_map[s['hostname']] = s['action_id']
                if s.get('scheduled_action_id'):
                    scheduled_action_id_map[s['hostname']] = s['scheduled_action_id']
            fail_map = {}
            for f_entry in failed:
                fail_map.setdefault(f_entry['hostname'], []).append(f"{f_entry['tag']}: {f_entry['error']}")

            report_cols = ['Hostname', 'Tanium ID', 'Action ID', 'Scheduled Action ID',
                           'IP Address', 'OS Platform', 'Last Seen', 'APAC Tag Removed',
                           'Status', 'Error']
            for _, row in batch.iterrows():
                hostname = str(row['Hostname'])
                tanium_id = str(int(float(row['Tanium ID']))) if row.get('Tanium ID') not in (None, '', float('nan')) else ''
                apac_tags = [t.strip() for t in str(row.get('Current Tags', '')).split(',')
                             if apac_ring_pattern.search(t.strip())]
                status = 'Success' if hostname in success_hostnames else 'Failed'
                error = '; '.join(fail_map.get(hostname, []))
                report_rows.append({
                    'Hostname': hostname,
                    'Tanium ID': tanium_id,
                    'Action ID': action_id_map.get(hostname, ''),
                    'Scheduled Action ID': scheduled_action_id_map.get(hostname, ''),
                    'IP Address': row.get('IP Address', ''),
                    'OS Platform': row.get('OS Platform', ''),
                    'Last Seen': row.get('Last Seen', ''),
                    'APAC Tag Removed': ', '.join(apac_tags),
                    'Status': status,
                    'Error': error,
                })

            report_df = pd.DataFrame(report_rows, columns=report_cols)
            timestamp = datetime.now(EASTERN_TZ).strftime('%H%M%S')
            excel_file = report_dir / f"apac_ring_removal_batch_{timestamp}.xlsx"
            report_df.to_excel(str(excel_file), index=False, engine='openpyxl')
            apply_professional_formatting(
                str(excel_file),
                column_widths={'tanium id': 18, 'action id': 18, 'scheduled action id': 20,
                               'apac tag removed': 40, 'status': 12, 'error': 50},
                wrap_columns={'apac tag removed', 'error'},
            )
            add_tanium_hyperlinks(str(excel_file), portal_url=tanium_portal_url)
        except Exception as e:
            logger.warning(f"Failed to generate APAC removal Excel report: {e}")
            excel_file = None

        files = [str(excel_file)] if excel_file and excel_file.exists() else []
        report_msg = send_message_with_retry(webex_api, room_id=room_id, markdown=summary, files=files)

        # If more hosts remain, show the card again
        if new_remaining > 0 and report_msg:
            _send_apac_removal_card(room_id, new_remaining)


class DontRemoveApacRingTag(Command):
    def __init__(self):
        super().__init__(
            command_keyword="dont_remove_apac_ring_tag",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_tars, log_file_name="tars_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        return f"Alright {activity['actor']['displayName']}, I won't remove the APAC Ring tags. 👋🏾"


# ── MGCC Hosts — APAC Ring Tag Removal ──────────────────────────────────────

class GetTaniumMGCCHosts(Command):
    def __init__(self):
        super().__init__(
            command_keyword="tanium_mgcc_hosts",
            help_message="Get Tanium Cloud MGCC Hosts 🔍🇮🇳",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_tars, log_file_name="tars_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        from src.epp.tanium_mgcc_hosts import create_processor as create_mgcc_processor

        room_id = attachment_actions.roomId
        loading_msg = get_random_loading_message()
        send_message_with_retry(webex_api,
                                room_id=room_id,
                                markdown=(
                                    f"Hello {activity['actor']['displayName']}! {loading_msg}\n\n"
                                    "🔍 **Tanium Cloud MGCC Hosts Report** 🇮🇳\n"
                                    "Fetching APAC-tagged non-PMLI hosts and enriching with ServiceNow data...\n"
                                    f"Estimated completion: {format_eta(15)} ⏰"
                                )
                                )

        lock_path = ROOT_DIRECTORY / "src" / "epp" / "tanium_mgcc_hosts.lock"
        clear_stale_lock(lock_path)
        filepath = None
        try:
            with periodic_progress_pinger(webex_api, room_id), fasteners.InterProcessLock(lock_path):
                processor = create_mgcc_processor(instance_filter="cloud")
                filepath = processor.process(test_limit=None)
        except Exception as e:
            logger.error(f"Error in GetTaniumMGCCHosts execute: {e}")
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
                                    markdown=f"Hello {activity['actor']['displayName']}! ❌ **Error generating MGCC hosts report**: {error_msg}"
                                    )
            return

        # Read report and generate summary
        df = pd.read_excel(filepath)
        total_mgcc = len(df)

        if total_mgcc == 0:
            send_message_with_retry(webex_api,
                                    room_id=room_id,
                                    markdown=f"Hello {activity['actor']['displayName']}! 🎉 **Great news!** No MGCC hosts with APAC ring tags found in Tanium Cloud."
                                    )
            return

        # Count statistics
        import re as _re
        snow_found = len(df[df['SNOW Status'] == 'Found'])
        tags_col = df['Current Tags'].fillna('').astype(str)
        apac_mask = tags_col.apply(lambda t: bool(_re.search(r'EPP_ECMTag_APAC_', t, _re.IGNORECASE)))
        us_mask = tags_col.apply(lambda t: bool(_re.search(r'EPP_ECMTag_US_', t, _re.IGNORECASE)))

        report_file_time = datetime.fromtimestamp(Path(filepath).stat().st_mtime, tz=timezone.utc)
        online_mask = df['Last Seen'].apply(lambda x: is_recently_online(x, report_file_time)) if 'Last Seen' in df.columns else pd.Series([False] * len(df))

        apac_count = int(apac_mask.sum())
        apac_online = int((apac_mask & online_mask).sum())
        us_count = int(us_mask.sum())
        us_online = int((us_mask & online_mask).sum())

        message = f"Hello {activity['actor']['displayName']}! Here's the **Tanium Cloud MGCC Hosts Report** 🇮🇳\n\n"
        message += f"**Summary:**\n"
        message += f"- Total MGCC hosts: **{total_mgcc:,}**\n"
        message += f"  - APAC tagged: {apac_count:,} (online: {apac_online:,})\n"
        message += f"  - US tagged: {us_count:,} (online: {us_online:,})\n"
        message += f"- Found in ServiceNow CMDB: {snow_found:,}\n"

        report_msg = send_message_with_retry(webex_api, room_id=room_id, markdown=message, files=[str(filepath)])

        # All hosts in this report have APAC tags by definition — offer removal
        if report_msg and total_mgcc > 0:
            _reset_mgcc_apac_removal_progress()
            _send_mgcc_apac_removal_card(room_id, total_mgcc, parent_id=report_msg.id)


def _get_mgcc_apac_removal_progress_path() -> Path:
    """Path to the JSON file tracking which MGCC hosts have had APAC tags removed."""
    today_date = datetime.now(EASTERN_TZ).strftime('%m-%d-%Y')
    return ROOT_DIRECTORY / "data" / "transient" / "epp_device_tagging" / today_date / "mgcc_apac_removal_progress.json"


def _load_mgcc_apac_removal_progress() -> set:
    """Load set of MGCC hostnames already processed."""
    import json
    progress_path = _get_mgcc_apac_removal_progress_path()
    if progress_path.exists():
        try:
            data = json.loads(progress_path.read_text())
            return set(data.get('processed_hostnames', []))
        except Exception:
            return set()
    return set()


def _save_mgcc_apac_removal_progress(processed_hostnames: set):
    """Save the set of processed MGCC hostnames."""
    import json
    progress_path = _get_mgcc_apac_removal_progress_path()
    progress_path.parent.mkdir(parents=True, exist_ok=True)
    progress_path.write_text(json.dumps({
        'processed_hostnames': sorted(processed_hostnames),
        'updated_at': datetime.now(EASTERN_TZ).isoformat()
    }, indent=2))


def _reset_mgcc_apac_removal_progress():
    """Reset progress when a new MGCC report is generated."""
    progress_path = _get_mgcc_apac_removal_progress_path()
    if progress_path.exists():
        progress_path.unlink()


def _send_mgcc_apac_removal_card(room_id, remaining_count, parent_id=None):
    """Send the MGCC old ring tag removal approval card."""
    card = AdaptiveCard(
        body=[
            Container(
                items=[
                    TextBlock(
                        text="🇮🇳  MGCC Hosts — Old Ring Tag Removal (APAC/US → MGCC)",
                        size=options.FontSize.LARGE,
                        weight=options.FontWeight.BOLDER,
                        color=options.Colors.LIGHT,
                        horizontalAlignment=HorizontalAlignment.CENTER,
                    ),
                ],
                style=options.ContainerStyle.ACCENT,
                bleed=True,
            ),
            ColumnSet(
                columns=[
                    Column(
                        width="auto",
                        items=[
                            TextBlock(
                                text=f"{remaining_count:,}",
                                size=options.FontSize.EXTRA_LARGE,
                                weight=options.FontWeight.BOLDER,
                                color=options.Colors.ATTENTION,
                                horizontalAlignment=HorizontalAlignment.CENTER,
                            ),
                            TextBlock(
                                text="hosts remaining",
                                size=options.FontSize.SMALL,
                                isSubtle=True,
                                horizontalAlignment=HorizontalAlignment.CENTER,
                                spacing=options.Spacing.NONE,
                            ),
                        ],
                        verticalContentAlignment=VerticalContentAlignment.CENTER,
                    ),
                    Column(
                        width="stretch",
                        items=[
                            TextBlock(
                                text="These MGCC hosts still have an **APAC or US Ring tag** that needs to be removed so the next ring tag job assigns MGCC tags. Only hosts seen online in the last 2 hours will be targeted.",
                                wrap=True,
                            ),
                        ],
                        verticalContentAlignment=VerticalContentAlignment.CENTER,
                    ),
                ],
                separator=True,
                spacing=options.Spacing.MEDIUM,
            ),
            TextBlock(
                text="Batch Size",
                weight=options.FontWeight.BOLDER,
                separator=True,
                spacing=options.Spacing.MEDIUM,
            ),
            TextInput(
                id="batch_size",
                placeholder="Default: 100 (max 500)",
                isRequired=False,
            ),
        ],
        actions=[
            Submit(title="Skip ✋", data={"callback_keyword": "dont_remove_mgcc_apac_ring_tag"},
                   style=options.ActionStyle.DESTRUCTIVE),
            Submit(title="Remove Tags 🏷️", data={"callback_keyword": "remove_mgcc_apac_ring_tag"},
                   style=options.ActionStyle.POSITIVE),
        ],
    )

    kwargs = {}
    if parent_id:
        kwargs['parentId'] = parent_id

    send_card_with_retry(
        webex_api,
        room_id=room_id,
        text="MGCC Hosts — APAC Ring Tag Removal",
        attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}],
        **kwargs
    )


class RemoveApacRingTagMGCC(Command):
    """Remove APAC Ring tags from MGCC hosts per button click."""

    DEFAULT_BATCH_SIZE = 100
    MAX_BATCH_SIZE = 500

    def __init__(self):
        super().__init__(
            command_keyword="remove_mgcc_apac_ring_tag",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_tars, log_file_name="tars_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        import re
        from services.tanium import TaniumClient

        room_id = attachment_actions.roomId

        # Parse batch size from card input
        batch_size = self.DEFAULT_BATCH_SIZE
        raw_input = (attachment_actions.inputs or {}).get('batch_size', '').strip()
        if raw_input:
            try:
                batch_size = max(1, min(int(raw_input), self.MAX_BATCH_SIZE))
            except ValueError:
                send_message_with_retry(webex_api, room_id=room_id,
                                        markdown=f"⚠️ Invalid batch size '{raw_input}'. Using default of {self.DEFAULT_BATCH_SIZE}.")

        loading_msg = get_random_loading_message()
        send_message_with_retry(webex_api, room_id=room_id,
                                markdown=f"Hello {activity['actor']['displayName']}! {loading_msg}\n\n🏷️ **Removing old ring tags (APAC/US) from the next {batch_size} MGCC hosts...**")

        # Find today's MGCC report
        today_date = datetime.now(EASTERN_TZ).strftime('%m-%d-%Y')
        report_dir = ROOT_DIRECTORY / "data" / "transient" / "epp_device_tagging" / today_date
        report_path = report_dir / "Tanium_MGCC_Hosts_cloud.xlsx"

        if not report_path.exists():
            send_message_with_retry(webex_api, room_id=room_id,
                                    markdown="❌ **Error**: MGCC report not found for today. Please run the MGCC hosts report first.")
            return

        try:
            df = pd.read_excel(report_path)
        except Exception as e:
            send_message_with_retry(webex_api, room_id=room_id,
                                    markdown=f"❌ **Error reading MGCC report**: {e}")
            return

        # Filter hosts with APAC or US ring tags that haven't been processed yet
        old_tag_pattern = re.compile(r'EPP_ECMTag_(APAC|US)_', re.IGNORECASE)
        df['_has_old_tag'] = df['Current Tags'].fillna('').astype(str).apply(lambda t: bool(old_tag_pattern.search(t)))
        all_old_tag_hosts = df[df['_has_old_tag']].copy()

        already_processed = _load_mgcc_apac_removal_progress()
        remaining_hosts = all_old_tag_hosts[~all_old_tag_hosts['Hostname'].isin(already_processed)]

        if len(remaining_hosts) == 0:
            send_message_with_retry(webex_api, room_id=room_id,
                                    markdown="✅ All MGCC hosts with old ring tags have already been processed. Nothing left to remove!")
            return

        # Filter for hosts seen within last 2 hours (likely online)
        total_before_online_filter = len(remaining_hosts)
        report_file_time = datetime.fromtimestamp(report_path.stat().st_mtime, tz=timezone.utc)
        if 'Last Seen' in remaining_hosts.columns:
            remaining_hosts = remaining_hosts[remaining_hosts['Last Seen'].apply(
                lambda x: is_recently_online(x, report_file_time)
            )]

        if len(remaining_hosts) == 0:
            offline_count = total_before_online_filter
            send_message_with_retry(webex_api, room_id=room_id,
                                    markdown=f"⚠️ **No online MGCC hosts available.** {offline_count:,} hosts have old ring tags but none were seen within 2 hours of report generation. Try running a fresh MGCC report first.")
            return

        # Take the next batch
        batch = remaining_hosts.head(batch_size)
        total_remaining = len(remaining_hosts)

        tanium_client = TaniumClient()
        cloud_instance = tanium_client.get_instance_by_name("Cloud")
        if not cloud_instance:
            send_message_with_retry(webex_api, room_id=room_id,
                                    markdown="❌ **Error**: Could not connect to Tanium Cloud instance.")
            return

        successful = []
        failed = []
        tanium_portal_url = CONFIG.tanium_cloud_ui_url or cloud_instance.server_url

        for _, row in batch.iterrows():
            hostname = str(row['Hostname'])
            tanium_id = str(int(float(row['Tanium ID']))) if row.get('Tanium ID') not in (None, '', float('nan')) else ''
            current_tags_str = str(row.get('Current Tags', ''))

            # Find the specific APAC/US ring tag(s) on this host
            old_tags = [t.strip() for t in current_tags_str.split(',')
                        if old_tag_pattern.search(t.strip())]

            host_ok = True
            for tag in old_tags:
                try:
                    result = cloud_instance.remove_tag_by_name(hostname, tag)
                    action_data = result.get('action', {})
                    action_id = action_data.get('id', '')
                    scheduled_action_id = action_data.get('scheduledAction', {}).get('id', '')
                    successful.append({'hostname': hostname, 'tag_removed': tag,
                                       'tanium_id': tanium_id, 'action_id': action_id,
                                       'scheduled_action_id': scheduled_action_id})
                except Exception as e:
                    failed.append({'hostname': hostname, 'tag': tag, 'error': str(e),
                                   'tanium_id': tanium_id})
                    logger.warning(f"Failed to remove tag '{tag}' from {hostname}: {e}")
                    host_ok = False

            # Mark host as processed regardless of success/failure (don't retry automatically)
            already_processed.add(hostname)

        _save_mgcc_apac_removal_progress(already_processed)

        # Build batch report
        batch_count = len(batch)
        new_remaining = total_remaining - batch_count

        summary = f"**MGCC — Old Ring Tag Removal — Batch Results**\n\n"
        summary += f"- Hosts in this batch: **{batch_count:,}**\n"
        summary += f"- Tags successfully removed: **{len(successful):,}**\n"
        if failed:
            summary += f"- Failed removals: **{len(failed):,}** _(see attached Excel for details)_\n"
        summary += f"\n- **Remaining online hosts with old ring tags: {new_remaining:,}**"
        if successful:
            summary += "\n\n⏱️ Tag removal actions have been created. Allow ~5 minutes for Tanium to distribute and execute on endpoints before verifying."
        if new_remaining == 0:
            summary += "\n\n✅ **All done!** No more online MGCC hosts with old ring tags."

        # Generate Excel report of processed hosts for analyst verification
        excel_file = None
        try:
            from src.utils.excel_formatting import apply_professional_formatting, add_tanium_hyperlinks

            report_rows = []
            success_hostnames = {s['hostname'] for s in successful}
            action_id_map = {}
            scheduled_action_id_map = {}
            for s in successful:
                if s.get('action_id'):
                    action_id_map[s['hostname']] = s['action_id']
                if s.get('scheduled_action_id'):
                    scheduled_action_id_map[s['hostname']] = s['scheduled_action_id']
            fail_map = {}
            for f_entry in failed:
                fail_map.setdefault(f_entry['hostname'], []).append(f"{f_entry['tag']}: {f_entry['error']}")

            report_cols = ['Hostname', 'Tanium ID', 'Action ID', 'Scheduled Action ID',
                           'IP Address', 'OS Platform', 'Last Seen', 'Old Tag Removed',
                           'Status', 'Error']
            for _, row in batch.iterrows():
                hostname = str(row['Hostname'])
                tanium_id = str(int(float(row['Tanium ID']))) if row.get('Tanium ID') not in (None, '', float('nan')) else ''
                old_tags = [t.strip() for t in str(row.get('Current Tags', '')).split(',')
                            if old_tag_pattern.search(t.strip())]
                status = 'Success' if hostname in success_hostnames else 'Failed'
                error = '; '.join(fail_map.get(hostname, []))
                report_rows.append({
                    'Hostname': hostname,
                    'Tanium ID': tanium_id,
                    'Action ID': action_id_map.get(hostname, ''),
                    'Scheduled Action ID': scheduled_action_id_map.get(hostname, ''),
                    'IP Address': row.get('IP Address', ''),
                    'OS Platform': row.get('OS Platform', ''),
                    'Last Seen': row.get('Last Seen', ''),
                    'Old Tag Removed': ', '.join(old_tags),
                    'Status': status,
                    'Error': error,
                })

            report_df = pd.DataFrame(report_rows, columns=report_cols)
            timestamp = datetime.now(EASTERN_TZ).strftime('%H%M%S')
            excel_file = report_dir / f"mgcc_old_ring_removal_batch_{timestamp}.xlsx"
            report_df.to_excel(str(excel_file), index=False, engine='openpyxl')
            apply_professional_formatting(
                str(excel_file),
                column_widths={'tanium id': 18, 'action id': 18, 'scheduled action id': 20,
                               'old tag removed': 40, 'status': 12, 'error': 50},
                wrap_columns={'old tag removed', 'error'},
            )
            add_tanium_hyperlinks(str(excel_file), portal_url=tanium_portal_url)
        except Exception as e:
            logger.warning(f"Failed to generate MGCC tag removal Excel report: {e}")
            excel_file = None

        files = [str(excel_file)] if excel_file and excel_file.exists() else []
        report_msg = send_message_with_retry(webex_api, room_id=room_id, markdown=summary, files=files)

        # If more hosts remain, show the card again
        if new_remaining > 0 and report_msg:
            _send_mgcc_apac_removal_card(room_id, new_remaining)


class DontRemoveApacRingTagMGCC(Command):
    def __init__(self):
        super().__init__(
            command_keyword="dont_remove_mgcc_apac_ring_tag",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_tars, log_file_name="tars_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        return f"Alright {activity['actor']['displayName']}, I won't remove the MGCC APAC Ring tags. 👋🏾"


class GetTaniumHostsWithInvalidRingTags(Command):
    def __init__(self):
        super().__init__(
            command_keyword="tanium_invalid_ring_tag",
            help_message="Get Tanium Cloud Hosts with Invalid Ring Tags 🛡️❌💍",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_tars, log_file_name="tars_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        from src.epp.tanium_hosts_with_invalid_ring_tags import generate_report

        room_id = attachment_actions.roomId
        loading_msg = get_random_loading_message()
        send_message_with_retry(webex_api,
                                room_id=room_id,
                                markdown=(
                                    f"Hello {activity['actor']['displayName']}! {loading_msg}\n\n"
                                    "🛡️ **Tanium Cloud Hosts with Invalid Ring Tags Report** ❌💍\n"
                                    "Fetching all hosts, enriching with ServiceNow, validating ring tags (environment + region)...\n"
                                    f"Estimated completion: {format_eta(60)} ⏰ (ServiceNow enrichment dominates — "
                                    "I'll ping you at each stage)"
                                )
                                )

        def _send_progress(msg):
            send_message_with_retry(webex_api, room_id=room_id, markdown=f"⏳ {msg}")

        lock_path = ROOT_DIRECTORY / "src" / "epp" / "tanium_invalid_ring_tags.lock"
        clear_stale_lock(lock_path)
        filepath = None
        try:
            with periodic_progress_pinger(webex_api, room_id), fasteners.InterProcessLock(lock_path):
                filepath = generate_report(
                    instance_filter="cloud",
                    progress_callback=_send_progress,
                )
        except Exception as e:
            logger.error(f"Error in GetTaniumHostsWithInvalidRingTags execute: {e}")
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
            send_message_with_retry(webex_api,
                                    room_id=room_id,
                                    markdown=f"Hello {activity['actor']['displayName']}! 🎉 **Great news!** No Tanium Cloud hosts with invalid ring tags found."
                                    )
            return

        df = pd.read_excel(filepath)
        total_invalid = len(df)

        comment_col = df['comment'].fillna('').astype(str)
        env_mismatch = int(comment_col.str.contains('should be Ring', case=False).sum())
        region_mismatch = int(comment_col.str.contains('region', case=False).sum())
        multiple_tags = int(comment_col.str.contains('multiple', case=False).sum())

        message = f"Hello {activity['actor']['displayName']}! Here's the **Tanium Cloud Hosts with Invalid Ring Tags Report** 🛡️❌💍\n\n"
        message += f"**Summary:**\n"
        message += f"- Total hosts with invalid ring tags: **{total_invalid:,}**\n"
        if env_mismatch > 0:
            message += f"  - Environment-ring mismatch (servers): {env_mismatch:,}\n"
        if region_mismatch > 0:
            message += f"  - Country-region mismatch: {region_mismatch:,}\n"
        if multiple_tags > 0:
            message += f"  - Multiple ring tags: {multiple_tags:,}\n"

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

        status_card = create_bot_health_card("the threat-intel service", current_time)

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
    """Create the threat-intel service bot instance"""
    cleanup_devices_on_startup(
        CONFIG.webex_bot_access_token_tars,
        bot_name="the threat-intel service"
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

    return RoomGatedWebexBot(
        CONFIG.webex_bot_access_token_tars,
        approved_domains=[CONFIG.my_web_domain],
        approved_users=approved_bot_emails,
        allowed_room_ids=[
            CONFIG.webex_room_id_epp_tanium_cloud_tagging,
            CONFIG.webex_room_id_epp_tanium_onprem_tagging,
            CONFIG.webex_room_id_dev_test_space,
        ],
        bot_name="the threat-intel service - The Tanium Cloud Assistant",
        threads=True,
        log_level="ERROR",
        bot_help_subtitle="Your friendly Tanium Cloud tagging bot!",
        allow_bot_to_bot=True
    )


def tars_initialization(bot):
    """Initialize the threat-intel service commands"""
    if bot:
        bot.add_command(GetTaniumHostsWithoutRingTag())
        bot.add_command(RingTagTaniumHosts())  # Hidden - triggered via adaptive card
        bot.add_command(DontRingTagTaniumHosts())  # Hidden - triggered via adaptive card
        bot.add_command(StopAutomatedTaniumRingTagging())  # Hidden - triggered via adaptive card
        bot.add_command(GetTaniumUnhealthyHosts())
        bot.add_command(GetTaniumPMLIHosts())
        bot.add_command(RemoveApacRingTag())  # Hidden - triggered via adaptive card
        bot.add_command(DontRemoveApacRingTag())  # Hidden - triggered via adaptive card
        bot.add_command(GetTaniumMGCCHosts())
        bot.add_command(RemoveApacRingTagMGCC())  # Hidden - triggered via adaptive card
        bot.add_command(DontRemoveApacRingTagMGCC())  # Hidden - triggered via adaptive card
        bot.add_command(GetTaniumHostsWithInvalidRingTags())
        bot.add_command(Hi())
        return True
    return False


def _shutdown_handler(_signum=None, _frame=None):
    """Log shutdown marker before exit"""
    logger.warning("=" * 100)
    logger.warning(f"🛑 the threat-intel service BOT STOPPED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.warning("=" * 100)


def main():
    """the threat-intel service main - Tanium Cloud tagging bot"""
    logger.info("Starting the threat-intel service with basic WebexBot")

    atexit.register(_shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    bot = tars_bot_factory()
    tars_initialization(bot)

    logger.info("🚀 the threat-intel service is up and running...")
    print("🚀 the threat-intel service is up and running...", flush=True)
    bot.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
