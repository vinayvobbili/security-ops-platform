#!/usr/bin/python3
"""
Job scheduler for security operations automation.

Runs scheduled tasks for chart generation, shift announcements, SLA monitoring,
and other operational workflows. All jobs are wrapped in error handling to ensure
scheduler resilience.
"""

import logging
import os
import sys
import warnings
from pathlib import Path

# Suppress noisy library loggers BEFORE imports to prevent startup spam
# Set to WARNING to hide INFO/DEBUG but still show errors and warnings
logging.getLogger("webexpythonsdk.restsession").setLevel(logging.WARNING)
logging.getLogger("webexteamssdk.restsession").setLevel(logging.WARNING)
logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
warnings.filterwarnings("ignore", category=UserWarning, module="openpyxl")

sys.path.insert(0, str(Path(__file__).parent.parent))
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import Callable, Iterable, List

import pytz
import schedule

import secops
from my_config import get_config
from src.components.ticket_cache import TicketCache
from src import helper_methods, verify_host_online_status
from src.charts import (
    mttr_mttc, outflow, lifespan, heatmap, sla_breaches, aging_tickets,
    inflow, qradar_rule_efficacy, de_stories, days_since_incident, re_stories,
    threatcon_level, vectra_volume, crowdstrike_volume, threat_tippers,
    crowdstrike_efficacy
)
from src.components import (
    oncall, approved_security_testing, thithi, response_sla_risk_tickets,
    containment_sla_risk_tickets, incident_declaration_sla_risk, abandoned_tickets,
    orphaned_tickets, birthdays_anniversaries, stale_containment_cleanup, ticket_pattern_analysis
)
from src.components.tipper_analyzer.rules.sync import sync_catalog
from src.components.tipper_analyzer import analyze_recent_tippers
from src.components.tipper_indexer import sync_tipper_index
from src.components.tanium_signals_sync import sync_tanium_signals_catalog
from src.utils.webex_utils import get_room_name
from webex_bots.jarvis import run_automated_ring_tagging_workflow
from webex_bots.tars import run_automated_ring_tagging_workflow as run_automated_tanium_ring_tagging_workflow
from src.components import domain_monitoring
from services import phish_fort
from src.utils.fs_utils import make_dir_for_todays_charts, cleanup_old_transient_data
from src.utils.logging_utils import setup_logging
from src import peer_ping_keepalive

# Configure logging with centralized utility
setup_logging(
    bot_name='all_jobs',
    log_level=logging.INFO,  # Default level for most modules
    info_modules=['__main__', 'src.components.response_sla_risk_tickets', 'services.xsoar'],
    rotate_on_startup=False  # Keep logs continuous, rely on RotatingFileHandler for size-based rotation
)

# Set XSOAR logging to INFO (connection issues have been resolved)
logging.getLogger("services.xsoar").setLevel(logging.INFO)

# Set ticket_cache to DEBUG for nightly failure diagnosis
logging.getLogger("src.components.ticket_cache").setLevel(logging.DEBUG)

logger = logging.getLogger(__name__)

# Log clear startup marker for visual separation in logs
import signal
import atexit
from datetime import datetime

logger.warning("=" * 100)
logger.warning(f"🚀 ALL_JOBS SCHEDULER STARTED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
logger.warning("=" * 100)

config = get_config()
eastern = pytz.timezone('US/Eastern')

# Default per-job timeout (seconds)
DEFAULT_JOB_TIMEOUT = 1800  # 30 minutes
TICKET_CACHE_TIMEOUT = 21600  # 360 minutes (6 hours) for ticket enrichment job on VM

# Webex notification helper for access issues
_webex_api = None


def _get_webex_api():
    """Lazy-load Webex API client."""
    global _webex_api
    if _webex_api is None:
        try:
            from webexpythonsdk import WebexAPI
            if config.webex_bot_access_token_pokedex:
                _webex_api = WebexAPI(access_token=config.webex_bot_access_token_pokedex)
        except Exception as e:
            logger.warning(f"Failed to initialize Webex API: {e}")
    return _webex_api


def notify_access_issue(job_name: str, issues: list, room_id: str = None) -> None:
    """Send Webex notification about access/permission issues.

    Args:
        job_name: Name of the job that encountered issues
        issues: List of access issue messages
        room_id: Optional room ID (defaults to tipper analysis room)
    """
    if not issues:
        return

    target_room = room_id or config.webex_room_id_threat_tipper_analysis

    if not target_room:
        logger.warning(f"Cannot send access issue notification - no room configured")
        return

    webex = _get_webex_api()
    if not webex:
        logger.warning(f"Cannot send access issue notification - Webex API not available")
        return

    try:
        msg = f"⚠️ **Access Issues in {job_name}**\n\n"
        for issue in issues:
            msg += f"- {issue}\n"
        msg += f"\n_Reported at {datetime.now().strftime('%Y-%m-%d %H:%M:%S ET')}_"

        webex.messages.create(roomId=target_room, markdown=msg)
        logger.info(f"Sent access issue notification for {job_name}")
    except Exception as e:
        logger.error(f"Failed to send access issue notification: {e}")


def sync_catalog_with_notifications() -> None:
    """Sync detection rules catalog and notify on access issues."""
    result = sync_catalog()

    # Collect access issues from platform sync results
    access_issues = []
    for platform_status in result.platforms:
        if not platform_status.success and platform_status.error:
            error_lower = platform_status.error.lower()
            if 'auth' in error_lower or 'permission' in error_lower or 'access' in error_lower or 'forbidden' in error_lower:
                access_issues.append(f"{platform_status.platform}: {platform_status.error}")
        elif platform_status.error and 'using cache' in platform_status.error.lower():
            access_issues.append(f"{platform_status.platform}: API unavailable (using cached rules)")

    if access_issues:
        notify_access_issue("Rules Catalog Sync", access_issues)


def sync_tanium_signals_with_notifications() -> None:
    """Sync Tanium signals catalog and notify on access issues."""
    result = sync_tanium_signals_catalog()

    access_issues = []
    if result.get('skipped'):
        for error in result.get('errors', []):
            if 'permission' in error.lower() or 'no tanium' in error.lower() or 'token' in error.lower():
                access_issues.append(error)

    if result.get('signals_count', 0) == 0 and not result.get('skipped'):
        access_issues.append("No signals fetched from Tanium - check API permissions")

    if access_issues:
        notify_access_issue("Tanium Signals Sync", access_issues)


# Note: VM with slow network takes 2-4 hours for 12k tickets with note enrichment
# Generous timeout prevents premature termination of this critical nightly job


def _run_job_with_timeout(job: Callable[[], None], job_name: str, timeout: int) -> None:
    """Internal: Run a single job with timeout protection."""
    executor = None
    start_time = time.time()
    logger.debug(f">>> Starting job: {job_name}")
    try:
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(job)
        try:
            future.result(timeout=timeout)
            elapsed = time.time() - start_time
            logger.debug(f"<<< Job completed successfully: {job_name} (took {elapsed:.2f}s)")
        except FuturesTimeoutError:
            elapsed = time.time() - start_time
            logger.error(f"Job timed out after {timeout} seconds: {job_name} (elapsed {elapsed:.2f}s)")
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"Job execution failed for {job_name} after {elapsed:.2f}s: {e}")
        logger.debug(traceback.format_exc())
    finally:
        if executor:
            executor.shutdown(wait=False)


def safe_run(*jobs: Callable[[], None], timeout: int = DEFAULT_JOB_TIMEOUT, name: str = None, blocking: bool = True) -> None:
    """Execute multiple jobs safely with timeout protection, continuing even if some fail.

    Sequentially runs each provided job. Each job is isolated with its own ThreadPoolExecutor
    to enforce a timeout and prevent the entire scheduler from hanging.

    Args:
        *jobs: One or more callable jobs to execute
        timeout: Maximum execution time per job in seconds
        name: Optional descriptive name for the job(s) in logs (overrides auto-detected names)
        blocking: If False, run jobs in background thread (won't block scheduler)
    """
    import threading
    if not jobs:
        logger.debug("safe_run() called with 0 jobs - nothing to do")
        return
    logger.debug(f"safe_run() running {len(jobs)} job(s) with timeout={timeout}s, blocking={blocking}")

    def run_all_jobs():
        for i, job in enumerate(jobs):
            # Use provided name, or try to extract function name, or fall back to repr
            if name:
                job_name = name if len(jobs) == 1 else f"{name}[{i + 1}/{len(jobs)}]"
            else:
                job_name = getattr(job, '__name__', repr(job))
            _run_job_with_timeout(job, job_name, timeout)

    if blocking:
        run_all_jobs()
    else:
        # Run in background daemon thread - won't block scheduler
        thread = threading.Thread(target=run_all_jobs, daemon=True)
        thread.start()
        logger.debug(f"Job(s) started in background thread")


# ----------------------------------------------------------------------------------
# Helper functions for cleaner scheduling
# ----------------------------------------------------------------------------------

def schedule_daily(time_str: str, *jobs: Callable[[], None], name: str = None) -> None:
    """Schedule a set of jobs to run daily at a given time (Eastern).

    Args:
        time_str: Time in 'HH:MM' format (Eastern timezone)
        *jobs: One or more callable jobs to execute
        name: Optional descriptive name for logs
    """
    schedule.every().day.at(time_str, eastern).do(lambda: safe_run(*jobs, name=name))


def schedule_group(time_str: str, name: str, jobs: Iterable[Callable[[], None]]) -> None:
    """Schedule a named group of jobs and log registration."""
    job_list = list(jobs)
    logger.info(f"Scheduling {name} ({len(job_list)} job(s)) at {time_str} ET")
    schedule_daily(time_str, *job_list, name=name)


def schedule_shift(time_str: str, shift_name: str, room_id: str) -> None:
    """Schedule a shift change announcement."""
    schedule_daily(time_str, lambda: secops.announce_shift_change(shift_name, room_id), name=f"shift_{shift_name}")


def schedule_sla(interval: str, job: Callable[[], None], name: str, timeout: int) -> None:
    """Schedule SLA job based on interval descriptor.

    Interval formats supported:
    - 'minutes:<n>'   -> every n minutes
    - 'hourly:00'     -> every hour at :00

    Args:
        interval: Interval descriptor (e.g., 'minutes:1', 'hourly:00')
        job: Callable job to schedule
        name: Descriptive name for logs (required)
        timeout: Timeout in seconds (required - should be less than interval to prevent overlap)
    """
    kind, value = interval.split(':', 1)

    if kind == 'minutes':
        schedule.every(int(value)).minutes.do(lambda: safe_run(job, name=name, timeout=timeout))
    elif kind == 'hourly':
        schedule.every().hour.at(f":{value}").do(lambda: safe_run(job, name=name, timeout=timeout))
    else:
        logger.error(f"Unsupported SLA interval format: {interval}")


def schedule_business_hours(
        minute: int,
        job: Callable[[], None],
        name: str = None,
        timeout: int = DEFAULT_JOB_TIMEOUT,
        start_hour: int = 9,
        end_hour: int = 18
) -> None:
    """Schedule a job to run during US business hours (Mon-Fri, Eastern timezone).

    Args:
        minute: Minute of the hour to run (0-59)
        job: Callable job to execute
        name: Optional descriptive name for logs
        timeout: Job timeout in seconds
        start_hour: First hour to run (inclusive, 24-hour format)
        end_hour: Last hour to run (inclusive, 24-hour format)
    """
    job_name = name or job.__name__
    for hour in range(start_hour, end_hour + 1):
        time_str = f"{hour:02d}:{minute:02d}"
        schedule.every().monday.at(time_str, eastern).do(lambda j=job, t=timeout, n=name: safe_run(j, timeout=t, name=n))
        schedule.every().tuesday.at(time_str, eastern).do(lambda j=job, t=timeout, n=name: safe_run(j, timeout=t, name=n))
        schedule.every().wednesday.at(time_str, eastern).do(lambda j=job, t=timeout, n=name: safe_run(j, timeout=t, name=n))
        schedule.every().thursday.at(time_str, eastern).do(lambda j=job, t=timeout, n=name: safe_run(j, timeout=t, name=n))
        schedule.every().friday.at(time_str, eastern).do(lambda j=job, t=timeout, n=name: safe_run(j, timeout=t, name=n))
    logger.info(f"Scheduled '{job_name}' Mon-Fri {start_hour}:00-{end_hour}:00 ET at :{minute:02d}")


# ----------------------------------------------------------------------------------
# Data-driven configuration for chart groups
# ----------------------------------------------------------------------------------
CHART_GROUPS: List[dict] = [
    {
        'time': '00:02',
        'name': 'Group 1: Basic metrics charts',
        'jobs': [
            aging_tickets.make_chart,
            inflow.make_chart,
            outflow.make_chart,
            mttr_mttc.make_chart,
            sla_breaches.make_chart,
            threatcon_level.make_chart,  # Generate before DOR so chart is available
            lambda: secops.send_daily_operational_report_charts(get_config().webex_room_id_metrics)
        ]
    },
    {
        'time': '00:07',
        'name': 'Group 2: Efficacy & volume charts',
        'jobs': [
            crowdstrike_efficacy.make_chart,
            crowdstrike_volume.make_chart,
            qradar_rule_efficacy.make_chart,
            vectra_volume.make_chart,
            lifespan.make_chart,
        ]
    },
    {
        'time': '00:12',
        'name': 'Group 3: Story & status charts',
        'jobs': [
            de_stories.make_chart,
            re_stories.make_chart,
            days_since_incident.make_chart,
            threat_tippers.make_chart,
        ]
    },
    {
        'time': '00:17',
        'name': 'Group 4: Complex/slow charts',
        'jobs': [
            heatmap.create_choropleth_map,
        ]
    },
]


def _shutdown_handler(_signum=None, _frame=None):
    """Log shutdown marker before exit."""
    logger.warning("=" * 100)
    logger.warning(f"🛑 ALL_JOBS SCHEDULER STOPPED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.warning("=" * 100)


def main() -> None:
    """Configure and start the job scheduler."""
    print("Starting crash-proof job scheduler...")
    logger.info("Initializing security operations scheduler")

    # Register shutdown handlers for graceful logging
    atexit.register(_shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    # Directory preparation (first, fast)
    logger.info("Scheduling daily chart directory preparation...")
    schedule_daily('00:01', lambda: make_dir_for_todays_charts(helper_methods.CHARTS_DIR_PATH), name="chart_dir_prep")

    # Cleanup old transient data (secOps and charts folders older than 30 days)
    logger.info("Scheduling daily cleanup of old transient data (02:00 ET)...")
    schedule_daily('02:00', lambda: cleanup_old_transient_data() or None, name="transient_data_cleanup")

    # Note: Tipper jobs now run here on lab-vm (previously in home_jobs.py)

    # Chart groups (data-driven)
    for group in CHART_GROUPS:
        schedule_group(group['time'], group['name'], group['jobs'])

    # Ticket cache - RUNS LAST to avoid interfering with chart generation
    # Scheduled after all chart jobs complete (charts finish by ~00:30)
    # Extended timeout (6 hours) accommodates slow VM network with full note enrichment
    logger.info("Scheduling ticket cache generation at 01:00 ET (runs last, may take 2-4 hours on VM)...")

    def ticket_cache_with_logging():
        logger.info("=" * 60)
        logger.info("TICKET CACHE JOB STARTING at 01:00 ET")
        logger.info("=" * 60)
        safe_run(TicketCache.generate, timeout=TICKET_CACHE_TIMEOUT, name="ticket_cache")
        logger.info("=" * 60)
        logger.info("TICKET CACHE JOB COMPLETED")
        logger.info("=" * 60)

    schedule.every().day.at('01:00', eastern).do(ticket_cache_with_logging)

    # Host verification
    logger.info("Scheduling host verification every 5 minutes...")
    schedule.every(5).minutes.do(lambda: safe_run(verify_host_online_status.start, name="host_online_verification"))

    # Peer ping keepalive for bot NAT paths
    logger.info("Scheduling peer ping keepalive Hi messages...")
    schedule.every(5).minutes.do(
        lambda: safe_run(lambda: peer_ping_keepalive.send_peer_pings(config.webex_bot_access_token_pinger), name="peer_ping_keepalive")
    )

    # Shift changes
    logger.info("Scheduling shift change announcements...")
    shift_room = config.webex_room_id_soc_shift_updates
    schedule_shift('04:30', 'morning', shift_room)
    schedule_shift('12:30', 'afternoon', shift_room)
    schedule_shift('20:30', 'night', shift_room)

    # Weekly reports (Friday)
    logger.info("Scheduling weekly efficacy report (Friday 08:00 ET)...")
    schedule.every().friday.at('08:00', eastern).do(lambda: safe_run(
        qradar_rule_efficacy.send_charts,
        crowdstrike_efficacy.send_charts,
        name="weekly_efficacy_report"
    ))

    # On-call management
    logger.info("Scheduling on-call management (Fri alert, Mon announce)...")
    schedule.every().friday.at('14:00', eastern).do(lambda: safe_run(oncall.alert_change, name="oncall_alert"))
    schedule.every().monday.at('08:00', eastern).do(lambda: safe_run(oncall.announce_change, name="oncall_announce"))

    # Automated Crowdstrike ring tagging (Mon/Thu 9 AM ET)
    # Timeout: 90 min (60 min safety window + 30 min for tagging), non-blocking
    logger.info("Scheduling automated Crowdstrike ring tagging (Mon/Thu 09:00 ET)...")
    schedule.every().monday.at('09:00', eastern).do(
        lambda: safe_run(run_automated_ring_tagging_workflow, name="automated_cs_ring_tagging_monday", timeout=5400, blocking=False)
    )
    schedule.every().thursday.at('09:00', eastern).do(
        lambda: safe_run(run_automated_ring_tagging_workflow, name="automated_cs_ring_tagging_thursday", timeout=5400, blocking=False)
    )

    # Automated Tanium Cloud ring tagging (Mon/Thu at 4 AM, 12 PM, 8 PM ET)
    # Timeout: 90 min (60 min safety window + 30 min for tagging), non-blocking
    logger.info("Scheduling automated Tanium Cloud ring tagging (Mon/Thu 04:00, 12:00, 20:00 ET)...")
    schedule.every().monday.at('04:00', eastern).do(
        lambda: safe_run(run_automated_tanium_ring_tagging_workflow, name="automated_tanium_ring_tagging_mon_04am", timeout=5400, blocking=False)
    )
    schedule.every().monday.at('12:00', eastern).do(
        lambda: safe_run(run_automated_tanium_ring_tagging_workflow, name="automated_tanium_ring_tagging_mon_12pm", timeout=5400, blocking=False)
    )
    schedule.every().monday.at('20:00', eastern).do(
        lambda: safe_run(run_automated_tanium_ring_tagging_workflow, name="automated_tanium_ring_tagging_mon_08pm", timeout=5400, blocking=False)
    )
    schedule.every().thursday.at('04:00', eastern).do(
        lambda: safe_run(run_automated_tanium_ring_tagging_workflow, name="automated_tanium_ring_tagging_thu_04am", timeout=5400, blocking=False)
    )
    schedule.every().thursday.at('12:00', eastern).do(
        lambda: safe_run(run_automated_tanium_ring_tagging_workflow, name="automated_tanium_ring_tagging_thu_12pm", timeout=5400, blocking=False)
    )
    schedule.every().thursday.at('20:00', eastern).do(
        lambda: safe_run(run_automated_tanium_ring_tagging_workflow, name="automated_tanium_ring_tagging_thu_08pm", timeout=5400, blocking=False)
    )

    # Daily maintenance
    logger.info("Scheduling daily maintenance tasks...")
    schedule_daily('17:00', approved_security_testing.removed_expired_entries)
    schedule_daily('07:00', thithi.main)
    schedule_daily('08:00',
                   lambda: abandoned_tickets.send_report(config.webex_room_id_abandoned_tickets),
                   lambda: orphaned_tickets.send_report(config.webex_room_id_abandoned_tickets)
                   )

    # Stale containment cleanup - removes hosts from containment list when their ticket is closed
    logger.info("Scheduling stale containment cleanup (18:00 ET)...")
    schedule_daily('18:00', stale_containment_cleanup.cleanup_stale_containments, name="stale_containment_cleanup")

    # Birthday and anniversary celebrations
    logger.info("Scheduling daily birthday/anniversary check (08:00 ET)...")
    schedule_daily('08:00', birthdays_anniversaries.daily_celebration_check, name="birthday_anniversary_check")

    # Domain lookalike, dark web, and brand impersonation monitoring
    # Includes CT log search for semantic attacks (acme-loan.com) via crt.sh
    logger.info("Scheduling daily domain monitoring (08:00 ET)...")
    schedule_daily('08:00',
                   lambda: domain_monitoring.run_daily_monitoring(room_id=domain_monitoring.ALERT_ROOM_ID_PROD),
                   name="domain_monitoring")

    # Detection rules catalog sync - refreshes CrowdStrike and QRadar rules
    # Populates cache files used by /detection-rules web page
    # Uses notification wrapper to alert on access issues
    logger.info("Scheduling daily detection rules sync (02:00 ET)...")
    schedule_daily('02:00', sync_catalog_with_notifications, name="detection_rules_sync")

    # Tanium signals catalog sync - refreshes Tanium signals cache
    # Uses notification wrapper to alert on access issues
    logger.info("Scheduling daily Tanium signals sync (02:05 ET)...")
    schedule_daily('02:05', sync_tanium_signals_with_notifications, name="tanium_signals_sync")

    # Tipper index sync - indexes new tippers for similarity search in ChromaDB
    # Looks back 7 days to catch any missed tippers
    logger.info("Scheduling daily tipper index sync (02:10 ET)...")
    schedule_daily('02:10', lambda: sync_tipper_index(days_back=7), name="tipper_index_sync")

    # Hourly tipper analysis - analyzes new tippers and sends to Webex
    # Runs at :15 past each hour during US business hours (9 AM - 6 PM ET)
    # Controlled by ENABLE_HOURLY_TIPPER_ANALYSIS env var (default: disabled)
    tipper_analysis_room = config.webex_room_id_threat_tipper_analysis
    if tipper_analysis_room:
        room_name = get_room_name(tipper_analysis_room, config.webex_bot_access_token_pokedex) or "Unknown"
        logger.info(f"Tipper analysis will send to room: {room_name}")
    if os.environ.get("ENABLE_HOURLY_TIPPER_ANALYSIS", "false").lower() == "true":
        schedule_business_hours(
            15,
            lambda: analyze_recent_tippers(hours_back=1, room_id=tipper_analysis_room),
            name="business_hours_tipper_analysis",
            timeout=900  # 15 min timeout
        )
        logger.info("Hourly tipper analysis ENABLED")
    else:
        logger.info("Hourly tipper analysis DISABLED (set ENABLE_HOURLY_TIPPER_ANALYSIS=true to enable)")

    # PhishFort incident report - weekly summary of active phishing takedowns
    logger.info("Scheduling weekly PhishFort incident report (Monday 09:00 ET)...")
    schedule.every().monday.at('09:00', eastern).do(
        lambda: safe_run(lambda: phish_fort.fetch_and_report_incidents(room_id=config.webex_room_id_phish_fort), name="phishfort_report")
    )

    # Weekly ticket pattern analysis - identifies top offenders and creates AZDO user story
    logger.info("Scheduling weekly ticket pattern analysis (Monday 07:00 ET)...")
    schedule.every().monday.at('07:00', eastern).do(
        lambda: safe_run(ticket_pattern_analysis.run, name="ticket_pattern_analysis", timeout=1800)
    )

    # SLA risk monitoring
    logger.info("Scheduling SLA risk monitoring jobs...")
    schedule_sla('minutes:1', lambda: response_sla_risk_tickets.start(config.webex_room_id_response_sla_risk), name="response_sla_risk", timeout=50)
    schedule_sla('minutes:3', lambda: containment_sla_risk_tickets.start(config.webex_room_id_containment_sla_risk), name="containment_sla_risk", timeout=170)
    schedule_sla('hourly:00', lambda: incident_declaration_sla_risk.start(config.webex_room_id_response_sla_risk), name="incident_declaration_sla_risk", timeout=3540)

    # Major Incident monitoring (polls ServiceNow for new incidents assigned to configured groups)
    # TODO: Uncomment once SNOW ITSM Incident API access is granted (EAD_ITSM_API_INC_GET_APP10140)
    # logger.info("Scheduling Major Incident monitoring (every 15 minutes)...")
    # schedule_sla('minutes:15', lambda: major_incident_monitor.check_for_new_incidents(config.webex_room_id_threatcon_collab), name="major_incident_monitor", timeout=300)

    total_jobs = len(schedule.get_jobs())
    logger.info(f"All jobs scheduled successfully! Total jobs: {total_jobs}")
    logger.info("Entering main scheduler loop...")

    loop_counter = 0
    while True:
        try:
            schedule.run_pending()
            loop_counter += 1
            if loop_counter % 30 == 0:
                next_run = schedule.next_run()
                idle_seconds = schedule.idle_seconds()
                logger.debug(f"Loop {loop_counter}: next run at {next_run}, idle {idle_seconds:.1f}s")
            time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Scheduler stopped by user")
            break
        except Exception as e:
            logger.error(f"Error in scheduler main loop: {e}")
            logger.error(traceback.format_exc())
            time.sleep(5)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
