#!/usr/bin/python3
"""
Job scheduler for security operations automation.

Runs scheduled tasks for chart generation, shift announcements, SLA monitoring,
and other operational workflows. All jobs are wrapped in error handling to ensure
scheduler resilience.
"""

import logging
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

from my_config import get_config
from src.utils.logging_utils import setup_logging

# Configure logging with centralized utility
setup_logging(
    bot_name='ir_scheduler',
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
logger.warning(f"🚀 IR SCHEDULER STARTED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
logger.warning("=" * 100)

config = get_config()
eastern = pytz.timezone('US/Eastern')

# Default per-job timeout (seconds)
DEFAULT_JOB_TIMEOUT = 1800  # 30 minutes
TICKET_CACHE_TIMEOUT = 21600  # 360 minutes (6 hours) for ticket enrichment job on VM

# Track which jobs have already sent a failure notification (notify once until success resets)
_job_failure_notified: set = set()

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
            # Job succeeded — reset notification so we alert again if it breaks later
            _job_failure_notified.discard(job_name)
        except FuturesTimeoutError:
            elapsed = time.time() - start_time
            logger.error(f"Job timed out after {timeout} seconds: {job_name} (elapsed {elapsed:.2f}s)")
            _notify_job_failure(job_name, f"Timed out after {timeout}s")
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"Job execution failed for {job_name} after {elapsed:.2f}s: {e}")
        logger.debug(traceback.format_exc())
        _notify_job_failure(job_name, str(e))
    finally:
        if executor:
            executor.shutdown(wait=False)


def _notify_job_failure(job_name: str, error_msg: str) -> None:
    """Send a one-time Webex notification when a scheduled job fails."""
    if job_name in _job_failure_notified:
        return
    _job_failure_notified.add(job_name)
    try:
        notify_access_issue(f"Scheduler Job: {job_name}", [error_msg], room_id=config.webex_room_id_dev_test_space)
    except Exception as e:
        logger.error(f"Failed to send job failure notification for {job_name}: {e}")


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

def schedule_daily(time_str: str, *jobs: Callable[[], None], name: str = None,
                   timeout: int = DEFAULT_JOB_TIMEOUT) -> None:
    """Schedule a set of jobs to run daily at a given time (Eastern).

    Args:
        time_str: Time in 'HH:MM' format (Eastern timezone)
        *jobs: One or more callable jobs to execute
        name: Optional descriptive name for logs
        timeout: Per-job timeout in seconds (applied to each job in the set)
    """
    schedule.every().day.at(time_str, eastern).do(lambda: safe_run(*jobs, name=name, timeout=timeout))


def schedule_group(time_str: str, name: str, jobs: Iterable[Callable[[], None]],
                   timeout: int = DEFAULT_JOB_TIMEOUT) -> None:
    """Schedule a named group of jobs and log registration."""
    job_list = list(jobs)
    logger.info(f"Scheduling {name} ({len(job_list)} job(s)) at {time_str} ET, per-job timeout={timeout}s")
    schedule_daily(time_str, *job_list, name=name, timeout=timeout)


def schedule_shift(time_str: str, shift_name: str, room_id: str) -> None:
    """Schedule a shift change announcement."""
    schedule_daily(time_str, lambda: __import__('secops').announce_shift_change(shift_name, room_id), name=f"shift_{shift_name}")


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



# ----------------------------------------------------------------------------------
# Data-driven configuration for chart groups
# ----------------------------------------------------------------------------------
def _lazy_chart(module_name: str, func_name: str = 'make_chart') -> Callable[[], None]:
    """Create a lazy-loading wrapper for a chart function."""
    def _run():
        import importlib
        mod = importlib.import_module(f'src.charts.{module_name}')
        getattr(mod, func_name)()
    _run.__name__ = f'{module_name}.{func_name}'
    return _run


def _lazy_component(module_path: str, func_name: str, *args, **kwargs) -> Callable[[], None]:
    """Create a lazy-loading wrapper for a component function."""
    def _run():
        import importlib
        mod = importlib.import_module(module_path)
        getattr(mod, func_name)(*args, **kwargs)
    _run.__name__ = f'{module_path.split(".")[-1]}.{func_name}'
    return _run


CHART_GROUPS: List[dict] = [
    {
        'time': '00:02',
        'name': 'Group 1: Basic metrics charts',
        # inflow.make_chart paginates 12 months of XSOAR tickets; longer
        # timeout absorbs slow-network days without firing a false alarm.
        'timeout': 3600,
        'jobs': [
            _lazy_chart('aging_tickets'),
            _lazy_chart('inflow'),
            _lazy_chart('outflow'),
            _lazy_chart('mttr_mttc'),
            _lazy_chart('sla_breaches'),
            _lazy_chart('threatcon_level'),
        ]
    },
    {
        'time': '00:07',
        'name': 'Group 2: Efficacy & volume charts',
        'jobs': [
            _lazy_chart('crowdstrike_efficacy'),
            _lazy_chart('crowdstrike_volume'),
            _lazy_chart('qradar_rule_efficacy'),
            _lazy_chart('vectra_volume'),
            _lazy_chart('lifespan'),
        ]
    },
    {
        'time': '00:12',
        'name': 'Group 3: Story & status charts',
        'jobs': [
            _lazy_chart('de_stories'),
            _lazy_chart('re_stories'),
            _lazy_chart('days_since_incident'),
            _lazy_chart('threat_tippers'),
        ]
    },
    {
        'time': '00:17',
        'name': 'Group 4: Complex/slow charts',
        'jobs': [
            _lazy_chart('heatmap', 'create_choropleth_map'),
        ]
    },
]


def _shutdown_handler(_signum=None, _frame=None):
    """Log shutdown marker before exit."""
    logger.warning("=" * 100)
    logger.warning(f"🛑 IR SCHEDULER STOPPED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
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
    def _chart_dir_prep():
        from src.utils.fs_utils import make_dir_for_todays_charts
        from src import helper_methods
        make_dir_for_todays_charts(helper_methods.CHARTS_DIR_PATH)
    schedule_daily('00:01', _chart_dir_prep, name="chart_dir_prep")

    # Cleanup old transient data (secOps and charts folders older than 30 days)
    logger.info("Scheduling daily cleanup of old transient data (02:00 ET)...")
    def _transient_cleanup():
        from src.utils.fs_utils import cleanup_old_transient_data
        cleanup_old_transient_data()
    schedule_daily('02:00', _transient_cleanup, name="transient_data_cleanup")

    # Cleanup old recap audio files (>30 days). Transcripts/summaries kept forever.
    logger.info("Scheduling daily cleanup of old recap audio (03:00 ET)...")
    def _recap_audio_cleanup():
        from src.components.web.recap_handler import cleanup_old_audio
        cleanup_old_audio(retention_days=30)
    schedule_daily('03:00', _recap_audio_cleanup, name="recap_audio_cleanup")

    # Note: Tipper jobs now run here on lab-vm (previously in home_jobs.py)

    # Chart groups (data-driven)
    for group in CHART_GROUPS:
        schedule_group(group['time'], group['name'], group['jobs'],
                       timeout=group.get('timeout', DEFAULT_JOB_TIMEOUT))

    # Daily operational report dispatch runs after all chart groups so it
    # sees today's PNGs; inline dispatch races inflow's 12-month fetch.
    schedule_daily(
        '00:45',
        lambda: __import__('secops').send_daily_operational_report_charts(get_config().webex_room_id_metrics),
        name="daily_operational_report_dispatch"
    )

    # Ticket cache - RUNS LAST to avoid interfering with chart generation
    # Scheduled after all chart jobs complete (charts finish by ~00:30)
    # Extended timeout (6 hours) accommodates slow VM network with full note enrichment
    logger.info("Scheduling ticket cache generation at 01:00 ET (runs last, may take 2-4 hours on VM)...")

    def ticket_cache_with_logging():
        logger.info("=" * 60)
        logger.info("TICKET CACHE JOB STARTING at 01:00 ET")
        logger.info("=" * 60)
        from src.components.ticket_cache import TicketCache
        safe_run(TicketCache.generate, timeout=TICKET_CACHE_TIMEOUT, name="ticket_cache")
        logger.info("=" * 60)
        logger.info("TICKET CACHE JOB COMPLETED")
        logger.info("=" * 60)

    schedule.every().day.at('01:00', eastern).do(ticket_cache_with_logging)

    # Host verification
    logger.info("Scheduling host verification every 5 minutes...")
    schedule.every(5).minutes.do(lambda: safe_run(
        lambda: __import__('src.verify_host_online_status', fromlist=['start']).start(),
        name="host_online_verification"))

    # Deferred RTR actions (offline hosts waiting to come online)
    logger.info("Scheduling deferred RTR processing every 15 minutes...")
    def _run_deferred_rtr():
        from webexpythonsdk import WebexAPI
        from src.deferred_rtr import process_pending
        toodles_api = WebexAPI(access_token=config.webex_bot_access_token_toodles)
        process_pending(toodles_api)
    schedule.every(15).minutes.do(lambda: safe_run(_run_deferred_rtr, name="deferred_rtr", timeout=600))

    # Peer ping keepalive for bot NAT paths
    logger.info("Scheduling peer ping keepalive Hi messages...")
    schedule.every(5).minutes.do(
        lambda: safe_run(lambda: __import__('src.peer_ping_keepalive', fromlist=['send_peer_pings']).send_peer_pings(config.webex_bot_access_token_pinger), name="peer_ping_keepalive")
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
        lambda: __import__('src.charts.qradar_rule_efficacy', fromlist=['send_charts']).send_charts(),
        lambda: __import__('src.charts.crowdstrike_efficacy', fromlist=['send_charts']).send_charts(),
        name="weekly_efficacy_report"
    ))

    # On-call management
    logger.info("Scheduling on-call management (Fri alert, Mon announce)...")
    schedule.every().friday.at('14:00', eastern).do(lambda: safe_run(
        lambda: __import__('src.components.oncall', fromlist=['alert_change']).alert_change(), name="oncall_alert"))
    schedule.every().monday.at('08:00', eastern).do(lambda: safe_run(
        lambda: __import__('src.components.oncall', fromlist=['announce_change']).announce_change(), name="oncall_announce"))

    # Daily maintenance
    logger.info("Scheduling daily maintenance tasks...")
    schedule_daily('17:00', _lazy_component('src.components.approved_security_testing', 'removed_expired_entries'))
    schedule_daily('17:00', _lazy_component('services.ticket_cannon_utils', 'remove_expired_entries'))
    schedule_daily('07:00', _lazy_component('src.components.thithi', 'main'))
    schedule_daily('08:00',
                   lambda: __import__('src.components.abandoned_tickets', fromlist=['send_report']).send_report(config.webex_room_id_abandoned_tickets),
                   lambda: __import__('src.components.orphaned_tickets', fromlist=['send_report']).send_report(config.webex_room_id_abandoned_tickets)
                   )

    # Nightly LLM QA review of closed tickets
    logger.info("Scheduling nightly LLM ticket QA review (05:00 ET)...")
    schedule_daily('05:00', _lazy_component('src.components.qa_tickets', 'run'), name="llm_qa_review")

    # Weekly QA trends summary (Friday)
    logger.info("Scheduling weekly QA trends summary (Friday 09:00 ET)...")
    schedule.every().friday.at('09:00', eastern).do(lambda: safe_run(
        _lazy_component('src.components.qa_tickets', 'weekly_summary'), name="qa_weekly_summary"))

    # Stale containment cleanup - removes hosts from containment list when their ticket is closed
    logger.info("Scheduling stale containment cleanup (18:00 ET)...")
    schedule_daily('18:00', _lazy_component('src.components.stale_containment_cleanup', 'cleanup_stale_containments'), name="stale_containment_cleanup")

    # Birthday and anniversary celebrations
    logger.info("Scheduling daily birthday/anniversary check (08:00 ET)...")
    schedule_daily('08:00', _lazy_component('src.components.birthdays_anniversaries', 'daily_celebration_check'), name="birthday_anniversary_check")

    # XSOAR auto-triage poller — fetches new tickets and submits to worker pool
    sentinel_triage_room = config.webex_room_id_sentinel_triage
    if sentinel_triage_room:
        def _run_xsoar_triage_poller() -> None:
            from src.components.xsoar_alert_triage.xsoar_poller import poll_once
            poll_once(webex_api=_get_webex_api(), room_id=sentinel_triage_room)

        logger.info("Scheduling XSOAR triage poller every 5 minutes...")
        schedule.every(5).minutes.do(
            lambda: safe_run(_run_xsoar_triage_poller, name="sentinel_xsoar_triage_poller", timeout=30)
        )
    else:
        logger.warning("XSOAR auto-triage poller DISABLED (no WEBEX_ROOM_ID_SENTINEL_TRIAGE configured)")

    # PhishFort incident report - weekly summary of active phishing takedowns
    logger.info("Scheduling weekly PhishFort incident report (Monday 09:00 ET)...")
    schedule.every().monday.at('09:00', eastern).do(
        lambda: safe_run(lambda: __import__('services.phish_fort', fromlist=['fetch_and_report_incidents']).fetch_and_report_incidents(room_id=config.webex_room_id_phish_fort), name="phishfort_report")
    )

    # XSOAR ticket timeline sync - monthly refresh for the animated bar chart race
    # Runs on the 1st of each month at 03:00 ET, pulls last 45 days to catch
    # both new tickets and updates to existing ones (status, impact, severity, etc.)
    def _xsoar_timeline_monthly_sync():
        today = datetime.now(eastern)
        if today.day != 1:
            return
        logger.info("XSOAR timeline monthly sync starting (days_back=45)...")
        from scripts.backfill_xsoar_timeline import backfill
        backfill(days_back=45)

    logger.info("Scheduling monthly XSOAR timeline sync (1st of month, 03:00 ET)...")
    schedule.every().day.at('03:00', eastern).do(
        lambda: safe_run(_xsoar_timeline_monthly_sync, name="xsoar_timeline_sync", timeout=3600)
    )

    # Biweekly Defense Pulse analysis - systemic security gap charts + strategic report
    # Runs on even ISO weeks (Monday after ticket cache has refreshed)
    def _defense_pulse_biweekly():
        iso_week = datetime.now(eastern).isocalendar()[1]
        if iso_week % 2 != 0:
            logger.info(f"Defense Pulse skipped — odd ISO week {iso_week} (runs biweekly on even weeks)")
            return
        from src.charts import defense_pulse
        safe_run(lambda: defense_pulse.make_chart(room_id=config.webex_room_id_metrics), name="defense_pulse_biweekly")

    logger.info("Scheduling biweekly Defense Pulse analysis (even-week Monday 06:00 ET)...")
    schedule.every().monday.at('06:00', eastern).do(_defense_pulse_biweekly)

    # Weekly ticket pattern analysis - identifies top offenders and creates AZDO user story
    logger.info("Scheduling weekly ticket pattern analysis (Monday 07:00 ET)...")
    schedule.every().monday.at('07:00', eastern).do(
        lambda: safe_run(_lazy_component('src.components.ticket_pattern_analysis', 'run'), name="ticket_pattern_analysis", timeout=1800)
    )

    # OE Detection — disabled (not in use)
    # def _run_oe_detection_scan():
    #     from src.components.oe_detection.config.loader import load_oe_config
    #     from src.components.oe_detection.scanner import run_scan as run_oe_scan
    #     oe_config = load_oe_config()
    #     run_oe_scan(oe_config, dry_run=False)
    # schedule.every(6).hours.do(
    #     lambda: safe_run(_run_oe_detection_scan, name="oe_detection_scan", timeout=3600, blocking=False)
    # )
    # schedule.every().monday.at('08:10', eastern).do(
    #     lambda: safe_run(
    #         lambda: __import__('src.components.oe_detection.scanner', fromlist=['send_heartbeat']).send_heartbeat(),
    #         name="oe_detection_heartbeat", timeout=30,
    #     )
    # )

    # SLA risk monitoring
    logger.info("Scheduling SLA risk monitoring jobs...")
    schedule_sla('minutes:3', lambda: __import__('src.components.response_sla_risk_tickets', fromlist=['start']).start(config.webex_room_id_response_sla_risk), name="response_sla_risk", timeout=50)
    schedule_sla('minutes:3', lambda: __import__('src.components.containment_sla_risk_tickets', fromlist=['start']).start(config.webex_room_id_containment_sla_risk), name="containment_sla_risk", timeout=170)
    schedule_sla('hourly:00', lambda: __import__('src.components.incident_declaration_sla_risk', fromlist=['start']).start(config.webex_room_id_response_sla_risk), name="incident_declaration_sla_risk", timeout=3540)

    # Major Incident monitoring (polls ServiceNow for new incidents assigned to configured groups)
    logger.info("Scheduling Major Incident monitoring (every 15 minutes)...")
    schedule_sla('minutes:15', lambda: __import__('src.components.major_incident_monitor', fromlist=['check_for_new_incidents']).check_for_new_incidents(config.webex_room_id_threatcon_collab), name="major_incident_monitor", timeout=300)

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
