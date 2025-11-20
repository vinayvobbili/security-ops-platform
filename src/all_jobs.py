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
    containment_sla_risk_tickets, incident_declaration_sla_risk
)
from src.utils.fs_utils import make_dir_for_todays_charts
from src.utils.logging_utils import setup_logging
from src import peer_ping_keepalive

# Configure logging with centralized utility
setup_logging(
    bot_name='all_jobs',
    log_level=logging.INFO,  # Default level for most modules
    info_modules=['__main__', 'src.components.response_sla_risk_tickets', 'services.xsoar']
)

# Set XSOAR logging to INFO (connection issues have been resolved)
logging.getLogger("services.xsoar").setLevel(logging.INFO)

# Set ticket_cache to DEBUG for nightly failure diagnosis
logging.getLogger("src.components.ticket_cache").setLevel(logging.DEBUG)

logger = logging.getLogger(__name__)

config = get_config()
eastern = pytz.timezone('US/Eastern')

# Default per-job timeout (seconds)
DEFAULT_JOB_TIMEOUT = 1800  # 30 minutes
TICKET_CACHE_TIMEOUT = 21600  # 360 minutes (6 hours) for ticket enrichment job on VM


# Note: VM with slow network takes 2-4 hours for 12k tickets with note enrichment
# Generous timeout prevents premature termination of this critical nightly job


def safe_run(*jobs: Callable[[], None], timeout: int = DEFAULT_JOB_TIMEOUT, name: str = None) -> None:
    """Execute multiple jobs safely with timeout protection, continuing even if some fail.

    Sequentially runs each provided job. Each job is isolated with its own ThreadPoolExecutor
    to enforce a timeout and prevent the entire scheduler from hanging.

    Args:
        *jobs: One or more callable jobs to execute
        timeout: Maximum execution time per job in seconds
        name: Optional descriptive name for the job(s) in logs (overrides auto-detected names)
    """
    import time
    if not jobs:
        logger.debug("safe_run() called with 0 jobs - nothing to do")
        return
    logger.debug(f"safe_run() running {len(jobs)} job(s) with timeout={timeout}s")
    for i, job in enumerate(jobs):
        # Use provided name, or try to extract function name, or fall back to repr
        if name:
            job_name = name if len(jobs) == 1 else f"{name}[{i + 1}/{len(jobs)}]"
        else:
            job_name = getattr(job, '__name__', repr(job))
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
            secops.send_daily_operational_report_charts
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
            threatcon_level.make_chart,
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


def main() -> None:
    """Configure and start the job scheduler."""
    print("Starting crash-proof job scheduler...")
    logger.info("Initializing security operations scheduler")

    # Directory preparation (first, fast)
    logger.info("Scheduling daily chart directory preparation...")
    schedule_daily('00:01', lambda: make_dir_for_todays_charts(helper_methods.CHARTS_DIR_PATH), name="chart_dir_prep")

    # Chart groups (data-driven)
    for group in CHART_GROUPS:
        schedule_group(group['time'], group['name'], group['jobs'])

    # Ticket cache - RUNS LAST to avoid interfering with chart generation
    # Scheduled after all chart jobs complete (charts finish by ~00:30)
    # Extended timeout (6 hours) accommodates slow VM network with full note enrichment
    logger.info("Scheduling ticket cache generation at 01:00 ET (runs last, may take 2-4 hours on VM)...")
    schedule.every().day.at('01:00', eastern).do(
        lambda: safe_run(TicketCache.generate, timeout=TICKET_CACHE_TIMEOUT, name="ticket_cache")
    )

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

    # Daily maintenance
    logger.info("Scheduling daily maintenance tasks...")
    schedule_daily('17:00', approved_security_testing.removed_expired_entries)
    schedule_daily('07:00', thithi.main)

    # SLA risk monitoring
    logger.info("Scheduling SLA risk monitoring jobs...")
    schedule_sla('minutes:1', lambda: response_sla_risk_tickets.start(config.webex_room_id_response_sla_risk), name="response_sla_risk", timeout=50)
    schedule_sla('minutes:3', lambda: containment_sla_risk_tickets.start(config.webex_room_id_containment_sla_risk), name="containment_sla_risk", timeout=170)
    schedule_sla('hourly:00', lambda: incident_declaration_sla_risk.start(config.webex_room_id_response_sla_risk), name="incident_declaration_sla_risk", timeout=3540)

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
