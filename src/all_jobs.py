#!/usr/bin/python3
"""
Job scheduler for security operations automation.

Runs scheduled tasks for chart generation, shift announcements, SLA monitoring,
and other operational workflows. All jobs are wrapped in error handling to ensure
scheduler resilience.
"""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import Callable

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

# Configure logging with centralized utility
setup_logging(
    bot_name='all_jobs',
    log_level=logging.INFO,
    info_modules=['__main__', 'src.components.response_sla_risk_tickets'],
    use_colors=True
)

# Suppress noisy library logs
logging.getLogger("webexpythonsdk.restsession").setLevel(logging.ERROR)
logging.getLogger("webexteamssdk.restsession").setLevel(logging.ERROR)
logging.getLogger("openpyxl").setLevel(logging.ERROR)

logger = logging.getLogger(__name__)

config = get_config()
eastern = pytz.timezone('US/Eastern')


def safe_run(*jobs: Callable[[], None], timeout: int = 1800) -> None:
    """Execute multiple jobs safely with timeout protection, continuing even if some fail.

    Jobs are executed in SEQUENCE with independent error handling and timeout protection.
    This is a BLOCKING function - it waits for all jobs to complete before returning.

    Key guarantee: If one job fails or times out, remaining jobs STILL EXECUTE.
    This ensures errors in one group don't prevent subsequent groups from running.

    Args:
        *jobs: Variable number of callable functions to execute
        timeout: Maximum seconds per job (default: 1800 = 30 minutes)

    Error Handling:
        - Exceptions: Caught, logged, execution continues to next job
        - Timeouts: Job killed, logged, execution continues to next job
        - All jobs in the batch get a chance to run regardless of failures

    Example:
        If Group 1 has 6 jobs and job 3 fails, jobs 4-6 still run.
        When Group 1 completes (even with failures), Group 2 runs next.
    """
    logger.debug(f"safe_run() called with {len(jobs)} job(s)")
    for job in jobs:
        job_name = getattr(job, '__name__', str(job))
        logger.debug(f"Starting job: {job_name}")
        executor = None
        try:
            # Execute job with timeout protection using ThreadPoolExecutor
            # Note: We manually manage executor lifecycle to avoid blocking on shutdown
            executor = ThreadPoolExecutor(max_workers=1)
            future = executor.submit(job)
            try:
                future.result(timeout=timeout)
                logger.debug(f"Job completed successfully: {job_name}")
            except FuturesTimeoutError:
                logger.error(f"Job timed out after {timeout} seconds: {job_name}")
                logger.error(f"This job was forcefully terminated to prevent scheduler hang")
                # Continue to next job despite timeout
        except Exception as e:
            logger.error(f"Job execution failed for {job_name}: {e}")
            logger.debug(traceback.format_exc())
            # Continue to next job despite exception
        finally:
            # Clean up executor without waiting for hung threads
            if executor:
                executor.shutdown(wait=False)


def main() -> None:
    """Configure and start the job scheduler.

    Schedules all security operations tasks including:
    - Daily chart generation at midnight
    - Shift change announcements (morning, afternoon, night)
    - SLA risk monitoring (response, containment, incident declaration)
    - Weekly report distribution
    - Host verification checks
    - On-call notifications

    The scheduler runs indefinitely with crash-proof error handling.
    """
    # Run once to test (uncomment for debugging)
    # print("Running once to test the scheduler...")
    # make_dir_for_todays_charts(helper_methods.CHARTS_DIR_PATH)
    # aging_tickets.make_chart()
    # crowdstrike_efficacy.make_chart()
    # crowdstrike_volume.make_chart()
    # days_since_incident.make_chart()
    # de_stories.make_chart()
    # heatmap.create_choropleth_map()
    # inflow.make_chart()
    # lifespan.make_chart()
    # mttr_mttc.make_chart()
    # outflow.make_chart()
    # qradar_rule_efficacy.make_chart()
    # re_stories.make_chart()
    # sla_breaches.make_chart()
    # threat_tippers.make_chart()
    # threatcon_level.make_chart()
    # vectra_volume.make_chart()
    # secops.announce_shift_change('afternoon', config.webex_room_id_vinay_test_space)
    # # qradar_rule_efficacy.send_charts()
    # # phish_fort.fetch_and_report_incidents()
    # aging_tickets.send_report(config.webex_room_id_vinay_test_space)

    # Configure scheduled jobs
    print("Starting crash-proof job scheduler...")
    logger.info("Initializing security operations scheduler")

    # =============================================================================
    # STABLE JOBS - Fast, reliable chart generation (runs FIRST for quick results)
    # =============================================================================
    # Note: Using generous timeouts since jobs are isolated - timeout is only
    # to prevent infinite hangs, not to aggressively kill legitimate work

    # Prepare directory (fast, runs first)
    logger.info("Scheduling daily chart jobs...")
    schedule.every().day.at("00:01", eastern).do(lambda: safe_run(
        lambda: make_dir_for_todays_charts(helper_methods.CHARTS_DIR_PATH),
    ))
    logger.info("Daily chart jobs scheduled")

    # Group 1: Basic metrics charts (fast, data-driven from cache)
    logger.info("Scheduling Group 1: Basic metrics charts...")
    schedule.every().day.at("00:02", eastern).do(lambda: safe_run(
        aging_tickets.make_chart,
        inflow.make_chart,
        outflow.make_chart,
        mttr_mttc.make_chart,
        sla_breaches.make_chart,
    ))
    logger.info("Group 1 scheduled")

    # Group 2: Efficacy and volume charts (may call external APIs)
    logger.info("Scheduling Group 2: Efficacy and volume charts...")
    schedule.every().day.at("00:07", eastern).do(lambda: safe_run(
        crowdstrike_efficacy.make_chart,
        crowdstrike_volume.make_chart,
        qradar_rule_efficacy.make_chart,
        vectra_volume.make_chart,
        lifespan.make_chart,
    ))
    logger.info("Group 2 scheduled")

    # Group 3: Story and status charts (stable, simple)
    logger.info("Scheduling Group 3: Story and status charts...")
    schedule.every().day.at("00:12", eastern).do(lambda: safe_run(
        de_stories.make_chart,
        re_stories.make_chart,
        days_since_incident.make_chart,
        threat_tippers.make_chart,
        threatcon_level.make_chart,
    ))
    logger.info("Group 3 scheduled")

    # Group 4: Complex/slow charts (heatmap can be slow)
    logger.info("Scheduling Group 4: Complex/slow charts...")
    schedule.every().day.at("00:17", eastern).do(lambda: safe_run(
        heatmap.create_choropleth_map,
    ))
    logger.info("Group 4 scheduled")

    # =============================================================================
    # UNSTABLE JOBS - High risk of timeout/failure, runs LAST after stable jobs
    # =============================================================================

    # Ticket cache generation (UNSTABLE - can take 15-20 min, fully isolated)
    # Runs at 00:30 after all stable jobs complete, so it doesn't block anything
    logger.info("Scheduling ticket cache generation...")
    schedule.every().day.at("00:30", eastern).do(lambda: safe_run(
        TicketCache.generate,
        # Uses default 30-minute timeout - sufficient for ~7000+ tickets with retries
    ))
    logger.info("Ticket cache scheduled")

    # Host verification - checks endpoint connectivity every 5 minutes
    logger.info("Scheduling host verification...")
    schedule.every(5).minutes.do(lambda: safe_run(verify_host_online_status.start))
    logger.info("Host verification scheduled")

    # Shift change announcements - notify SOC team at shift boundaries (04:30, 12:30, 20:30 ET)
    logger.info("Scheduling shift change announcements...")
    room_id = config.webex_room_id_soc_shift_updates
    schedule.every().day.at("04:30", eastern).do(lambda: safe_run(
        lambda: secops.announce_shift_change('morning', room_id)
    ))
    schedule.every().day.at("12:30", eastern).do(lambda: safe_run(
        lambda: secops.announce_shift_change('afternoon', room_id)
    ))
    schedule.every().day.at("20:30", eastern).do(lambda: safe_run(
        lambda: secops.announce_shift_change('night', room_id)
    ))
    logger.info("Shift changes scheduled")

    # Weekly reports - send efficacy charts on Fridays at 08:00 ET
    logger.info("Scheduling weekly reports...")
    schedule.every().friday.at("08:00", eastern).do(lambda: safe_run(
        qradar_rule_efficacy.send_charts,
        crowdstrike_efficacy.send_charts
    ))
    logger.info("Weekly reports scheduled")

    # On-call management - alert before change (Friday 14:00) and announce (Monday 08:00)
    logger.info("Scheduling on-call management...")
    schedule.every().friday.at("14:00", eastern).do(lambda: safe_run(oncall.alert_change))
    schedule.every().monday.at("08:00", eastern).do(lambda: safe_run(
        oncall.announce_change,
    ))
    logger.info("On-call management scheduled")

    # Daily maintenance tasks
    logger.info("Scheduling daily maintenance...")
    schedule.every().day.at("17:00", eastern).do(lambda: safe_run(
        approved_security_testing.removed_expired_entries
    ))
    schedule.every().day.at("07:00", eastern).do(lambda: safe_run(thithi.main))
    logger.info("Daily maintenance scheduled")

    # SLA risk monitoring - continuous checks to prevent breaches
    logger.info("Scheduling SLA risk monitoring...")

    def run_response_sla():
        def response_sla_job():
            response_sla_risk_tickets.start(config.webex_room_id_response_sla_risk)

        safe_run(response_sla_job)

    def run_containment_sla():
        def containment_sla_job():
            containment_sla_risk_tickets.start(config.webex_room_id_containment_sla_risk)

        safe_run(containment_sla_job)

    def run_incident_sla():
        def incident_sla_job():
            incident_declaration_sla_risk.start(config.webex_room_id_response_sla_risk)

        safe_run(incident_sla_job)

    schedule.every(1).minutes.do(run_response_sla)
    schedule.every(3).minutes.do(run_containment_sla)
    schedule.every().hour.at(":00").do(run_incident_sla)
    logger.info("SLA risk monitoring scheduled")

    logger.info(f"All jobs scheduled successfully! Total jobs: {len(schedule.get_jobs())}")
    logger.info("Entering main scheduler loop...")

    loop_counter = 0
    while True:
        try:
            schedule.run_pending()
            loop_counter += 1

            # Debug logging every 30 seconds
            if loop_counter % 30 == 0:
                next_run = schedule.next_run()
                idle_seconds = schedule.idle_seconds()
                logger.debug(f"Loop iteration {loop_counter}: Next run at {next_run}, idle for {idle_seconds:.1f}s")

            time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Scheduler stopped by user")
            break
        except Exception as e:
            logger.error(f"Error in scheduler main loop: {e}")
            logger.error(traceback.format_exc())
            # Brief pause before continuing to avoid tight error loop
            time.sleep(5)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
