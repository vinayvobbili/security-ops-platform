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
    log_level=logging.WARNING,
    info_modules=['__main__'],
    use_colors=True
)

# Suppress noisy library logs
logging.getLogger("webexpythonsdk.restsession").setLevel(logging.ERROR)
logging.getLogger("webexteamssdk.restsession").setLevel(logging.ERROR)
logging.getLogger("openpyxl").setLevel(logging.ERROR)

logger = logging.getLogger(__name__)

config = get_config()
eastern = pytz.timezone('US/Eastern')


def safe_run(*jobs: Callable[[], None], timeout: int = 300) -> None:
    """Execute multiple jobs safely with timeout protection, continuing even if some fail.

    Each job is executed in sequence with independent error handling and timeout protection.
    If one job fails or times out, remaining jobs continue executing.

    Args:
        *jobs: Variable number of callable functions to execute
        timeout: Maximum seconds per job (default: 300 = 5 minutes)
    """
    for job in jobs:
        job_name = getattr(job, '__name__', str(job))
        try:
            # Execute job with timeout protection using ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(job)
                try:
                    future.result(timeout=timeout)
                except FuturesTimeoutError:
                    logger.error(f"Job timed out after {timeout} seconds: {job_name}")
                    logger.error(f"This job was forcefully terminated to prevent scheduler hang")
        except Exception as e:
            logger.error(f"Job execution failed for {job_name}: {e}")
            logger.debug(traceback.format_exc())


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

    # Daily chart generation - runs at midnight to prepare metrics for the next day
    schedule.every().day.at("00:01", eastern).do(lambda: safe_run(
        lambda: make_dir_for_todays_charts(helper_methods.CHARTS_DIR_PATH),
        TicketCache.generate,
        aging_tickets.make_chart,
        crowdstrike_efficacy.make_chart,
        crowdstrike_volume.make_chart,
        days_since_incident.make_chart,
        de_stories.make_chart,
        heatmap.create_choropleth_map,
        inflow.make_chart,
        lifespan.make_chart,
        mttr_mttc.make_chart,
        outflow.make_chart,
        qradar_rule_efficacy.make_chart,
        re_stories.make_chart,
        sla_breaches.make_chart,
        threat_tippers.make_chart,
        threatcon_level.make_chart,
        vectra_volume.make_chart,
    ))

    # Host verification - checks endpoint connectivity every 5 minutes
    schedule.every(5).minutes.do(lambda: safe_run(verify_host_online_status.start))

    # Shift change announcements - notify SOC team at shift boundaries (04:30, 12:30, 20:30 ET)
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

    # Weekly reports - send efficacy charts on Fridays at 08:00 ET
    schedule.every().friday.at("08:00", eastern).do(lambda: safe_run(
        qradar_rule_efficacy.send_charts,
        crowdstrike_efficacy.send_charts
    ))

    # On-call management - alert before change (Friday 14:00) and announce (Monday 08:00)
    schedule.every().friday.at("14:00", eastern).do(lambda: safe_run(oncall.alert_change))
    schedule.every().monday.at("08:00", eastern).do(lambda: safe_run(
        oncall.announce_change,
    ))

    # Daily maintenance tasks
    schedule.every().day.at("17:00", eastern).do(lambda: safe_run(
        approved_security_testing.removed_expired_entries
    ))
    schedule.every().day.at("07:00", eastern).do(lambda: safe_run(thithi.main))

    # SLA risk monitoring - continuous checks to prevent breaches
    schedule.every(1).minutes.do(lambda: safe_run(
        lambda: response_sla_risk_tickets.start(config.webex_room_id_response_sla_risk)
    ))
    schedule.every(3).minutes.do(lambda: safe_run(
        lambda: containment_sla_risk_tickets.start(config.webex_room_id_containment_sla_risk)
    ))
    schedule.every().hour.at(":00").do(lambda: safe_run(
        lambda: incident_declaration_sla_risk.start(config.webex_room_id_response_sla_risk),
    ))

    while True:
        try:
            schedule.run_pending()
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
