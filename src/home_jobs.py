#!/usr/bin/python3
"""
Home job scheduler for jobs that run on the same machine as Pokédex.

This scheduler runs jobs that need to be on the same box as Pokédex,
such as the tipper similarity index which uses local ChromaDB storage.

Usage:
    python src/home_jobs.py
"""

import logging
import os
import signal
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import pytz
import schedule

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.logging_utils import setup_logging
from src.utils.webex_utils import get_room_name
from src.components.tipper_analyzer import analyze_recent_tippers
from src.components.tipper_analyzer.rules.sync import sync_catalog
from src.components.tipper_indexer import sync_tipper_index
from src.components.tanium_signals_sync import sync_tanium_signals_catalog
from my_config import get_config

# Configure logging (file handler)
setup_logging(
    bot_name='home_jobs',
    log_level=logging.INFO,
    rotate_on_startup=False
)

# Add console handler for terminal output
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S'))
logging.getLogger().addHandler(console_handler)

logger = logging.getLogger(__name__)

eastern = pytz.timezone('US/Eastern')

# Default job timeout (seconds)
DEFAULT_JOB_TIMEOUT = 1800  # 30 minutes


def safe_run(job: Callable[[], Any], timeout: int = DEFAULT_JOB_TIMEOUT, name: str = None) -> None:
    """Execute a job safely with timeout protection.

    Args:
        job: Callable job to execute
        timeout: Maximum execution time in seconds
        name: Optional descriptive name for logs
    """
    job_name = name or getattr(job, '__name__', repr(job))
    executor = None
    start_time = time.time()

    logger.info(f">>> Starting job: {job_name}")
    try:
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(job)
        try:
            future.result(timeout=timeout)
            elapsed = time.time() - start_time
            logger.info(f"<<< Job completed successfully: {job_name} (took {elapsed:.2f}s)")
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


def schedule_daily(time_str: str, job: Callable[[], Any], name: str = None, timeout: int = DEFAULT_JOB_TIMEOUT) -> None:
    """Schedule a job to run daily at a given time (Eastern).

    Args:
        time_str: Time in 'HH:MM' format (Eastern timezone)
        job: Callable job to execute
        name: Optional descriptive name for logs
        timeout: Job timeout in seconds
    """
    schedule.every().day.at(time_str, eastern).do(lambda: safe_run(job, timeout=timeout, name=name))
    logger.info(f"Scheduled '{name or job.__name__}' daily at {time_str} ET")


def schedule_weekdays(time_str: str, job: Callable[[], Any], name: str = None, timeout: int = DEFAULT_JOB_TIMEOUT) -> None:
    """Schedule a job to run Monday-Friday at a given time (Eastern).

    Args:
        time_str: Time in 'HH:MM' format (Eastern timezone)
        job: Callable job to execute
        name: Optional descriptive name for logs
        timeout: Job timeout in seconds
    """
    job_name = name or job.__name__
    schedule.every().monday.at(time_str, eastern).do(lambda: safe_run(job, timeout=timeout, name=name))
    schedule.every().tuesday.at(time_str, eastern).do(lambda: safe_run(job, timeout=timeout, name=name))
    schedule.every().wednesday.at(time_str, eastern).do(lambda: safe_run(job, timeout=timeout, name=name))
    schedule.every().thursday.at(time_str, eastern).do(lambda: safe_run(job, timeout=timeout, name=name))
    schedule.every().friday.at(time_str, eastern).do(lambda: safe_run(job, timeout=timeout, name=name))
    logger.info(f"Scheduled '{job_name}' Mon-Fri at {time_str} ET")


def schedule_hourly(minute: int, job: Callable[[], Any], name: str = None, timeout: int = DEFAULT_JOB_TIMEOUT) -> None:
    """Schedule a job to run every hour at a given minute.

    Args:
        minute: Minute of the hour to run (0-59)
        job: Callable job to execute
        name: Optional descriptive name for logs
        timeout: Job timeout in seconds
    """
    schedule.every().hour.at(f":{minute:02d}").do(lambda: safe_run(job, timeout=timeout, name=name))
    logger.info(f"Scheduled '{name or job.__name__}' hourly at :{minute:02d}")


def schedule_business_hours(
        minute: int,
        job: Callable[[], Any],
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
        # Must create fresh scheduler objects each iteration - they are mutable builders
        # that get modified by .at(), so reusing them overwrites previous settings
        schedule.every().monday.at(time_str, eastern).do(lambda j=job, t=timeout, n=name: safe_run(j, timeout=t, name=n))
        schedule.every().tuesday.at(time_str, eastern).do(lambda j=job, t=timeout, n=name: safe_run(j, timeout=t, name=n))
        schedule.every().wednesday.at(time_str, eastern).do(lambda j=job, t=timeout, n=name: safe_run(j, timeout=t, name=n))
        schedule.every().thursday.at(time_str, eastern).do(lambda j=job, t=timeout, n=name: safe_run(j, timeout=t, name=n))
        schedule.every().friday.at(time_str, eastern).do(lambda j=job, t=timeout, n=name: safe_run(j, timeout=t, name=n))
    logger.info(f"Scheduled '{job_name}' Mon-Fri {start_hour}:00-{end_hour}:00 ET at :{minute:02d}")


def _shutdown_handler(_signum=None, _frame=None):
    """Log shutdown marker before exit."""
    logger.warning("=" * 80)
    logger.warning(f"HOME_JOBS SCHEDULER STOPPED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.warning("=" * 80)
    sys.exit(0)


def main() -> None:
    """Configure and start the home job scheduler."""
    logger.warning("=" * 80)
    logger.warning(f"HOME_JOBS SCHEDULER STARTED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.warning("=" * 80)

    # Register shutdown handlers
    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    # -------------------------------------------------------------------------
    # Schedule jobs
    # -------------------------------------------------------------------------

    # Tipper analysis - analyzes new tippers and sends to Webex
    # Runs at :15 past each hour during US business hours (9 AM - 6 PM ET)
    # Tippers are only created during business hours, so no need to run overnight
    # Explicitly passes prod room; tipper_analyzer defaults to test room for manual runs
    config = get_config()
    tipper_analysis_room = config.webex_room_id_threat_tipper_analysis
    if tipper_analysis_room:
        room_name = get_room_name(tipper_analysis_room, config.webex_bot_access_token_pokedex) or "Unknown"
        logger.info(f"Tipper analysis will send to room: {room_name}")
    else:
        logger.warning("WARNING: No tipper analysis room configured!")
    # Hourly tipper analysis - controlled by ENABLE_HOURLY_TIPPER_ANALYSIS env var
    if os.environ.get("ENABLE_HOURLY_TIPPER_ANALYSIS", "false").lower() == "true":
        schedule_business_hours(
            15,
            lambda: analyze_recent_tippers(hours_back=1, room_id=tipper_analysis_room),
            name="business_hours_tipper_analysis",
            timeout=900  # 15 min timeout - should handle several tippers
        )
        logger.info("Hourly tipper analysis ENABLED")
    else:
        logger.info("Hourly tipper analysis DISABLED (set ENABLE_HOURLY_TIPPER_ANALYSIS=true to enable)")

    # Detection rules catalog sync - refreshes CrowdStrike/QRadar rules daily
    # Runs at 7:00 PM ET Mon-Fri when user is at computer (ZPA connected)
    schedule_weekdays(
        "19:00",
        sync_catalog,
        name="daily_rules_catalog_sync",
        timeout=600  # 10 min timeout
    )

    # Tanium signals catalog sync - fetches signals from Cloud and On-Prem Tanium
    # Runs at 7:05 PM ET Mon-Fri when user is at computer (ZPA connected)
    schedule_weekdays(
        "19:05",
        sync_tanium_signals_catalog,
        name="daily_tanium_signals_sync",
        timeout=600  # 10 min timeout
    )

    # Tipper index sync - indexes new tippers for similarity search
    # Runs at 7:10 PM ET Mon-Fri when user is at computer (ZPA connected)
    schedule_weekdays(
        "19:10",
        lambda: sync_tipper_index(days_back=7),  # Look back 7 days to catch any missed
        name="daily_tipper_index_sync",
        timeout=1800  # 30 min timeout - indexing can be slow
    )

    # -------------------------------------------------------------------------
    # Main loop
    # -------------------------------------------------------------------------
    # Note: Total jobs count is high because schedule_business_hours creates
    # a separate job for each hour × each weekday (e.g., 10 hours × 5 days = 50)
    total_jobs = len(schedule.get_jobs())
    logger.info(f"All jobs scheduled. Total jobs: {total_jobs}")
    logger.info("Entering main scheduler loop...")

    while True:
        try:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
        except KeyboardInterrupt:
            logger.info("Scheduler stopped by user")
            break
        except Exception as e:
            logger.error(f"Error in scheduler main loop: {e}")
            logger.error(traceback.format_exc())
            time.sleep(5)


if __name__ == '__main__':
    main()
