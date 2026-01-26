#!/usr/bin/python3
"""
Job scheduler for office/on-prem security operations automation.

Runs scheduled tasks that need to run from the office network (on-prem).
All jobs are wrapped in error handling to ensure scheduler resilience.
"""

import logging
import sys
import warnings
from pathlib import Path

# Suppress noisy library loggers BEFORE imports to prevent startup spam
logging.getLogger("webexpythonsdk.restsession").setLevel(logging.WARNING)
logging.getLogger("webexteamssdk.restsession").setLevel(logging.WARNING)
logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
warnings.filterwarnings("ignore", category=UserWarning, module="openpyxl")

sys.path.insert(0, str(Path(__file__).parent.parent))
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import Callable

import pytz
import schedule

from my_config import get_config
from webex_bots.case import run_automated_ring_tagging_workflow as run_automated_tanium_onprem_ring_tagging_workflow
from src.utils.logging_utils import setup_logging

# Configure logging with centralized utility
setup_logging(
    bot_name='office_jobs',
    log_level=logging.INFO,
    info_modules=['__main__'],
    rotate_on_startup=False
)

logger = logging.getLogger(__name__)

# Log clear startup marker for visual separation in logs
import signal
import atexit
from datetime import datetime

logger.warning("=" * 100)
logger.warning(f"🚀 OFFICE_JOBS SCHEDULER STARTED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
logger.warning("=" * 100)

config = get_config()
eastern = pytz.timezone('US/Eastern')

# Default per-job timeout (seconds)
DEFAULT_JOB_TIMEOUT = 1800  # 30 minutes


def safe_run(*jobs: Callable[[], None], timeout: int = DEFAULT_JOB_TIMEOUT, name: str = None) -> None:
    """Execute multiple jobs safely with timeout protection, continuing even if some fail.

    Args:
        *jobs: One or more callable jobs to execute
        timeout: Maximum execution time per job in seconds
        name: Optional descriptive name for the job(s) in logs
    """
    if not jobs:
        logger.debug("safe_run() called with 0 jobs - nothing to do")
        return
    logger.debug(f"safe_run() running {len(jobs)} job(s) with timeout={timeout}s")
    for i, job in enumerate(jobs):
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


def _shutdown_handler(signum=None, frame=None):
    """Log shutdown marker before exit"""
    logger.warning("=" * 100)
    logger.warning(f"🛑 OFFICE_JOBS SCHEDULER STOPPED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.warning("=" * 100)


def main() -> None:
    """Configure and start the office job scheduler."""
    print("Starting office job scheduler...")
    logger.info("Initializing office operations scheduler")

    # Register shutdown handlers for graceful logging
    atexit.register(_shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    # Automated Tanium On-Prem ring tagging (Mon/Thu at 4 AM, 12 PM, 8 PM ET) - COMMENTED OUT until ready
    # logger.info("Scheduling automated Tanium On-Prem ring tagging (Mon/Thu 04:00, 12:00, 20:00 ET)...")
    # schedule.every().monday.at('04:00', eastern).do(
    #     lambda: safe_run(run_automated_tanium_onprem_ring_tagging_workflow, name="automated_tanium_onprem_ring_tagging_mon_04am", timeout=1800)
    # )
    # schedule.every().monday.at('12:00', eastern).do(
    #     lambda: safe_run(run_automated_tanium_onprem_ring_tagging_workflow, name="automated_tanium_onprem_ring_tagging_mon_12pm", timeout=1800)
    # )
    # schedule.every().monday.at('20:00', eastern).do(
    #     lambda: safe_run(run_automated_tanium_onprem_ring_tagging_workflow, name="automated_tanium_onprem_ring_tagging_mon_08pm", timeout=1800)
    # )
    # schedule.every().thursday.at('04:00', eastern).do(
    #     lambda: safe_run(run_automated_tanium_onprem_ring_tagging_workflow, name="automated_tanium_onprem_ring_tagging_thu_04am", timeout=1800)
    # )
    # schedule.every().thursday.at('12:00', eastern).do(
    #     lambda: safe_run(run_automated_tanium_onprem_ring_tagging_workflow, name="automated_tanium_onprem_ring_tagging_thu_12pm", timeout=1800)
    # )
    # schedule.every().thursday.at('20:00', eastern).do(
    #     lambda: safe_run(run_automated_tanium_onprem_ring_tagging_workflow, name="automated_tanium_onprem_ring_tagging_thu_08pm", timeout=1800)
    # )

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
