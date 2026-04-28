#!/usr/bin/python3
"""
EPP (Endpoint Protection Platform) job scheduler.

Runs scheduled CrowdStrike and Tanium Cloud ring-tagging workflows on
Mondays and Thursdays. Isolated from ir_scheduler so restarts do not
interrupt these long-running (1-2 hour) jobs.
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
from src.utils.logging_utils import setup_logging

setup_logging(
    bot_name='epp_scheduler',
    log_level=logging.INFO,
    rotate_on_startup=False
)

logger = logging.getLogger(__name__)

import signal
import atexit
from datetime import datetime

logger.warning("=" * 100)
logger.warning(f"EPP SCHEDULER STARTED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
logger.warning("=" * 100)

config = get_config()
eastern = pytz.timezone('US/Eastern')

DEFAULT_JOB_TIMEOUT = 1800

_job_failure_notified: set = set()
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
    """Send Webex notification about access/permission issues."""
    if not issues:
        return

    target_room = room_id or config.webex_room_id_threat_tipper_analysis

    if not target_room:
        logger.warning("Cannot send access issue notification - no room configured")
        return

    webex = _get_webex_api()
    if not webex:
        logger.warning("Cannot send access issue notification - Webex API not available")
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
        notify_access_issue(f"EPP Scheduler Job: {job_name}", [error_msg], room_id=config.webex_room_id_dev_test_space)
    except Exception as e:
        logger.error(f"Failed to send job failure notification for {job_name}: {e}")


def safe_run(*jobs: Callable[[], None], timeout: int = DEFAULT_JOB_TIMEOUT, name: str = None, blocking: bool = True) -> None:
    """Execute multiple jobs safely with timeout protection."""
    import threading
    if not jobs:
        logger.debug("safe_run() called with 0 jobs - nothing to do")
        return
    logger.debug(f"safe_run() running {len(jobs)} job(s) with timeout={timeout}s, blocking={blocking}")

    def run_all_jobs():
        for i, job in enumerate(jobs):
            if name:
                job_name = name if len(jobs) == 1 else f"{name}[{i + 1}/{len(jobs)}]"
            else:
                job_name = getattr(job, '__name__', repr(job))
            _run_job_with_timeout(job, job_name, timeout)

    if blocking:
        run_all_jobs()
    else:
        thread = threading.Thread(target=run_all_jobs, daemon=True)
        thread.start()
        logger.debug("Job(s) started in background thread")


def _shutdown_handler(_signum=None, _frame=None):
    """Log shutdown marker before exit."""
    logger.warning("=" * 100)
    logger.warning(f"EPP SCHEDULER STOPPED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.warning("=" * 100)


def main() -> None:
    """Configure and start the EPP job scheduler."""
    print("Starting EPP scheduler (CrowdStrike + Tanium ring tagging)...")
    logger.info("Initializing EPP scheduler")

    atexit.register(_shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    # Weekly MGCC migration cache refresh (Sun 02:00 ET)
    # This produces Tanium_MGCC_Hosts_cloud.xlsx — the whitelist that the ring-tagging
    # job uses to narrow MGCC migration candidates from ~85K hosts down to ~7K. Without
    # a fresh cache (>14 days old), the ring-tagging job skips the migration branch.
    # Long timeout (3 hours) — nothing else is waiting on it.
    logger.info("Scheduling weekly MGCC migration cache refresh (Sun 02:00 ET)...")
    def _run_mgcc_cache_refresh():
        from src.epp.tanium_mgcc_hosts import create_processor as create_mgcc_processor
        processor = create_mgcc_processor(instance_filter="cloud")
        processor.process()

    schedule.every().sunday.at('02:00', eastern).do(
        lambda: safe_run(_run_mgcc_cache_refresh, name="weekly_mgcc_cache_refresh", timeout=10800, blocking=False)
    )

    total_jobs = len(schedule.get_jobs())
    logger.info(f"All jobs scheduled successfully! Total jobs: {total_jobs}")
    logger.info("Entering EPP scheduler main loop...")

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
            logger.info("EPP scheduler stopped by user")
            break
        except Exception as e:
            logger.error(f"Error in EPP scheduler main loop: {e}")
            logger.error(traceback.format_exc())
            time.sleep(5)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
