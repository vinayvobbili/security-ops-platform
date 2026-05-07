#!/usr/bin/python3
"""
AI / LLM index scheduler.

Runs embedding-dependent index rebuilds and incremental updates for:
- Tipper similarity index (daily)
- XSOAR ticket similarity index (daily)
- Win.AI IR codebase index (weekly)
- Win.AI XSOAR codebase index (weekly)

Isolated from ir_scheduler so embedding-heavy jobs don't block
operational monitoring and alerting.
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
    bot_name='ai_scheduler',
    log_level=logging.INFO,
    rotate_on_startup=False
)

logger = logging.getLogger(__name__)

import signal
import atexit
from datetime import datetime

logger.warning("=" * 100)
logger.warning(f"AI SCHEDULER STARTED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
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

    target_room = room_id or config.webex_room_id_dev_test_space

    if not target_room:
        logger.warning("Cannot send access issue notification - no room configured")
        return

    webex = _get_webex_api()
    if not webex:
        logger.warning("Cannot send access issue notification - Webex API not available")
        return

    try:
        msg = f"**Access Issues in {job_name}**\n\n"
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
        notify_access_issue(f"AI Scheduler Job: {job_name}", [error_msg], room_id=config.webex_room_id_dev_test_space)
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


_embeddings_down_notified = False


def _check_embeddings_and_rebuild(rebuild_fn, job_name: str, days_back: int = 365) -> None:
    """Run an embedding-dependent index rebuild, notifying dev space if the embedding server is unreachable."""
    global _embeddings_down_notified
    import requests as _req
    try:
        _req.get(f"{config.embeds_base_url}/models", timeout=5)
    except Exception:
        logger.warning(f"Embedding server unreachable at {config.embeds_base_url} — skipping {job_name}")
        if not _embeddings_down_notified:
            _embeddings_down_notified = True
            notify_access_issue(job_name, [
                f"Embedding server is unreachable at {config.embeds_base_url}.",
                "Index rebuilds will fail until the server is restored.",
                "Check LaunchAgent: launchctl list | grep mlx-lm"
            ], room_id=config.webex_room_id_dev_test_space)
        return

    _embeddings_down_notified = False
    result = rebuild_fn(days_back=days_back)
    if not result:
        notify_access_issue(job_name, [
            f"{job_name} returned failure. Check scheduler logs for details."
        ], room_id=config.webex_room_id_dev_test_space)


def _shutdown_handler(_signum=None, _frame=None):
    """Log shutdown marker before exit."""
    logger.warning("=" * 100)
    logger.warning(f"AI SCHEDULER STOPPED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.warning("=" * 100)


def main() -> None:
    """Configure and start the AI index scheduler."""
    print("Starting AI scheduler (embedding indexes)...")
    logger.info("Initializing AI scheduler")

    atexit.register(_shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    # Tipper index rebuild - full rebuild because tipper statuses change over time
    # (New -> Active -> Closed) and similarity search filters to Closed tippers only
    logger.info("Scheduling daily tipper index rebuild (02:10 ET)...")
    def _rebuild_tipper():
        from src.components.tipper_indexer import rebuild_tipper_index
        _check_embeddings_and_rebuild(rebuild_tipper_index, "Tipper Index Rebuild")
    schedule.every().day.at('02:10', eastern).do(
        lambda: safe_run(_rebuild_tipper, name="tipper_index_rebuild", timeout=3600)
    )

    # XSOAR ticket similarity index - incremental sync adds only newly-closed tickets
    logger.info("Scheduling daily XSOAR ticket index sync (03:00 ET)...")
    def _sync_xsoar_index(days_back: int = 365) -> bool:
        from src.components.xsoar_ticket_indexer import sync_xsoar_ticket_index
        added = sync_xsoar_ticket_index(days_back=days_back)
        logger.info(f"XSOAR ticket index sync: {added} new tickets added")
        return True

    schedule.every().day.at('03:00', eastern).do(
        lambda: safe_run(
            lambda: _check_embeddings_and_rebuild(_sync_xsoar_index, "XSOAR Ticket Index Sync"),
            name="xsoar_ticket_index_sync",
        )
    )

    # Win.AI IR codebase index - weekly incremental update (Sunday 03:15 ET)
    logger.info("Scheduling weekly Win.AI IR codebase index update (Sunday 03:15 ET)...")
    def _update_ir():
        from my_bot.document.codebase_indexer import update_ir_index
        _check_embeddings_and_rebuild(
            lambda days_back=10: update_ir_index(),
            "Win.AI IR Codebase Index Update",
        )
    schedule.every().sunday.at('03:15', eastern).do(
        lambda: safe_run(_update_ir, name="win_ai_ir_codebase_index_update", timeout=1800)
    )

    # Win.AI XSOAR codebase index - weekly incremental update (Sunday 03:30 ET)
    logger.info("Scheduling weekly Win.AI XSOAR codebase index update (Sunday 03:30 ET)...")
    def _update_xsoar():
        from my_bot.document.codebase_indexer import update_xsoar_index
        _check_embeddings_and_rebuild(
            lambda days_back=10: update_xsoar_index(),
            "Win.AI XSOAR Codebase Index Update",
        )
    schedule.every().sunday.at('03:30', eastern).do(
        lambda: safe_run(_update_xsoar, name="win_ai_xsoar_codebase_index_update", timeout=3600)
    )

    # Wiki Knowledge Base — weekly incremental compile (Sunday 04:00 ET)
    logger.info("Scheduling weekly wiki compile (Sunday 04:00 ET)...")
    def _compile_wiki():
        from my_bot.document.wiki_compiler import compile_incremental
        _check_embeddings_and_rebuild(
            lambda days_back=365: compile_incremental(),
            "Wiki Knowledge Base Compile",
        )
    schedule.every().sunday.at('04:00', eastern).do(
        lambda: safe_run(_compile_wiki, name="wiki_compile", timeout=3600)
    )

    total_jobs = len(schedule.get_jobs())
    logger.info(f"All jobs scheduled successfully! Total jobs: {total_jobs}")
    logger.info("Entering AI scheduler main loop...")

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
            logger.info("AI scheduler stopped by user")
            break
        except Exception as e:
            logger.error(f"Error in AI scheduler main loop: {e}")
            logger.error(traceback.format_exc())
            time.sleep(5)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
