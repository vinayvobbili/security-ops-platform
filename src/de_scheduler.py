#!/usr/bin/python3
"""
Detection Engineering (DE) scheduler.

Runs scheduled tasks for detection rule syncs, threat intelligence
enrichment, tipper analysis, and domain/asset monitoring:
- Detection rules catalog sync (daily)
- Tanium signals catalog sync (daily)
- Threat intel dashboard sync (daily)
- Threat intel IOC enrichment (daily)
- Hourly tipper analysis (business hours)
- Domain monitoring + watchlist poller (daily + every 15 min)
- Salesforce guest-access scan (daily) — DISABLED

Isolated from ir_scheduler so detection engineering workflows have
their own process lifecycle.
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
    bot_name='de_scheduler',
    log_level=logging.INFO,
    rotate_on_startup=False
)

logger = logging.getLogger(__name__)

import signal
import atexit
from datetime import datetime

logger.warning("=" * 100)
logger.warning(f"DE SCHEDULER STARTED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
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
            if config.webex_bot_access_token_sleuth:
                _webex_api = WebexAPI(access_token=config.webex_bot_access_token_sleuth)
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
        notify_access_issue(f"DE Scheduler Job: {job_name}", [error_msg], room_id=config.webex_room_id_dev_test_space)
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


def _lazy_component(module_path: str, func_name: str, *args, **kwargs) -> Callable[[], None]:
    """Create a lazy-loading wrapper for a component function."""
    def _run():
        import importlib
        mod = importlib.import_module(module_path)
        getattr(mod, func_name)(*args, **kwargs)
    _run.__name__ = f'{module_path.split(".")[-1]}.{func_name}'
    return _run


def schedule_daily(time_str: str, *jobs: Callable[[], None], name: str = None) -> None:
    """Schedule jobs to run daily at a given time (Eastern)."""
    schedule.every().day.at(time_str, eastern).do(lambda: safe_run(*jobs, name=name))


def schedule_business_hours(
        minute: int,
        job: Callable[[], None],
        name: str = None,
        timeout: int = DEFAULT_JOB_TIMEOUT,
        start_hour: int = 9,
        end_hour: int = 18
) -> None:
    """Schedule a job to run during US business hours (Mon-Fri, Eastern timezone)."""
    job_name = name or job.__name__
    for hour in range(start_hour, end_hour + 1):
        time_str = f"{hour:02d}:{minute:02d}"
        schedule.every().monday.at(time_str, eastern).do(lambda j=job, t=timeout, n=name: safe_run(j, timeout=t, name=n))
        schedule.every().tuesday.at(time_str, eastern).do(lambda j=job, t=timeout, n=name: safe_run(j, timeout=t, name=n))
        schedule.every().wednesday.at(time_str, eastern).do(lambda j=job, t=timeout, n=name: safe_run(j, timeout=t, name=n))
        schedule.every().thursday.at(time_str, eastern).do(lambda j=job, t=timeout, n=name: safe_run(j, timeout=t, name=n))
        schedule.every().friday.at(time_str, eastern).do(lambda j=job, t=timeout, n=name: safe_run(j, timeout=t, name=n))
    logger.info(f"Scheduled '{job_name}' Mon-Fri {start_hour}:00-{end_hour}:00 ET at :{minute:02d}")


def sync_catalog_with_notifications() -> None:
    """Sync detection rules catalog and notify on access issues."""
    from src.components.tipper_analyzer.rules.sync import sync_catalog
    result = sync_catalog()

    access_issues = []
    for platform_status in result.platforms:
        if not platform_status.success and platform_status.error:
            error_lower = platform_status.error.lower()
            if 'auth' in error_lower or 'permission' in error_lower or 'access' in error_lower or 'forbidden' in error_lower:
                access_issues.append(f"{platform_status.platform}: {platform_status.error}")
        elif platform_status.error and 'using cache' in platform_status.error.lower():
            access_issues.append(f"{platform_status.platform}: API unavailable (using cached rules)")

    if access_issues:
        notify_access_issue("Rules Catalog Sync", access_issues, room_id=config.webex_room_id_dev_test_space)


def sync_tanium_signals_with_notifications() -> None:
    """Sync Tanium signals catalog and notify on access issues."""
    from src.components.tanium_signals_sync import sync_tanium_signals_catalog
    result = sync_tanium_signals_catalog()

    access_issues = []
    if result.get('skipped'):
        for error in result.get('errors', []):
            if 'permission' in error.lower() or 'no tanium' in error.lower() or 'token' in error.lower():
                access_issues.append(error)

    if result.get('signals_count', 0) == 0 and not result.get('skipped'):
        access_issues.append("No signals fetched from Tanium - check API permissions")

    if access_issues:
        notify_access_issue("Tanium Signals Sync", access_issues, room_id=config.webex_room_id_dev_test_space)


def _shutdown_handler(_signum=None, _frame=None):
    """Log shutdown marker before exit."""
    logger.warning("=" * 100)
    logger.warning(f"DE SCHEDULER STOPPED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.warning("=" * 100)


def main() -> None:
    """Configure and start the DE scheduler."""
    print("Starting DE scheduler (detection rules + tipper analysis)...")
    logger.info("Initializing DE scheduler")

    atexit.register(_shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    # Detection rules catalog sync - refreshes CrowdStrike and QRadar rules
    logger.info("Scheduling daily detection rules sync (02:00 ET)...")
    schedule_daily('02:00', sync_catalog_with_notifications, name="detection_rules_sync")

    # Tanium signals catalog sync
    logger.info("Scheduling daily Tanium signals sync (02:05 ET)...")
    schedule_daily('02:05', sync_tanium_signals_with_notifications, name="tanium_signals_sync")

    # Threat intel dashboard sync - populates SQLite DB with entity-extracted tipper insights
    logger.info("Scheduling daily threat intel dashboard sync (02:15 ET)...")
    schedule_daily('02:15', _lazy_component('services.threat_intel_db', 'sync_tippers', days_back=7),
                   name="threat_intel_dashboard_sync")

    # Threat intel IOC enrichment - VT verdicts and RF risk scores for top IOCs
    logger.info("Scheduling daily threat intel enrichment (02:20 ET)...")
    schedule_daily('02:20', _lazy_component('services.threat_intel_db', 'enrich_top_iocs', vt_limit=50, rf_limit=200),
                   name="threat_intel_enrichment")

    # AttackIQ BAS auto-fire — runs the tipper assessments that 02:15 sync just
    # BUILT (status='created') at the small SOC-approved test asset group,
    # throttled to a per-night scenario budget so a tipper spike drains over
    # several nights instead of firing in one window. Closes the loop: the
    # 02:55 results poll then picks up the detection outcomes for the matrix.
    # Blast radius is re-verified per fire (small curated group only).
    logger.info("Scheduling daily AttackIQ BAS auto-fire (02:25 ET, 25 scenarios/night)...")
    schedule.every().day.at('02:25', eastern).do(
        lambda: safe_run(
            _lazy_component('services.threat_intel_db', 'auto_fire_pending_assessments', max_scenarios=25),
            name="attackiq_auto_fire", timeout=1800)
    )

    # GitHub critical Security Advisory monitor — hourly poll of reviewed+critical
    # advisories; Webex digest (Aide) + AppSec email on new, dedup'd advisories.
    logger.info("Scheduling GitHub critical advisory monitor (hourly at :00)...")
    schedule.every().hour.at(':00').do(
        lambda: safe_run(
            _lazy_component('services.github_advisories', 'poll_critical_advisories',
                            room_id=config.webex_room_id_dev_test_space),
            name="github_critical_advisories", timeout=900)
    )

    # Veracode SCA exposure index — daily rebuild (24h TTL). The portfolio
    # findings report is ~240k rows / ~6 min, so it's built here as a background
    # job; advisory + tipper CVE lookups only ever read the warm SQLite cache.
    logger.info("Scheduling daily Veracode SCA index refresh (02:40 ET)...")
    schedule.every().day.at('02:40', eastern).do(
        lambda: safe_run(
            _lazy_component('services.veracode', 'refresh_index'),
            name="veracode_sca_index_refresh", timeout=1800)
    )

    # AttackIQ BAS validation overlay — nightly, read-only. The index maps the
    # matrix's MITRE techniques to AttackIQ scenarios (tag lookups, rate-limited
    # ~3s/req), then the poll pulls recent run results and records per-technique
    # detection_outcome so the ATT&CK matrix can show "did our detection fire?".
    logger.info("Scheduling nightly AttackIQ technique-scenario index (02:45 ET)...")
    schedule.every().day.at('02:45', eastern).do(
        lambda: safe_run(
            _lazy_component('services.threat_intel_db', 'refresh_technique_scenario_index'),
            name="attackiq_technique_index", timeout=1800)
    )
    logger.info("Scheduling nightly AttackIQ results poll (02:55 ET)...")
    schedule.every().day.at('02:55', eastern).do(
        lambda: safe_run(
            _lazy_component('services.threat_intel_db', 'refresh_attackiq_results'),
            name="attackiq_results_poll", timeout=600)
    )

    # Hourly tipper analysis - analyzes new tippers and sends to Webex
    tipper_analysis_room = config.webex_room_id_threat_tipper_analysis
    if tipper_analysis_room:
        import json as _json
        from datetime import timezone as _tz

        _TIPPER_LAST_RUN_FILE = Path(__file__).parent.parent / "data/transient/tipper_analysis_last_run.json"
        _TIPPER_MAX_LOOKBACK_HOURS = 18

        def _run_tipper_analysis() -> None:
            from src.components.tipper_analyzer import analyze_recent_tippers
            hours_back = 1
            try:
                if _TIPPER_LAST_RUN_FILE.exists():
                    last_run_iso = _json.loads(_TIPPER_LAST_RUN_FILE.read_text()).get("last_run")
                    if last_run_iso:
                        gap_hours = (datetime.now(_tz.utc) - datetime.fromisoformat(last_run_iso)).total_seconds() / 3600
                        hours_back = min(max(gap_hours, 1), _TIPPER_MAX_LOOKBACK_HOURS)
                        if hours_back > 1.5:
                            logger.info(f"[Tipper Analysis] Widened lookback to {hours_back:.1f}h (last run: {last_run_iso})")
            except Exception as e:
                logger.warning(f"[Tipper Analysis] Failed to read last-run state: {e}")

            import math
            analyze_recent_tippers(hours_back=math.ceil(hours_back), room_id=tipper_analysis_room)

            try:
                _TIPPER_LAST_RUN_FILE.parent.mkdir(parents=True, exist_ok=True)
                _TIPPER_LAST_RUN_FILE.write_text(_json.dumps({"last_run": datetime.now(_tz.utc).isoformat()}))
            except OSError as e:
                logger.warning(f"[Tipper Analysis] Failed to save last-run state: {e}")

        from src.utils.webex_utils import get_room_name
        room_name = get_room_name(tipper_analysis_room, config.webex_bot_access_token_sleuth) or "Unknown"
        logger.info(f"Tipper analysis will send to room: {room_name}")

        schedule_business_hours(
            15,
            _run_tipper_analysis,
            name="business_hours_tipper_analysis",
            timeout=900
        )
    else:
        logger.warning("Hourly tipper analysis DISABLED (no TIPPER_ANALYSIS_ROOM_ID configured)")

    # Domain lookalike, dark web, and brand impersonation monitoring.
    # The full per-brand pipeline (dnstwist + WHOIS/VT/Shodan/HIBP/abuse checks)
    # is minutes per brand and a single run has a hard 30-minute timeout, so the
    # scan is STAGGERED across the morning: each slot scans a disjoint partition
    # of the monitored brands and merges into the shared day report; slot 0 also
    # runs the once-per-day global sweeps (RF watchlist + brand-keyword CT). A
    # final job posts one consolidated summary. Brands are partitioned at run
    # time, so adding a brand via the management UI needs no scheduler restart.
    _DOMAIN_MON_SLOTS = ['08:00', '08:30', '09:00', '09:30',
                         '10:00', '10:30', '11:00', '11:30']
    _total_slots = len(_DOMAIN_MON_SLOTS)
    logger.info(f"Scheduling staggered domain monitoring ({_total_slots} slots, 08:00–11:30 ET)...")
    for _idx, _slot_time in enumerate(_DOMAIN_MON_SLOTS):
        schedule_daily(_slot_time,
                       _lazy_component('src.components.domain_monitoring', 'run_brand_slot',
                                       slot_index=_idx, total_slots=_total_slots),
                       name=f"domain_monitoring_slot_{_idx}")
    # Consolidated daily summary after the last slot completes.
    logger.info("Scheduling consolidated domain monitoring summary (12:00 ET)...")
    schedule_daily('12:00',
                   _lazy_component('src.components.domain_monitoring', 'send_daily_summary_now'),
                   name="domain_monitoring_summary")

    # PhishFort takedown-status sync — reconciles incident statuses into the
    # findings ledger so the leadership report's SLA tiles (time-to-takedown,
    # % contained) reflect live progress. Twice daily is plenty (takedowns
    # resolve over days, not minutes).
    logger.info("Scheduling PhishFort takedown-status sync (12:15 + 17:15 ET)...")
    for _sync_time in ('12:15', '17:15'):
        schedule_daily(_sync_time,
                       _lazy_component('services.phish_fort', 'sync_phishfort_statuses'),
                       name="phishfort_status_sync")

    # Age out stale findings by ARCHIVING only (reversibly hide) — never hard
    # delete. Threat actors register lookalikes and let them sit dormant for
    # months before weaponizing, so a quiet domain at day 31 is precisely the one
    # we must NOT forget: dropping its row loses first_seen ("registered N months
    # ago, just went live" is a top signal) and its history in the monthly report.
    # Storage for archived rows is trivial, so we keep them indefinitely.
    #   12:40 — archive anything quiet for 7 days (guarded; reversible).
    # The 30-day hard prune (prune_stale_findings) is intentionally NOT scheduled
    # — it remains for manual ops only. Re-add a schedule_daily here to re-enable.
    logger.info("Scheduling stale-findings archive (12:40) ET daily (no auto-prune)...")
    schedule_daily('12:40',
                   _lazy_component('src.components.domain_monitoring.findings_ledger',
                                   'archive_stale_findings'),
                   name="domain_monitoring_archive")

    # Monthly Brand-Protection report — generated + posted on the 1st (the
    # `schedule` library has no native monthly trigger, so a daily job guards on
    # the day-of-month).
    def _post_monthly_brand_report_if_first() -> None:
        if datetime.now(eastern).day != 1:
            return
        from src.components.domain_monitoring.monthly_report import post_monthly_report
        post_monthly_report()
    logger.info("Scheduling monthly Brand-Protection report (1st of month, 13:00 ET)...")
    schedule_daily('13:00', _post_monthly_brand_report_if_first,
                   name="domain_monitoring_monthly_report")

    # Tanium installed-software inventory sync — feeds the CVE exposure correlator
    logger.info("Scheduling Tanium software inventory sync (04:30 ET)...")
    def _run_tanium_inventory_sync() -> None:
        from services.tanium_inventory import sync_inventory
        result = sync_inventory()
        logger.info(f"[Tanium Inventory] synced {result['row_count']} rows in "
                    f"{result['duration_sec']:.1f}s from {result['instances']}")
    schedule_daily('04:30', _run_tanium_inventory_sync, name="tanium_inventory_sync")

    # Realtime watchlist poller — lightweight DNS/HTTP/SSL checks for high-priority domains
    logger.debug("Scheduling domain watchlist poller every 15 minutes...")
    schedule.every(15).minutes.do(
        lambda: safe_run(_lazy_component('src.components.domain_monitoring', 'poll_watchlist'),
                         name="domain_watchlist_poller", timeout=120)
    )

    # Weekly heartbeat for watchlist poller — confirms it's alive
    logger.info("Scheduling watchlist poller heartbeat (Mondays 08:05 ET)...")
    schedule.every().monday.at('08:05', eastern).do(
        lambda: safe_run(_lazy_component('src.components.domain_monitoring', 'send_watchlist_heartbeat'),
                         name="watchlist_heartbeat", timeout=30)
    )

    # Daily Salesforce guest-access scan — DISABLED 2026-05-03 (per user request)
    # logger.info("Scheduling daily Salesforce scan (08:30 ET)...")
    # def _run_sf_daily_scan():
    #     from services.salesforce_scanner import scan_sites, load_targets
    #     from services.sf_scanner_db import save_scan
    #
    #     targets = load_targets()
    #     results = []
    #     report_data = {}
    #     for event_type, data in scan_sites(targets):
    #         if event_type == "result":
    #             results.append(data)
    #         elif event_type == "complete":
    #             report_data = data
    #
    #     # Persist to DB
    #     try:
    #         save_scan(report_data)
    #     except Exception as e:
    #         logger.error(f"SF scan: failed to save results: {e}")
    #
    #     # Alert on findings
    #     fails = [r for r in results if r.get("status") == "FAIL"]
    #     if not fails:
    #         logger.info(f"SF daily scan: all clear ({len(results)} checks passed)")
    #         return
    #
    #     webex = _get_webex_api()
    #     room_id = config.webex_room_id_domain_monitoring
    #     if not webex or not room_id:
    #         logger.warning("SF scan: findings detected but Webex/room not configured")
    #         return
    #
    #     lines = [f"🚨 **Salesforce Guest Access — {len(fails)} Finding(s)**\n"]
    #     for f in fails:
    #         pii = f""
    #         if f.get("pii_fields"):
    #             pii = f"  ⚠️ PII: {', '.join(f['pii_fields'])}"
    #         lines.append(f"- **{f['check']}** on `{f['base_url']}`  \n  {f['detail']}{pii}")
    #     lines.append(f"\n_Scanned {len(results)} checks across {len(targets)} site(s)_")
    #     try:
    #         webex.messages.create(roomId=room_id, markdown="\n".join(lines))
    #     except Exception as e:
    #         logger.error(f"SF scan: failed to send Webex alert: {e}")
    #
    # schedule_daily('08:30', _run_sf_daily_scan, name="salesforce_daily_scan")

    total_jobs = len(schedule.get_jobs())
    logger.info(f"All jobs scheduled successfully! Total jobs: {total_jobs}")
    logger.info("Entering DE scheduler main loop...")

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
            logger.info("DE scheduler stopped by user")
            break
        except Exception as e:
            logger.error(f"Error in DE scheduler main loop: {e}")
            logger.error(traceback.format_exc())
            time.sleep(5)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
