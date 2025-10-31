#!/usr/bin/python3

from src.charts.chart_style import apply_chart_style

apply_chart_style()

import time
import pytz
import schedule
import logging
from time import perf_counter
from datetime import datetime

from my_config import get_config
from src import helper_methods
from src.charts import (
    mttr_mttc,
    outflow,
    lifespan,
    heatmap,
    sla_breaches,
    aging_tickets,
    inflow,
    qradar_rule_efficacy,
    de_stories,
    days_since_incident,
    re_stories,
    threatcon_level,
    vectra_volume,
    crowdstrike_volume,
    threat_tippers,
    crowdstrike_efficacy,
)
from src.components.ticket_cache import TicketCache
from src.utils.fs_utils import make_dir_for_todays_charts

# --- Logging Setup ---
logger = logging.getLogger("office_jobs")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(name)s - %(message)s'
    )

config = get_config()
eastern = pytz.timezone('US/Eastern')  # Reserved if we later use a TZ-aware scheduler


def _time_task(name: str, func):
    """Execute a chart generation function with timing and logging.

    Returns tuple: (name, elapsed_seconds, success_bool, exception_or_None)
    """
    start = perf_counter()
    try:
        func()
        elapsed = perf_counter() - start
        logger.info("Chart '%s' generated in %.2f s", name, elapsed)
        return name, elapsed, True, None
    except Exception as exc:  # noqa: BLE001 - we want to log any exception
        elapsed = perf_counter() - start
        logger.exception("Chart '%s' FAILED after %.2f s: %s", name, elapsed, exc)
        return name, elapsed, False, exc


def run_all_charts():
    """Generate all charts in a single batch with per-chart timing & summary logging."""
    overall_start = perf_counter()

    make_dir_for_todays_charts(helper_methods.CHARTS_DIR_PATH)

    # Treat cache generation as its own timed step (optional chart-like step)
    # cache_result = _time_task("Ticket Cache", TicketCache.generate)

    tasks = [
        ("Aging Tickets", aging_tickets.make_chart),
        ("Days Since Incident", days_since_incident.make_chart),
        ("CrowdStrike Volume", crowdstrike_volume.make_chart),
        ("CrowdStrike Efficacy", crowdstrike_efficacy.make_chart),
        ("Vectra Volume", vectra_volume.make_chart),
        ("Detection Engineering Stories", de_stories.make_chart),
        ("Threat Heatmap", heatmap.create_choropleth_map),
        ("Inflow", inflow.make_chart),
        ("Lifespan", lifespan.make_chart),
        ("MTTR MTTC", mttr_mttc.make_chart),
        ("Outflow", outflow.make_chart),
        ("Response Engineering Stories", re_stories.make_chart),
        ("SLA Breaches", sla_breaches.make_chart),
        ("ThreatCon Level", threatcon_level.make_chart),
        ("QRadar Rule Efficacy", qradar_rule_efficacy.make_chart),
        ("Threat Tippers", threat_tippers.make_chart),
    ]

    results = []

    for name, func in tasks:
        results.append(_time_task(name, func))

    total_elapsed = perf_counter() - overall_start

    # Build summary
    success = [r for r in results if r[2]]
    failed = [r for r in results if not r[2]]

    logger.info("Charts summary: %d succeeded, %d failed (excluding cache step)", len(success), len(failed))
    if failed:
        for name, elapsed, _, err in failed:
            logger.warning(" - FAILED: %s (%.2f s) -> %s", name, elapsed, err)

    # Sort by elapsed time (descending) for performance insight
    longest = sorted(results, key=lambda r: r[1], reverse=True)[:5]
    logger.info("Top slowest charts:")
    for name, elapsed, ok, _ in longest:
        logger.info(" - %s: %.2f s (%s)", name, elapsed, "ok" if ok else "fail")

    # Add total line
    logger.info("Full run (including cache) completed in %.2f s at %s", total_elapsed, datetime.now().isoformat(timespec='seconds'))

    # Return data structure if callers want to introspect
    return {
        # 'cache': cache_result,
        'charts': results,
        'total_seconds': total_elapsed,
    }


def scheduler_process():
    # Run once at startup
    logger.info("[office_jobs] Initial run starting...")
    run_all_charts()
    logger.info("[office_jobs] Initial run complete. Scheduling jobs...")

    # Hourly cache refresh on the hour
    schedule.every().hour.at(":00").do(TicketCache.generate)

    # Daily full chart run at 00:01 local system time (schedule isn't TZ-aware)
    schedule.every().day.at("00:01").do(run_all_charts)

    while True:
        schedule.run_pending()
        time.sleep(60)


def main():
    scheduler_process()


if __name__ == "__main__":
    main()
