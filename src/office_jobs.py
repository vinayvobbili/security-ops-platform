from src.charts.chart_style import apply_chart_style
apply_chart_style()

import time
import pytz
import schedule

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

config = get_config()
eastern = pytz.timezone('US/Eastern')  # Reserved if we later use a TZ-aware scheduler


def run_all_charts():
    """Generate all charts in a single batch."""
    make_dir_for_todays_charts(helper_methods.CHARTS_DIR_PATH)
    TicketCache.generate()
    aging_tickets.make_chart()
    days_since_incident.make_chart()
    crowdstrike_volume.make_chart()
    crowdstrike_efficacy.make_chart()
    vectra_volume.make_chart()
    de_stories.make_chart()
    heatmap.create_choropleth_map()
    inflow.make_chart()
    lifespan.make_chart()
    mttr_mttc.make_chart()
    outflow.make_chart()
    re_stories.make_chart()
    sla_breaches.make_chart()
    threatcon_level.make_chart()
    qradar_rule_efficacy.make_chart()
    threat_tippers.make_chart()


def scheduler_process():
    # Run once at startup
    print("[office_jobs] Initial run starting...")
    run_all_charts()
    print("[office_jobs] Initial run complete. Scheduling jobs...")

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
