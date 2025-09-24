import time

import pytz
import schedule

from my_config import get_config
from services.xsoar import TicketHandler
from src import helper_methods
from src.charts import mttr_mttc, outflow, lifespan, heatmap, sla_breaches, aging_tickets, inflow, qradar_rule_efficacy, de_stories, days_since_incident, re_stories, threatcon_level, vectra_volume, \
    crowdstrike_volume, threat_tippers, crowdstrike_efficacy
from src.utils.fs_utils import make_dir_for_todays_charts

config = get_config()
eastern = pytz.timezone('US/Eastern')


def scheduler_process():
    # run once to test
    print("Running once to test the scheduler...")
    make_dir_for_todays_charts(helper_methods.CHARTS_DIR_PATH),
    TicketHandler().cache_past_90_days_tickets(),
    aging_tickets.make_chart(),
    days_since_incident.make_chart(),
    crowdstrike_volume.make_chart(),
    crowdstrike_efficacy.make_chart(),
    vectra_volume.make_chart(),
    de_stories.make_chart(),
    heatmap.create_choropleth_map(),
    inflow.make_chart(),
    lifespan.make_chart(),
    mttr_mttc.make_chart(),
    outflow.make_chart(),
    re_stories.make_chart(),
    sla_breaches.make_chart(),
    threatcon_level.make_chart(),
    qradar_rule_efficacy.make_chart(),
    vectra_volume.make_chart(),
    crowdstrike_volume.make_chart(),
    threat_tippers.make_chart(),

    print("Starting the scheduler...")
    schedule.every().day.at("00:01", eastern).do(lambda: (
        make_dir_for_todays_charts(helper_methods.CHARTS_DIR_PATH),
        TicketHandler().cache_past_90_days_tickets(),
        aging_tickets.make_chart(),
        days_since_incident.make_chart(),
        crowdstrike_volume.make_chart(),
        crowdstrike_efficacy.make_chart(),
        vectra_volume.make_chart(),
        de_stories.make_chart(),
        heatmap.create_choropleth_map(),
        inflow.make_chart(),
        lifespan.make_chart(),
        mttr_mttc.make_chart(),
        outflow.make_chart(),
        re_stories.make_chart(),
        sla_breaches.make_chart(),
        threatcon_level.make_chart(),
        qradar_rule_efficacy.make_chart(),
        vectra_volume.make_chart(),
        crowdstrike_volume.make_chart(),
        threat_tippers.make_chart(),
    ))

    while True:
        schedule.run_pending()
        time.sleep(60)


def main():
    scheduler_process()


if __name__ == "__main__":
    main()
