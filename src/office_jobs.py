import time

import pytz
import schedule

from config import get_config
from services import crowdstrike
from src import helper_methods
from src.charts import mttr_mttc, outflow, lifespan, heatmap, sla_breaches, aging_tickets, inflow, qradar_rule_efficacy, de_stories, days_since_incident, re_stories, threatcon_level, vectra_volume, \
    crowdstrike_volume, threat_tippers, crowdstrike_efficacy

config = get_config()
eastern = pytz.timezone('US/Eastern')


def main():
    """
    Main function to run the scheduled jobs.
    """

    # schedule
    print("Starting the scheduler...")

    schedule.every().day.at("00:01", eastern).do(lambda: (
        helper_methods.make_dir_for_todays_charts(),
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
        crowdstrike.update_unique_hosts_from_cs()
    ))

    while True:
        schedule.run_pending()
        time.sleep(60)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
