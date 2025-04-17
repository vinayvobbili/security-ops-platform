import time

import pytz
import schedule

import secops
import verify_host_online_status
from config import get_config
from services import phish_fort
from src import helper_methods
from src.charts import mttr_mttc, outflow, lifespan, heatmap, sla_breaches, aging_tickets, inflow, qradar_rule_efficacy, de_stories, days_since_incident, re_stories, threatcon_level, vectra_volume, \
    crowdstrike_volume, threat_tippers
from src.components import oncall, approved_security_testing

config = get_config()
eastern = pytz.timezone('US/Eastern')


def main():
    """
    Main function to run the scheduled jobs.
    """
    # run once
    helper_methods.make_dir_for_todays_charts()
    aging_tickets.make_chart()
    days_since_incident.make_chart()
    crowdstrike_volume.make_chart()
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
    secops.announce_shift_change('night', config.webex_room_id_vinay_test_space)
    # qradar_rule_efficacy.send_charts()
    # phish_fort.fetch_and_report_incidents()
    # thithi.notify()

    # schedule
    print("Starting the scheduler...")
    schedule.every().day.at("08:00", eastern).do(lambda: (
        aging_tickets.send_report(config.webex_room_id_aging_tickets),
        # abandoned_tickets.send_report(),
    ))

    schedule.every().day.at("00:01", eastern).do(lambda: (
        helper_methods.make_dir_for_todays_charts(),
        aging_tickets.make_chart(),
        days_since_incident.make_chart(),
        crowdstrike_volume.make_chart(),
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
        threat_tippers.make_chart()
    ))

    schedule.every(5).minutes.do(verify_host_online_status.start)
    room_id = config.webex_room_id_soc_shift_updates
    schedule.every().day.at("04:30", eastern).do(lambda: secops.announce_shift_change('morning', room_id))
    schedule.every().day.at("12:30", eastern).do(lambda: secops.announce_shift_change('afternoon', room_id))
    schedule.every().day.at("20:30", eastern).do(lambda: secops.announce_shift_change('night', room_id))
    schedule.every().friday.at("08:00", eastern).do(lambda: qradar_rule_efficacy.send_charts())
    schedule.every().friday.at("14:00", eastern).do(lambda: oncall.alert_change())
    schedule.every().monday.at("08:00", eastern).do(lambda: (
        phish_fort.fetch_and_report_incidents(),
        oncall.announce_change()
    ))
    schedule.every().day.at("17:00", eastern).do(approved_security_testing.removed_expired_entries)
    # schedule.every().day.at("08:00", eastern).do(thithi.notify)

    while True:
        schedule.run_pending()
        time.sleep(60)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
