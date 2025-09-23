import logging
import time

import pytz
import schedule

import secops
from my_config import get_config
from services.xsoar import TicketHandler  # Added import for caching past 90 days tickets
from src import helper_methods, verify_host_online_status
from src.charts import mttr_mttc, outflow, lifespan, heatmap, sla_breaches, aging_tickets, inflow, qradar_rule_efficacy, de_stories, days_since_incident, re_stories, threatcon_level, vectra_volume, \
    crowdstrike_volume, threat_tippers, crowdstrike_efficacy
from src.components import oncall, approved_security_testing, thithi, qa_tickets, response_sla_risk_tickets, containment_sla_risk_tickets, incident_declaration_sla_risk
from src.utils.fs_utils import make_dir_for_todays_charts

logging.basicConfig(level=logging.ERROR)
logging.getLogger("webexpythonsdk.restsession").setLevel(logging.ERROR)
logging.getLogger("webexteamssdk.restsession").setLevel(logging.ERROR)
logging.getLogger("openpyxl").setLevel(logging.ERROR)

config = get_config()
eastern = pytz.timezone('US/Eastern')


def main():
    """
    Main function to run the scheduled jobs.
    """
    # run once to test
    # print("Running once to test the scheduler...")
    # make_dir_for_todays_charts(helper_methods.CHARTS_DIR_PATH)
    # aging_tickets.make_chart()
    # crowdstrike_efficacy.make_chart()
    # crowdstrike_volume.make_chart()
    # days_since_incident.make_chart()
    # de_stories.make_chart()
    # heatmap.create_choropleth_map()
    # inflow.make_chart()
    # lifespan.make_chart()
    # mttr_mttc.make_chart()
    # outflow.make_chart()
    # qradar_rule_efficacy.make_chart()
    # re_stories.make_chart()
    # sla_breaches.make_chart()
    # threat_tippers.make_chart()
    # threatcon_level.make_chart()
    # vectra_volume.make_chart()
    # secops.announce_shift_change('afternoon', config.webex_room_id_vinay_test_space)
    # # qradar_rule_efficacy.send_charts()
    # # phish_fort.fetch_and_report_incidents()
    # aging_tickets.send_report(config.webex_room_id_vinay_test_space)

    # schedule
    print("Starting the scheduler...")
    # schedule.every().day.at("08:00", eastern).do(lambda: (
    #     aging_tickets.send_report(config.webex_room_id_aging_tickets),
    #     # abandoned_tickets.send_report(),
    #     orphaned_tickets.send_report(config.webex_room_id_aging_tickets)
    # ))

    schedule.every().day.at("00:01", eastern).do(lambda: (
        make_dir_for_todays_charts(helper_methods.CHARTS_DIR_PATH),
        TicketHandler().cache_past_90_days_tickets(),
        aging_tickets.make_chart(),
        crowdstrike_efficacy.make_chart(),
        crowdstrike_volume.make_chart(),
        days_since_incident.make_chart(),
        de_stories.make_chart(),
        heatmap.create_choropleth_map(),
        inflow.make_chart(),
        lifespan.make_chart(),
        mttr_mttc.make_chart(),
        outflow.make_chart(),
        qradar_rule_efficacy.make_chart(),
        re_stories.make_chart(),
        sla_breaches.make_chart(),
        threat_tippers.make_chart(),
        threatcon_level.make_chart(),
        vectra_volume.make_chart(),
    ))

    schedule.every(5).minutes.do(verify_host_online_status.start)

    room_id = config.webex_room_id_soc_shift_updates
    schedule.every().day.at("04:30", eastern).do(lambda: secops.announce_shift_change('morning', room_id))
    schedule.every().day.at("12:30", eastern).do(lambda: secops.announce_shift_change('afternoon', room_id))
    schedule.every().day.at("20:30", eastern).do(lambda: secops.announce_shift_change('night', room_id))
    schedule.every().friday.at("08:00", eastern).do(lambda: (
        qradar_rule_efficacy.send_charts(),
        crowdstrike_efficacy.send_charts()
    ))
    schedule.every().friday.at("14:00", eastern).do(lambda: oncall.alert_change())
    schedule.every().monday.at("08:00", eastern).do(lambda: (
        # phish_fort.fetch_and_report_incidents(),
        oncall.announce_change(),
        qa_tickets.generate, config.webex_room_id_qa_tickets
    ))
    schedule.every().day.at("17:00", eastern).do(approved_security_testing.removed_expired_entries)
    schedule.every().day.at("07:00", eastern).do(thithi.main)
    schedule.every(1).minutes.do(lambda: response_sla_risk_tickets.start(config.webex_room_id_response_sla_risk))
    schedule.every(3).minutes.do(lambda: containment_sla_risk_tickets.start(config.webex_room_id_containment_sla_risk))
    schedule.every().hour.at(":00").do(lambda: incident_declaration_sla_risk.start(config.webex_room_id_response_sla_risk))

    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
