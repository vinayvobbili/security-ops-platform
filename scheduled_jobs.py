import time

import pytz
import schedule

import aging_tickets
import days_since_incident
import de_stories
import mttr_mttc
import outflow
import re_stories
import secops
import sla_breaches
import threatcon_level
import verify_host_online_status
from config import get_config

config = get_config()


def main():
    """
    Main function to run the scheduled jobs.
    """
    # run once
    '''
    aging_tickets.make_chart(),
    mttr_mttc.make_chart(),
    sla_breaches.make_chart(),
    outflow.make_chart(),
    # heatmap.create_choropleth_map(),
    threatcon_level.make_chart(),
    '''

    # schedule
    print("Starting the scheduler...")
    schedule.every().day.at("08:00", pytz.timezone('US/Eastern')).do(lambda: (
        aging_tickets.send_report(),
        # abandoned_tickets.send_report(),
    ))

    schedule.every().day.at("00:01", pytz.timezone('US/Eastern')).do(lambda: (
        aging_tickets.make_chart(),
        mttr_mttc.make_chart(),
        sla_breaches.make_chart(),
        de_stories.make_chart(),
        re_stories.make_chart(),
        days_since_incident.make_chart(),
        outflow.make_chart(),
        threatcon_level.make_chart(),
    ))

    schedule.every(5).minutes.do(verify_host_online_status.start)
    room_id = config.webex_room_id_soc_shift_updates
    schedule.every().day.at("03:30", pytz.timezone('US/Eastern')).do(lambda: secops.announce_shift_change('morning', room_id))
    schedule.every().day.at("11:30", pytz.timezone('US/Eastern')).do(lambda: secops.announce_shift_change('afternoon', room_id))
    schedule.every().day.at("19:30", pytz.timezone('US/Eastern')).do(lambda: secops.announce_shift_change('night', room_id))

    while True:
        schedule.run_pending()
        time.sleep(60)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
