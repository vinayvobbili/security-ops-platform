import time

import pytz
import schedule

import aging_tickets
import days_since_incident
import de_stories
import heatmap
import mttr_mttc
import outflow
import re_stories
import secops
import sla_breaches
import verify_host_online_status


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
        heatmap.create_choropleth_map()
    ))

    schedule.every(5).minutes.do(verify_host_online_status.start)

    schedule.every().day.at("03:30", pytz.timezone('US/Eastern')).do(lambda: secops.announce_shift_change('morning'))
    schedule.every().day.at("11:30", pytz.timezone('US/Eastern')).do(lambda: secops.announce_shift_change('afternoon'))
    schedule.every().day.at("19:30", pytz.timezone('US/Eastern')).do(lambda: secops.announce_shift_change('night'))

    while True:
        schedule.run_pending()
        time.sleep(60)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
