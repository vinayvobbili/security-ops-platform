import time

import pytz
import schedule

import aging_tickets
import de_stories
import re_stories


def main():
    # run once
    # aging_tickets.send_report()

    # schedule
    print("Starting the scheduler...")
    schedule.every().day.at("08:00", pytz.timezone('US/Eastern')).do(aging_tickets.send_report)
    schedule.every().day.at("00:01", pytz.timezone('US/Eastern')).do(de_stories.make_chart)
    schedule.every().day.at("00:01", pytz.timezone('US/Eastern')).do(re_stories.make_chart)

    while True:
        schedule.run_pending()
        time.sleep(60)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
