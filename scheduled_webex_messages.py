import time

import pytz
import schedule

import aging_tickets


def main():
    # run once
    # aging_tickets.send_report()

    # schedule
    print("Starting the scheduler...")
    schedule.every().day.at("08:00", pytz.timezone('US/Eastern')).do(aging_tickets.send_report)

    while True:
        schedule.run_pending()
        time.sleep(60)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
