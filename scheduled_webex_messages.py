import time

import pytz
import schedule

import aging_tickets
import secops_shift_staffing


def main():
    # run once
    # aging_tickets.send_report()

    # schedule
    print("Starting the scheduler...")
    schedule.every().day.at("08:00", pytz.timezone('US/Eastern')).do(lambda: (
        aging_tickets.send_report(),
        # abandoned_tickets.send_report(),
    ))

    schedule.every().day.at("03:30", pytz.timezone('US/Eastern')).do(lambda: secops_shift_staffing.announce_shift_staffing('morning'))
    schedule.every().day.at("11:30", pytz.timezone('US/Eastern')).do(lambda: secops_shift_staffing.announce_shift_staffing('afternoon'))
    schedule.every().day.at("19:30", pytz.timezone('US/Eastern')).do(lambda: secops_shift_staffing.announce_shift_staffing('night'))

    while True:
        schedule.run_pending()
        time.sleep(60)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
