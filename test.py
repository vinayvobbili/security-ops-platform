import time

import pytz
import schedule
from webex_bot.models.command import Command

import aging_tickets
import de_stories
import mttr_mttc
import re_stories
import sla_breaches
from helper_methods import log_activity


class Test(Command):
    def __init__(self):
        super().__init__(command_keyword="test")

    @log_activity
    def execute(self, message, attachment_actions, activity):
        return "Test passed!"


def main():
    # run once
    # aging_tickets.send_report()

    # schedule
    print("Starting the scheduler...")
    schedule.every().day.at("00:01", pytz.timezone('US/Eastern')).do(lambda: (
        aging_tickets.make_chart(),
        mttr_mttc.make_chart(),
        sla_breaches.make_chart(),
        de_stories.make_chart(),
        re_stories.make_chart()
    ))

    while True:
        schedule.run_pending()
        time.sleep(60)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
