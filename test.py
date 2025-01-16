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


schedule.every().day.at("11:29", pytz.timezone('US/Eastern')).do(lambda: (
    aging_tickets.make_chart(),
    mttr_mttc.make_chart(),
    sla_breaches.make_chart(),
    de_stories.make_chart(),
    re_stories.make_chart()
))
# schedule.every().day.at("11:29", pytz.timezone('US/Eastern')).do(aging_tickets.make_chart)
# schedule.every().day.at("11:30", pytz.timezone('US/Eastern')).do(mttr_mttc.make_chart)
# schedule.every().day.at("11:31", pytz.timezone('US/Eastern')).do(sla_breaches.make_chart)
# schedule.every().day.at("11:32", pytz.timezone('US/Eastern')).do(de_stories.make_chart)
# schedule.every().day.at("11:13", pytz.timezone('US/Eastern')).do(re_stories.make_chart)

while True:
    schedule.run_pending()
    time.sleep(60)
