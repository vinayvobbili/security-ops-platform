from webex_bot.models.command import Command

import days_since_incident
import mttr_mttc
import re_stories
from helper_methods import log_activity


class Test(Command):
    def __init__(self):
        super().__init__(command_keyword="test")

    @log_activity
    def execute(self, message, attachment_actions, activity):
        return "Test passed!"


# mttr_mttc.make_chart()
# re_stories.make_chart()
days_since_incident.make_chart()
