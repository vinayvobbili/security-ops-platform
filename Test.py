from webex_bot.models.command import Command

from helper_methods import log_activity


class Test(Command):
    def __init__(self):
        super().__init__(command_keyword="test")

    @log_activity
    def execute(self, message, attachment_actions, activity):
        return "Test passed!"
