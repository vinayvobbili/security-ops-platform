from webex_bot.models.command import Command


class All(Command):
    def __init__(self):
        super().__init__(command_keyword="all", help_message="All")

    def execute(self, message, attachment_actions, activity):
        pass
