import os

from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot
from webexteamssdk import WebexTeamsAPI

from Test import Test
from config import get_config
from heatmap import HeatMap
from helper_methods import log_activity
from inflow import Inflow
from lifespan import Lifespan
from outflow import Outflow

config = get_config()
webex_api = WebexTeamsAPI(access_token=config.webex_bot_access_token_moneyball)


class DetectionEngineeringStories(Command):
    def __init__(self):
        super().__init__(command_keyword="det_eng", help_message="DE Stories")

    @log_activity
    def execute(self, message, attachment_actions, activity):
        webex_api.messages.create(
            roomId=attachment_actions.json_data['roomId'],
            text=f"{activity['actor']['displayName']}, here's the latest DE Stories chart!",
            files=[os.path.join(os.path.dirname(__file__), 'charts', 'de_stories.png')]
        )


class ResponseEngineeringStories(Command):
    def __init__(self):
        super().__init__(command_keyword="resp_eng", help_message="RE Stories")

    @log_activity
    def execute(self, message, attachment_actions, activity):
        webex_api.messages.create(
            roomId=attachment_actions.json_data['roomId'],
            text=f"{activity['actor']['displayName']}, here's the latest RE Stories chart!",
            files=[os.path.join(os.path.dirname(__file__), 'charts', 're_stories.png')]
        )


class MttrMttc(Command):
    """Webex Bot command to display a graph of mean times to respond and contain."""

    def __init__(self):
        super().__init__(command_keyword="mttr_mttc", help_message="MTTR-MTTC")

    @log_activity
    def execute(self, message, attachment_actions, activity):
        # Use WebexTeamsAPI to send the file
        webex_api.messages.create(
            roomId=attachment_actions.json_data["roomId"],
            text=f"{activity['actor']['displayName']}, here's the latest MTTR-MTTC chart!",
            files=[os.path.join(os.path.dirname(__file__), 'charts', 'MTTR MTTC.png')]
        )


class AgingTickets(Command):
    """Webex Bot command to display a graph of aging tickets."""

    def __init__(self):
        super().__init__(command_keyword="aging", help_message="Aging Tickets")

    @log_activity
    def execute(self, message, attachment_actions, activity):
        # Use WebexTeamsAPI to send the file
        webex_api.messages.create(
            roomId=attachment_actions.json_data["roomId"],
            text=f"{activity['actor']['displayName']}, here's the latest Aging Tickets chart!",
            files=[os.path.join(os.path.dirname(__file__), 'charts', 'Aging Tickets.png')]
        )


class SlaBreaches(Command):
    """Webex Bot command to display a graph of mean times to respond and contain."""

    def __init__(self):
        super().__init__(command_keyword="sla_breach", help_message="SLA Breaches")

    @log_activity
    def execute(self, message, attachment_actions, activity):
        # Use WebexTeamsAPI to send the file
        webex_api.messages.create(
            roomId=attachment_actions.json_data["roomId"],
            text=f"{activity['actor']['displayName']}, here's the latest SLA Breaches chart!",
            files=[os.path.join(os.path.dirname(__file__), 'charts', 'SLA Breaches.png')]
        )


def main():
    """the main"""

    bot = WebexBot(
        config.webex_bot_access_token_moneyball,
        approved_domains=config.approved_domains.split(','),
        approved_rooms=config.approved_rooms.split(','),
        bot_name="Hello, Metricmeister!"
    )
    bot.add_command(AgingTickets())
    bot.add_command(MttrMttc())
    bot.add_command(SlaBreaches())
    bot.add_command(Inflow())
    bot.add_command(Outflow())
    bot.add_command(Lifespan())
    bot.add_command(HeatMap())
    bot.add_command(DetectionEngineeringStories())
    bot.add_command(ResponseEngineeringStories())
    bot.add_command(Test())
    bot.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
