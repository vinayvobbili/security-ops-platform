from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot
from webexteamssdk import WebexTeamsAPI

from Test import Test
from aging_tickets import AgingTickets
from config import get_config
from helper_methods import log_activity
from inflow import Inflow
from lifespan import Lifespan
from mttr_mttc import MttrMttc
from outflow import Outflow
from sla_breaches import SlaBreaches
from heatmap import HeatMap
import os

config = get_config()
webex_api = WebexTeamsAPI(access_token=config.webex_bot_access_token)


class DE_Stories(Command):
    def __init__(self):
        super().__init__(command_keyword="de", help_message="DE Stories")

    @log_activity
    def execute(self, message, attachment_actions, activity):
        webex_api.messages.create(
            roomId=attachment_actions.json_data['roomId'],
            text=f"{activity['actor']['displayName']}, here's the latest DE Stories chart!",
            files=[os.path.join(os.path.dirname(__file__), 'charts', 'de_stories.png')]
        )


def main():
    """the main"""

    bot = WebexBot(
        config.webex_bot_access_token,
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
    bot.add_command(DE_Stories())
    bot.add_command(Test())
    bot.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
