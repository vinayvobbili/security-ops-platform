from webex_bot.webex_bot import WebexBot

from aging_tickets import AgingTickets
from config import get_config
from inflow import Inflow
from lifespan import Lifespan
from mttr_mttc import MttrMttc
from outflow import Outflow
from sla_breaches import SlaBreaches
from heatmap import HeatMap

config = get_config()


def main():
    """the main"""

    bot = WebexBot(
        config.bot_access_token,
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
    bot.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
