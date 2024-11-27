from webex_bot.webex_bot import WebexBot

from aging_tickets import AgingTickets
from config import get_config
from inflow import Inflow
from lifespan import Lifespan
from mttr_mttc import MttcMttr
from outflow import Outflow
from sla_breaches import SlaBreaches
from heatmap import HeatMap

config = get_config()


def main():
    """the main"""

    bot = WebexBot(
        config.bot_access_token,
        approved_domains=['company.com'],
        approved_rooms=[
            "Y2lzY29zcGFyazovL3VzL1JPT00vZWU5ZDMyYzAtYTFjYS0xMWVmLWIyZjYtNTcwMThiNzRiOTUx",  # METCIRT Metrics,
            "Y2lzY29zcGFyazovL3VzL1JPT00vMDBmYmIzMjAtZTEyZi0xMWViLTg5M2ItNDdkNjNlNmIwYzUy"  # Vinay's test space
        ],
        bot_name="Hello, Metricmeister!"
    )
    bot.add_command(AgingTickets())
    bot.add_command(MttcMttr())
    bot.add_command(SlaBreaches())
    bot.add_command(Inflow())
    bot.add_command(Outflow())
    bot.add_command(Lifespan())
    bot.add_command(HeatMap())
    bot.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
