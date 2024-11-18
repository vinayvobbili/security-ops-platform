from aging_tickets import AgingTickets
from webex_bot.webex_bot import WebexBot

from all import All
from config import load_config

config = load_config()


def main():
    """the main"""

    bot = WebexBot(
        config.bot_api_token,
        approved_domains=['company.com'],
        approved_rooms=[
            "Y2lzY29zcGFyazovL3VzL1JPT00vZWU5ZDMyYzAtYTFjYS0xMWVmLWIyZjYtNTcwMThiNzRiOTUx"  # METCIRT Metrics,
            "Y2lzY29zcGFyazovL3VzL1JPT00vMDBmYmIzMjAtZTEyZi0xMWViLTg5M2ItNDdkNjNlNmIwYzUy"  # Vinay's test space
        ],
        bot_name="The Metrics Bot!"
    )
    bot.add_command(AgingTickets())
    bot.add_command(All())
    bot.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
