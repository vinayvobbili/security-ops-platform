from aging_tickets import AgingTickets
from webex_bot.webex_bot import WebexBot
from config import load_config

config = load_config()

def main():
    """the main"""

    bot = WebexBot(
        config.bot_api_token,
        approved_domains=['company.com'],
        bot_name="I am The the metrics service!"
    )
    bot.add_command(AgingTickets())
    bot.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()