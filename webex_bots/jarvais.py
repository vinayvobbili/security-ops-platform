import os

import pandas as pd  # Import pandas
from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot
from webexteamssdk import WebexTeamsAPI

from config import get_config
from helper_methods import log_jarvais_activity

# Load configuration
CONFIG = get_config()

# Initialize Webex API client
webex_api = WebexTeamsAPI(access_token=CONFIG.webex_bot_access_token_jarvais)


class CSHostsWithoutRingTag(Command):
    def __init__(self):
        super().__init__(command_keyword="cs_no_ring_tag", help_message="CS Hosts without Ring Tag")

    @log_jarvais_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais)
    def execute(self, message, attachment_actions, activity):
        file_path = os.path.join(os.path.dirname(__file__), "../data/transient/tagging/cs_hosts_without_ring_tag.xlsx")
        room_id = attachment_actions.json_data['roomId']
        try:
            # Use pandas to read the Excel file
            df = pd.read_excel(file_path, engine='openpyxl')
            num_hosts = len(df)  # Get the number of rows (hosts)

            # Send the message with the correct count
            webex_api.messages.create(
                roomId=room_id,
                text=f"{activity['actor']['displayName']}, there are {num_hosts} CS Hosts without a Falcon Grouping Ring tag!",
                files=[file_path]  # Send the Excel file as an attachment
            )
        except FileNotFoundError:
            webex_api.messages.create(
                roomId=room_id,
                text=f"{activity['actor']['displayName']}, the file {file_path} was not found.",
            )
        except Exception as e:
            webex_api.messages.create(
                roomId=room_id,
                text=f"{activity['actor']['displayName']}, an error occurred: {e}",
            )


def main():
    """Initialize and run the Webex bot."""

    bot = WebexBot(
        CONFIG.webex_bot_access_token_jarvais,
        approved_rooms=CONFIG.jarvais_approved_rooms.split(','),
        bot_name="Hello, Tagger!"
    )

    # Add commands to the bot
    bot.add_command(CSHostsWithoutRingTag())

    # Start the bot
    bot.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
