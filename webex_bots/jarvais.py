from pathlib import Path

import fasteners
from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot
from webexteamssdk import WebexTeamsAPI

from config import get_config
from src.epp import cs_hosts_without_ring_tag, ring_tag_cs_hosts
from src.helper_methods import log_jarvais_activity

CONFIG = get_config()
ROOT_DIRECTORY = Path(__file__).parent.parent
webex_api = WebexTeamsAPI(access_token=CONFIG.webex_bot_access_token_jarvais)


class CSHostsWithoutRingTag(Command):
    def __init__(self):
        super().__init__(command_keyword="cs_no_ring_tag", help_message="Get CS Hosts without Ring Tag")

    @log_jarvais_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais)
    def execute(self, message, attachment_actions, activity):
        webex_api.messages.create(
            roomId=CONFIG.webex_room_id_epp_tagging,
            markdown=f"Hello {activity['actor']['displayName']}! I've started the report generation process. It is running in the background and will complete in about 5 mins."
        )
        lock_path = ROOT_DIRECTORY / "src" / "epp" / "cs_hosts_without_ring_tag.lock"
        with fasteners.InterProcessLock(lock_path):
            cs_hosts_without_ring_tag.run_workflow()


class RingTagCSHosts(Command):
    def __init__(self):
        super().__init__(command_keyword="ring_tag_cs_hosts")

    @log_jarvais_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais)
    def execute(self, message, attachment_actions, activity):
        ring_tag_cs_hosts.run_workflow()


def main():
    """Initialize and run the Webex bot."""

    bot = WebexBot(
        CONFIG.webex_bot_access_token_jarvais,
        approved_rooms=CONFIG.jarvais_approved_rooms.split(','),
        bot_name="Hello, Tagger!"
    )

    # Add commands to the bot
    bot.add_command(CSHostsWithoutRingTag())
    bot.add_command(RingTagCSHosts())

    # Start the bot
    bot.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
