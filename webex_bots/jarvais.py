import logging
from datetime import datetime
from pathlib import Path

import fasteners
import pandas as pd
from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot
from webexpythonsdk.models.cards import (
    AdaptiveCard, Column, ColumnSet,
    TextBlock, options, HorizontalAlignment, VerticalContentAlignment
)
from webexpythonsdk.models.cards.actions import Submit
from webexteamssdk import WebexTeamsAPI

from config import get_config
from src.epp import ring_tag_cs_hosts, cs_hosts_without_ring_tag, cs_hosts_with_invalid_ring_tags
from src.helper_methods import log_jarvais_activity

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

CONFIG = get_config()
ROOT_DIRECTORY = Path(__file__).parent.parent
DATA_DIR = ROOT_DIRECTORY / "data" / "transient" / "epp_device_tagging"
webex_api = WebexTeamsAPI(access_token=CONFIG.webex_bot_access_token_jarvais)


def send_report(room_id, filename, message) -> None:
    """Sends the enriched hosts report to a Webex room, including step run times."""
    today_date = datetime.now().strftime('%m-%d-%Y')
    filepath = DATA_DIR / today_date / filename
    hosts_count = len(pd.read_excel(filepath))

    try:
        report_text = (
            f"{message}. Count={hosts_count}!"
        )
        webex_api.messages.create(
            roomId=room_id,
            text=report_text,
            files=[str(filepath)]
        )
    except FileNotFoundError:
        logger.error(f"Report file not found at {filepath}")
    except Exception as e:
        logger.error(f"Failed to send report: {e}")


def seek_approval_to_ring_tag(room_id):
    card = AdaptiveCard(
        body=[
            TextBlock(
                text="Ring Tagging Approval",
                color=options.Colors.ACCENT,
                size=options.FontSize.LARGE,
                weight=options.FontWeight.BOLDER,
                horizontalAlignment=HorizontalAlignment.CENTER),
            ColumnSet(
                columns=[
                    Column(
                        width="stretch",
                        items=[
                            TextBlock(text="Do you want these hosts to be Ring tagged?", wrap=True)
                        ],
                        verticalContentAlignment=VerticalContentAlignment.CENTER
                    )
                ]
            )
        ],
        actions=[
            Submit(title="No!", data={"callback_keyword": "dont_ring_tag_cs_hosts"},
                   style=options.ActionStyle.DESTRUCTIVE),
            Submit(title="Yes! Put a Ring On It!", data={"callback_keyword": "ring_tag_cs_hosts"},
                   style=options.ActionStyle.POSITIVE)
        ]
    )

    try:
        webex_api.messages.create(
            roomId=room_id,
            text="Please approve the tagging action.",
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}]
        )
    except Exception as e:
        logger.error(f"Failed to send approval card: {e}")


def seek_approval_to_delete_invalid_ring_tags(room_id):
    card = AdaptiveCard(
        body=[
            TextBlock(
                text="Invalid Ring Tag Removal Approval",
                color=options.Colors.ACCENT,
                size=options.FontSize.LARGE,
                weight=options.FontWeight.BOLDER,
                horizontalAlignment=HorizontalAlignment.CENTER),
            ColumnSet(
                columns=[
                    Column(
                        width="stretch",
                        items=[
                            TextBlock(text="Do you want these invalid Ring tags to be dropped?", wrap=True)
                        ],
                        verticalContentAlignment=VerticalContentAlignment.CENTER
                    )
                ]
            )
        ],
        actions=[
            Submit(title="No!", data={"callback_keyword": "dont_drop_invalid_ring_tags"},
                   style=options.ActionStyle.DESTRUCTIVE),
            Submit(title="Yes! Drop the invalid Ring tags!", data={"callback_keyword": "drop_invalid_ring_tags"},
                   style=options.ActionStyle.POSITIVE)
        ]
    )

    try:
        webex_api.messages.create(
            roomId=room_id,
            text="Please approve the tagging action.",
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}]
        )
    except Exception as e:
        logger.error(f"Failed to send approval card: {e}")


class CSHostsWithoutRingTag(Command):
    def __init__(self):
        super().__init__(
            command_keyword="cs_no_ring_tag",
            help_message="Get CS Hosts without a Ring Tag",
            delete_previous_message=True,
        )

    @log_jarvais_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais)
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId
        webex_api.messages.create(
            roomId=room_id,
            markdown=f"Hello {activity['actor']['displayName']}! I've started the report generation process for CS Hosts without a Ring Tag. It is running in the background and will complete shortly."
        )
        lock_path = ROOT_DIRECTORY / "src" / "epp" / "cs_hosts_without_ring_tag.lock"
        with fasteners.InterProcessLock(lock_path):
            cs_hosts_without_ring_tag.generate_report()
            filename = "cs_hosts_last_seen_without_ring_tag.xlsx"
            message = 'Unique CS servers without Ring tags'
            send_report(room_id, filename, message)
            seek_approval_to_ring_tag(room_id)


class RingTagCSHosts(Command):
    def __init__(self):
        super().__init__(
            command_keyword="ring_tag_cs_hosts",
            delete_previous_message=True,
        )

    @log_jarvais_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais)
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId
        webex_api.messages.create(
            roomId=room_id,
            markdown=f"Hello {activity['actor']['displayName']}! I've started the ring tagging process for CS Hosts. It is running in the background and will complete in about 15 mins."
        )
        lock_path = ROOT_DIRECTORY / "src" / "epp" / "ring_tag_cs_hosts.lock"
        with fasteners.InterProcessLock(lock_path):
            ring_tag_cs_hosts.run_workflow(room_id)


class DontRingTagCSHosts(Command):
    def __init__(self):
        super().__init__(
            command_keyword="dont_ring_tag_cs_hosts",
            delete_previous_message=True,
        )

    @log_jarvais_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais)
    def execute(self, message, attachment_actions, activity):
        return f"Alright {activity['actor']['displayName']}, I won't tag no more. Until next time!👋🏾"


class CSHostsWithInvalidRingTags(Command):
    def __init__(self):
        super().__init__(
            command_keyword="cs_invalid_ring_tag",
            help_message="Get CS Hosts with Invalid Ring Tags",
            delete_previous_message=True,
        )

    @log_jarvais_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais)
    def execute(self, message, attachment_actions, activity):
        try:
            room_id = attachment_actions.roomId
            webex_api.messages.create(
                roomId=room_id,
                markdown=f"Hello {activity['actor']['displayName']}! I've started the report generation process for CS Hosts with Invalid Ring Tags. It is running in the background and will complete in about 15 mins."
            )
            lock_path = ROOT_DIRECTORY / "src" / "epp" / "cs_hosts_lat_seen_with_invalid_ring_tags.lock"
            with fasteners.InterProcessLock(lock_path):
                cs_hosts_with_invalid_ring_tags.generate_report()
                filename = DATA_DIR / "cs_hosts_with_invalid_ring_tags.xlsx"
                message = 'Unique CS servers with Invalid Ring tags'
                send_report(room_id, filename, message)
                seek_approval_to_delete_invalid_ring_tags(room_id)
        except Exception as e:
            logger.error(f"Error in CSHostsWithInvalidRingTags execute: {e}")
            try:
                webex_api.messages.create(
                    roomId=attachment_actions.roomId,
                    markdown=f"Sorry, an error occurred while generating the report: {str(e)}"
                )
            except Exception as msg_error:
                logger.error(f"Failed to send error message: {msg_error}")


class DontDropInvalidRings(Command):
    def __init__(self):
        super().__init__(
            command_keyword="dont_drop_invalid_ring_tag_cs_hosts",
            delete_previous_message=True,
        )

    @log_jarvais_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais)
    def execute(self, message, attachment_actions, activity):
        return f"Alright {activity['actor']['displayName']}, I won't drop no invalid Rings. Until next time!👋🏾"


class DropInvalidRings(Command):
    def __init__(self):
        super().__init__(
            command_keyword="drop_invalid_ring_tags",
            delete_previous_message=True,
        )

    @log_jarvais_activity(bot_access_token=CONFIG.webex_bot_access_token_jarvais)
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId
        webex_api.messages.create(
            roomId=room_id,
            markdown=f"Hello {activity['actor']['displayName']}! This is still work in progress!."
        )
        lock_path = ROOT_DIRECTORY / "src" / "epp" / "drop_invalid_ring_tag_cs_hosts.lock"
        with fasteners.InterProcessLock(lock_path):
            pass


def main():
    """Initialize and run the Webex bot."""

    bot = WebexBot(
        CONFIG.webex_bot_access_token_jarvais,
        approved_rooms=[CONFIG.webex_room_id_epp_tagging, CONFIG.webex_room_id_vinay_test_space],
        bot_name="Hello, Tagger!"
    )

    # Add commands to the bot
    bot.add_command(CSHostsWithoutRingTag())
    bot.add_command(RingTagCSHosts())
    bot.add_command(DontRingTagCSHosts())
    bot.add_command(CSHostsWithInvalidRingTags())
    bot.add_command(DropInvalidRings())
    bot.add_command(DontDropInvalidRings())

    # Start the bot
    bot.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
