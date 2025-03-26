import json

from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot
from webexpythonsdk.models.cards import (
    Colors, TextBlock, FontWeight, FontSize,
    Column, AdaptiveCard, ColumnSet, Image,
    HorizontalAlignment, ActionSet, ImageStyle, ActionStyle
)
import webexpythonsdk.models.cards.actions as ACTIONS
import webexpythonsdk.models.cards.card_elements as CARD_ELEMENTS
import webexpythonsdk.models.cards.inputs as INPUTS
import webexpythonsdk.models.cards.types as TYPES
import webexpythonsdk.models.cards.options as OPTIONS
from webexpythonsdk.models.cards.actions import Submit
from webexteamssdk import WebexTeamsAPI

from config import get_config
from src.helper_methods import log_barnacles_activity

config = get_config()
bot_token = config.webex_bot_access_token_barnacles
webex_api = WebexTeamsAPI(access_token=bot_token)

NOTES_FILE = "../data/transient/secOps/management_notes.txt"
THREAT_CON_FILE = "../data/transient/secOps/threatcon.json"
COMPANY_LOGO_BASE64 = "../web/static/icons/company_logo.txt"

with open(COMPANY_LOGO_BASE64, "r") as file:
    company_logo = file.read()


# Command to save notes
class SaveNotes(Command):
    def __init__(self):
        super().__init__(command_keyword="save_notes")

    def execute(self, message, attachment_actions, activity):
        with open(NOTES_FILE, "w") as file:
            file.write(attachment_actions.inputs['management_notes'])

        card = AdaptiveCard(
            body=[
                TextBlock(
                    text="Notes Updated Successfully",
                    weight=FontWeight.BOLDER,
                    color=Colors.ACCENT,
                    size=FontSize.SMALL
                ),
                TextBlock(
                    text=f"**New Note**: {attachment_actions.inputs['management_notes']}",
                    wrap=True
                )
            ]
        )

        webex_api.messages.create(
            toPersonEmail=activity['actor']['id'],
            text='Notes Saved Successfully',
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}]
        )


# Command to view/edit notes
class ManagementNotes(Command):
    def __init__(self):
        super().__init__(command_keyword="notes", help_message="Management Notes")

    @log_barnacles_activity(bot_access_token=bot_token)
    def execute(self, message, attachment_actions, activity):
        with open(NOTES_FILE, "r") as file:
            notes = file.read()

        with open(NOTES_FILE, "r") as file:
            notes = file.read()

        card = AdaptiveCard(
            body=[
                ColumnSet(
                    columns=[
                        Column(
                            items=[
                                Image(
                                    url=company_logo,
                                    height="30px",
                                    style=ImageStyle.PERSON
                                )
                            ],
                            width="auto"
                        ),
                        Column(
                            items=[
                                TextBlock(
                                    text="Management Notes",
                                    wrap=True,
                                    size=FontSize.MEDIUM,
                                    weight=FontWeight.BOLDER,
                                    color=Colors.ACCENT
                                )
                            ],
                            width="stretch"
                        )
                    ]
                ),
                INPUTS.Text(
                    id="management_notes",
                    value=notes,
                    placeholder="Enter notes here",
                    isRequired=True,
                ),
                ActionSet(
                    actions=[
                        Submit(
                            title="Update",
                            style=ActionStyle.POSITIVE,
                            data={"callback_keyword": "save_notes"}
                        )
                    ],
                    spacing=OPTIONS.Spacing.NONE
                )
            ]
        )

        webex_api.messages.create(
            toPersonEmail=activity['actor']['id'],
            text='Management Notes',
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}]
        )


# Command to update threatcon level
class SaveThreatcon(Command):
    def __init__(self):
        super().__init__(command_keyword="save_threatcon")

    def execute(self, message, attachment_actions, activity):
        level = attachment_actions.inputs['threatcon_level']
        reason = attachment_actions.inputs['reason']

        threatcon_details = {
            "level": level,
            "reason": reason
        }

        with open(THREAT_CON_FILE, "w") as file:
            json.dump(threatcon_details, file, indent=4)

        card = AdaptiveCard(
            body=[
                TextBlock(
                    text="ThreatCon Level Updated Successfully",
                    weight=FontWeight.BOLDER,
                    color=Colors.ACCENT,
                    horizontalAlignment=HorizontalAlignment.CENTER
                ),
                TextBlock(
                    text=f"ThreatCon Level: {level.capitalize()}",
                ),
                TextBlock(
                    text=f"Reason: \n {reason}",
                    wrap=True
                )
            ]
        )

        webex_api.messages.create(
            toPersonEmail=activity['actor']['id'],
            text='ThreatCon Level Updated Successfully',
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}]
        )


class ThreatconLevel(Command):
    def __init__(self):
        super().__init__(command_keyword="threatcon", help_message="ThreatCon Level")

    @log_barnacles_activity(bot_access_token=bot_token)
    def execute(self, message, attachment_actions, activity):
        with open(THREAT_CON_FILE, "r") as file:
            threatcon_details = json.load(file)

        level = threatcon_details.get('level', 'green')
        reason = threatcon_details.get('reason', 'No current threats!')

        card = AdaptiveCard(
            body=[
                ColumnSet(
                    columns=[
                        Column(
                            items=[
                                Image(
                                    url=company_logo,
                                    height="30px",
                                    style=ImageStyle.PERSON
                                )
                            ],
                            width="auto"
                        ),
                        Column(
                            items=[
                                TextBlock(
                                    text="ThreatCon",
                                    wrap=True,
                                    size=FontSize.LARGE,
                                    weight=FontWeight.BOLDER,
                                    color=Colors.ACCENT,
                                    horizontalAlignment=HorizontalAlignment.CENTER
                                )
                            ],
                            width="stretch"
                        )
                    ]
                ),
                INPUTS.ChoiceSet(
                    id="threatcon_level",
                    value=level,
                    label="Level",
                    choices=[
                        {"title": "🟢 Green", "value": "green"},
                        {"title": "🟡 Yellow", "value": "yellow"},
                        {"title": "🟠 Orange", "value": "orange"},
                        {"title": "🔴 Red", "value": "red"}
                    ],
                    style=OPTIONS.ChoiceInputStyle.EXPANDED
                ),
                INPUTS.Text(
                    id="reason",
                    label="Reason",
                    isMultiline=True,
                    value=reason,
                    placeholder="Enter reason here",
                    isRequired=True
                ),
                ActionSet(
                    spacing=OPTIONS.Spacing.NONE,
                    actions=[
                        Submit(
                            title="Update",
                            style=ActionStyle.POSITIVE,
                            data={"callback_keyword": "save_threatcon"}
                        )
                    ]
                )
            ]
        )

        webex_api.messages.create(
            toPersonEmail=activity['actor']['id'],
            text='Threatcon Level',
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card.to_dict()}]
        )


def run_bot():
    try:
        bot = WebexBot(
            bot_token,
            approved_rooms=[],
            approved_users=config.barnacles_approved_users.split(','),
            bot_name="Hello, Captain!"
        )
        bot.add_command(ManagementNotes())
        bot.add_command(ThreatconLevel())
        bot.add_command(SaveNotes())
        bot.add_command(SaveThreatcon())
        bot.run()
    except Exception as e:
        print(f"Bot failed to start: {e}")


if __name__ == "__main__":
    run_bot()
