import json
from datetime import datetime, timedelta

import webexpythonsdk.models.cards.inputs as INPUTS
import webexpythonsdk.models.cards.options as OPTIONS
from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot
from webexpythonsdk.models.cards import (
    Colors, TextBlock, FontWeight, FontSize,
    Column, AdaptiveCard, ColumnSet, Image,
    HorizontalAlignment, ActionSet, ImageStyle, ActionStyle, Choice, FactSet, Fact
)
from webexpythonsdk.models.cards.actions import Submit
from webexteamssdk import WebexTeamsAPI

from config import get_config
from src.helper_methods import log_barnacles_activity

config = get_config()
bot_token = config.webex_bot_access_token_hal9000
webex_api = WebexTeamsAPI(access_token=bot_token)

NOTES_FILE = "../data/transient/secOps/management_notes.json"
THREAT_CON_FILE = "../data/transient/secOps/threatcon.json"
COMPANY_LOGO_BASE64 = "../web/static/icons/company_logo.txt"

with open(COMPANY_LOGO_BASE64, "r") as file:
    company_logo = file.read()

ICONS_BY_COLOR = {
    'green': '🟢',
    'yellow': '🟡',
    'orange': '🟠',
    'red': '🔴'
}


# Command to save notes
class SaveManagementNotes(Command):
    def __init__(self):
        super().__init__(
            command_keyword="save_notes",
            delete_previous_message=True,
            exact_command_keyword_match=True
        )

    def execute(self, message, attachment_actions, activity):
        with open(NOTES_FILE, "w") as file:
            file.write(json.dumps({
                "note": attachment_actions.inputs['management_notes'],
                "keep_until": attachment_actions.inputs['keep_until']
            }, indent=4))

        card = AdaptiveCard(
            body=[
                TextBlock(
                    text="Notes Updated Successfully",
                    weight=FontWeight.BOLDER,
                    color=Colors.ACCENT,
                    size=FontSize.DEFAULT,
                    horizontalAlignment=HorizontalAlignment.CENTER,
                ),
                FactSet(
                    facts=[
                        Fact(title="Note", value=attachment_actions.inputs['management_notes']),
                        Fact(title="Keep Until", value=attachment_actions.inputs['keep_until'])
                    ]
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
        super().__init__(
            command_keyword="notes",
            help_message="Management Notes",
        )

    @log_barnacles_activity(bot_access_token=bot_token)
    def execute(self, message, attachment_actions, activity):
        with open(NOTES_FILE, "r") as file:
            management_notes = file.read()
            management_notes = json.loads(management_notes)
            note = management_notes['note']
            keep_until = management_notes['keep_until']

        today = datetime.now().strftime("%Y-%m-%d")
        next_week = (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d")
        tomorrow = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")

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
                                    color=Colors.ACCENT,
                                    horizontalAlignment=HorizontalAlignment.CENTER,
                                )
                            ],
                            width="stretch",
                        )
                    ]
                ),
                INPUTS.Text(
                    id="management_notes",
                    isMultiline=True,
                    value=note,
                    placeholder="Enter notes here",
                    isRequired=True,
                ),
                ColumnSet(
                    columns=[
                        Column(
                            items=[
                                TextBlock(
                                    text="Keep Until",
                                    horizontalAlignment=HorizontalAlignment.LEFT,
                                    color=OPTIONS.Colors.DARK,
                                    height=OPTIONS.BlockElementHeight.STRETCH
                                )
                            ],
                            width="auto"
                        ),
                        Column(
                            items=[
                                INPUTS.Date(
                                    id='keep_until',
                                    max=next_week,
                                    min=today,
                                    value=keep_until or tomorrow,
                                    isRequired=True,
                                    height=OPTIONS.BlockElementHeight.AUTO
                                )
                            ],
                            width="175px",
                        )
                    ]
                ),
                ActionSet(
                    actions=[
                        Submit(
                            title="Update",
                            style=ActionStyle.POSITIVE,
                            data={"callback_keyword": "save_notes"},
                        ),
                    ],
                    spacing=OPTIONS.Spacing.NONE,
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
        super().__init__(
            command_keyword="save_threatcon",
            delete_previous_message=True,
            exact_command_keyword_match=True
        )

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
                    text=f"ThreatCon Level: {ICONS_BY_COLOR.get(level, '🟢') + ' ' + level.capitalize()}",
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
        super().__init__(
            command_keyword="threatcon",
            help_message="ThreatCon Level",
        )

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
                        Choice(title="🟢 Green", value="green"),
                        Choice(title="🟡 Yellow", value="yellow"),
                        Choice(title="🟠 Orange", value="orange"),
                        Choice(title="🔴 Red", value="red"),
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
                    ],
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
        bot.add_command(SaveManagementNotes())
        bot.add_command(SaveThreatcon())
        bot.run()
    except Exception as e:
        print(f"Bot failed to start: {e}")


if __name__ == "__main__":
    run_bot()
