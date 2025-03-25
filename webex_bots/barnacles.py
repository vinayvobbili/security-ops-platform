import json

from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot
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

        card = {
            "type": "AdaptiveCard",
            "body": [
                {
                    "type": "TextBlock",
                    "text": "Notes Updated Successfully",
                    "horizontalAlignment": "Center",
                    "weight": "bolder",
                    "color": "Accent",
                    "isSubtle": True,
                    "size": "Small"
                },
                {
                    "type": "TextBlock",
                    "text": f"**New Note**: {attachment_actions.inputs['management_notes']}",
                    "wrap": True
                }
            ],
            "version": "1.3",
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json"
        }

        webex_api.messages.create(
            toPersonEmail=activity['actor']['id'],
            text='Notes Saved Successfully',
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]
        )


# Command to view/edit notes
class ManagementNotes(Command):
    def __init__(self):
        super().__init__(command_keyword="notes", help_message="Management Notes")

    @log_barnacles_activity(bot_access_token=bot_token)
    def execute(self, message, attachment_actions, activity):
        with open(NOTES_FILE, "r") as file:
            notes = file.read()

        card = {
            "type": "AdaptiveCard",
            "body": [
                {
                    "type": "ColumnSet",
                    "columns": [
                        {
                            "type": "Column",
                            "items": [
                                {
                                    "type": "Image",
                                    "url": f"{company_logo}",
                                    "height": "30px",
                                    "style": "Person"
                                }
                            ],
                            "width": "auto"
                        },
                        {
                            "type": "Column",
                            "items": [
                                {
                                    "type": "TextBlock",
                                    "text": "Management Notes",
                                    "wrap": True,
                                    "fontType": "Default",
                                    "size": "Medium",
                                    "weight": "Bolder",
                                    "color": "Accent",
                                    "horizontalAlignment": "Center"
                                }
                            ],
                            "width": "stretch"
                        }
                    ]
                },
                {
                    "type": "Input.Text",
                    "id": "management_notes",
                    "value": notes,
                    "isMultiline": True,
                    "placeholder": "Enter notes here",
                    "isRequired": True,
                    "errorMessage": "Required"
                },
                {
                    "type": "ActionSet",
                    "horizontalAlignment": "Right",
                    "spacing": "None",
                    "actions": [
                        {
                            "type": "Action.Submit",
                            "title": "Update",
                            "style": "positive",
                            "data": {"callback_keyword": "save_notes"},
                            "horizontalAlignment": "Right"
                        }
                    ]
                }
            ],
            "version": "1.3",
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json"
        }

        webex_api.messages.create(
            toPersonEmail=activity['actor']['id'],
            text='Management Notes',
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]
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

        card = {
            "type": "AdaptiveCard",
            "body": [
                {
                    "type": "TextBlock",
                    "text": "ThreatCon Level Updated Successfully",
                    "weight": "Bolder",
                    "color": "Accent",
                    "horizontalAlignment": "Center"
                },
                {
                    "type": "TextBlock",
                    "text": f"ThreatCon Level: {level.capitalize()}",
                },
                {
                    "type": "TextBlock",
                    "text": f"Reason: \n {reason}",
                    "wrap": True
                }
            ],
            "version": "1.3",
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json"
        }

        webex_api.messages.create(
            toPersonEmail=activity['actor']['id'],
            text='ThreatCon Level Updated Successfully',
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]
        )


class ThreatconLevel(Command):
    def __init__(self):
        super().__init__(command_keyword="threatcon", help_message="ThreatCon Level")

    @log_barnacles_activity(bot_access_token=bot_token)
    def execute(self, message, attachment_actions, activity):
        with open(THREAT_CON_FILE, "r") as file:
            threatcon_details = file.read()

        threatcon_details = json.loads(threatcon_details)
        level = threatcon_details.get('level', 'green')
        reason = threatcon_details.get('reason', 'No current threats!')

        card = {
            "type": "AdaptiveCard",
            "body": [
                {
                    "type": "ColumnSet",
                    "columns": [
                        {
                            "type": "Column",
                            "items": [
                                {
                                    "type": "Image",
                                    "url": f"{company_logo}",
                                    "height": "30px",
                                    "style": "Person"
                                }
                            ],
                            "width": "auto"
                        },
                        {
                            "type": "Column",
                            "items": [
                                {
                                    "type": "TextBlock",
                                    "text": "ThreatCon",
                                    "wrap": True,
                                    "fontType": "Default",
                                    "size": "Large",
                                    "weight": "Bolder",
                                    "color": "Accent",
                                    "horizontalAlignment": "Center"
                                }
                            ],
                            "width": "stretch"
                        }
                    ]
                },
                {
                    "type": "Input.ChoiceSet",
                    "id": "threatcon_level",
                    "value": level,
                    "label": "Level",
                    "choices": [
                        {"title": "🟢 Green", "value": "green"},
                        {"title": "🟡 Yellow", "value": "yellow"},
                        {"title": "🟠 Orange", "value": "orange"},
                        {"title": "🔴 Red", "value": "red"}
                    ],
                    "style": "expanded"
                },
                {
                    "type": "Input.Text",
                    "id": "reason",
                    "label": "Reason",
                    "isMultiline": True,
                    "value": reason,
                    "placeholder": "Enter reason here",
                    "isRequired": True,
                    "errorMessage": "Required"
                },
                {
                    "type": "ActionSet",
                    "horizontalAlignment": "Right",
                    "spacing": "None",
                    "actions": [
                        {
                            "type": "Action.Submit",
                            "title": "Update",
                            "style": "positive",

                            "data": {"callback_keyword": "save_threatcon"}
                        }
                    ]
                }
            ],
            "version": "1.3",
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json"
        }

        webex_api.messages.create(
            toPersonEmail=activity['actor']['id'],
            text='Threatcon Level',
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]
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
