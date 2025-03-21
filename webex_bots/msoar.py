from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot
from webexteamssdk import WebexTeamsAPI

from config import get_config
from src.helper_methods import log_soar_activity

# Load configuration
CONFIG = get_config()
BOT_ACCESS_TOKEN = CONFIG.webex_bot_access_token_soar

# Initialize Webex API client
webex_api = WebexTeamsAPI(access_token=BOT_ACCESS_TOKEN)


class SaveNotes(Command):
    def __init__(self):
        super().__init__(
            command_keyword="save_notes",
            card=None,
        )

    def execute(self, message, attachment_actions, activity):
        # save the content of the adaptive card back to management_notes.txt
        with open("../data/transient/notes/management_notes.txt", "w") as file:
            file.write(attachment_actions.inputs['notes'])
        # delete the card
        webex_api.messages.delete(attachment_actions.json_data['messageId'])
        return "Notes saved successfully."


class ManagementNotes(Command):
    def __init__(self):
        super().__init__(command_keyword="notes", help_message="Management Notes")

    @log_soar_activity(bot_access_token=BOT_ACCESS_TOKEN)
    def execute(self, message, attachment_actions, activity):
        # Send an adaptive card with the contents of the file management_notes.txt
        with open("../data/transient/notes/management_notes.txt", "r") as file:
            content = file.read()

        webex_api.messages.create(
            toPersonEmail=activity['actor']['id'],
            text='Management Notes',
            attachments=[
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.3",
                        "body": [
                            {
                                "type": "Container",
                                "items": [
                                    {
                                        "type": "TextBlock",
                                        "text": "Current Notes",
                                        "weight": "Bolder",
                                        "size": "Medium"
                                    },
                                    {
                                        "type": "Input.Text",
                                        "id": "notes",
                                        "value": content,
                                        "isMultiline": True,
                                        "placeholder": "Enter notes here",
                                        "style": "text"
                                    }
                                ]
                            },
                            {
                                "type": "ActionSet",
                                "actions": [
                                    {
                                        "type": "Action.Submit",
                                        "title": "Submit",
                                        "style": "positive",
                                        "horizontalAlignment": "Right",
                                        "data": {
                                            "callback_keyword": "save_notes"
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        )


def main():
    """Initialize and run the Webex bot."""

    bot = WebexBot(
        CONFIG.webex_bot_access_token_soar,
        approved_users=CONFIG.soar_bot_approved_users.split(','),
        bot_name="Hello, Manager!"
    )

    # Add commands to the bot
    bot.add_command(ManagementNotes())
    bot.add_command(SaveNotes())

    # Start the bot
    bot.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
