from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot
from webexteamssdk import WebexTeamsAPI

from config import get_config
from src.helper_methods import log_soar_activity

config = get_config()
bot_token = config.webex_bot_access_token_soar
webex_api = WebexTeamsAPI(access_token=bot_token)


# Command to save notes
class SaveNotes(Command):
    def __init__(self):
        super().__init__(command_keyword="save_notes")

    def execute(self, message, attachment_actions, activity):
        with open("../data/transient/notes/management_notes.txt", "w") as file:
            file.write(attachment_actions.inputs['management_notes'])

        card = {
            "type": "AdaptiveCard",
            "body": [
                {
                    "type": "TextBlock",
                    "text": "Notes Saved Successfully",
                    "weight": "Bolder"
                },
                {
                    "type": "TextBlock",
                    "text": "Your management notes have been updated."
                },
                {
                    "type": "TextBlock",
                    "text": "Type '@bot notes' to view or edit notes again."
                }
            ],
            "version": "1.0"
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

    @log_soar_activity(bot_access_token=bot_token)
    def execute(self, message, attachment_actions, activity):
        with open("../data/transient/notes/management_notes.txt", "r") as file:
            content = file.read()

        card = {
            "type": "AdaptiveCard",
            "body": [
                {
                    "type": "TextBlock",
                    "text": "Management Notes",
                    "weight": "Bolder"
                },
                {
                    "type": "Input.Text",
                    "id": "management_notes",
                    "value": content,
                    "isMultiline": True,
                    "placeholder": "Enter notes here"
                }
            ],
            "actions": [
                {
                    "type": "Action.Submit",
                    "title": "Save",
                    "style": "positive",
                    "data": {"callback_keyword": "save_notes"},
                    "horizontalAlignment": "Right"
                }
            ],
            "version": "1.0"
        }

        webex_api.messages.create(
            toPersonEmail=activity['actor']['id'],
            text='Management Notes',
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]
        )


def run_bot():
    try:
        bot = WebexBot(
            bot_token,
            approved_users=config.soar_bot_approved_users.split(','),
            bot_name="Hello, Manager!"
        )
        bot.add_command(ManagementNotes())
        bot.add_command(SaveNotes())
        bot.run()
    except Exception as e:
        print(f"Bot failed to start: {e}")


if __name__ == "__main__":
    run_bot()
