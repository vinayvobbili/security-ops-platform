from adaptivecardbuilder import AdaptiveCard, Container, TextBlock, ActionSet, ActionSubmit
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
        # Save the content of the adaptive card to management_notes.txt
        with open("../data/transient/notes/management_notes.txt", "w") as file:
            file.write(attachment_actions.inputs['notes'])

        # Instead of deleting, update the card with a confirmation message
        card = AdaptiveCard()
        card.add(
            Container(
                items=[
                    TextBlock(text="Notes Saved Successfully", weight="BOLDER"),
                    TextBlock(text="Your management notes have been updated."),
                    TextBlock(text="Type '@bot notes' to view or edit notes again.")
                ]
            )
        )

        # Update the existing card instead of deleting it
        webex_api.attachment_actions.update(
            attachment_action_id=attachment_actions.id,
            new_card=card.to_dict()
        )

        return None  # No separate response needed


class ManagementNotes(Command):
    def __init__(self):
        super().__init__(command_keyword="notes", help_message="Management Notes")

    @log_soar_activity(bot_access_token=BOT_ACCESS_TOKEN)
    def execute(self, message, attachment_actions, activity):
        try:
            # Attempt to read the contents of the management_notes.txt file
            with open("../data/transient/notes/management_notes.txt", "r") as file:
                content = file.read()
        except (FileNotFoundError, IOError):
            # Handle case where file doesn't exist or can't be accessed
            content = ""
            # Create the directory and file if they don't exist
            import os
            os.makedirs("../data/transient/notes", exist_ok=True)
            with open("../data/transient/notes/management_notes.txt", "w") as file:
                file.write("")

        card = AdaptiveCard()
        card.add(
            Container(
                items=[
                    TextBlock(text="Management Notes", weight="BOLDER"),
                    InputText(id="notes", value=content, isMultiline=True, placeholder="Enter notes here")
                ]
            )
        )

        # Add action set with right-aligned submit button
        card.add(
            ActionSet(
                actions=[
                    ActionSubmit(title="Save Notes", style=ActionStyle.POSITIVE, data={"callback_keyword": "save_notes"})
                ],
                horizontalAlignment="right"  # Right-align the button
            )
        )

        webex_api.messages.create(
            toPersonEmail=activity['actor']['id'],
            text='Management Notes',
            attachments=[
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": card.to_dict()
                }
            ]
        )


def main():
    """Initialize and run the Webex bot."""

    # Add error handling for configuration
    try:
        bot = WebexBot(
            CONFIG.webex_bot_access_token_soar,
            approved_users=CONFIG.soar_bot_approved_users.split(','),
            bot_name="Management Notes Bot"
        )

        # Add commands to the bot
        bot.add_command(ManagementNotes())
        bot.add_command(SaveNotes())

        # Start the bot
        bot.run()
    except Exception as e:
        print(f"Error starting bot: {str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
