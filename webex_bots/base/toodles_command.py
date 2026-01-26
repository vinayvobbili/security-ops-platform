"""Base command classes for Toodles bot.

This module provides base classes that reduce boilerplate in Toodles commands:
- ToodlesCommand: Base class with common configuration and logging
- CardOnlyCommand: For commands that only display a card with no execute logic
"""

from webex_bot.models.command import Command
from src.utils.toodles_decorators import toodles_log_activity


class ToodlesCommand(Command):
    """
    Base class for Toodles commands with common configuration.

    Subclasses should define class attributes:
    - command_keyword: str (required) - The keyword that triggers this command
    - help_message: str (optional) - Help text shown in bot menu
    - card: dict or AdaptiveCard (optional) - Card to display
    - delete_previous_message: bool (default: True) - Whether to delete the triggering message
    - exact_command_keyword_match: bool (default: True) - Whether to require exact match

    Example:
        class MyCommand(ToodlesCommand):
            command_keyword = "mycommand"
            help_message = "Do something cool"
            card = MY_CARD

            @toodles_log_activity
            def execute(self, message, attachment_actions, activity):
                # Your logic here
                return "Response message"
    """

    command_keyword = None
    help_message = None
    card = None
    delete_previous_message = True
    exact_command_keyword_match = True

    def __init__(self):
        if self.command_keyword is None:
            raise ValueError(f"{self.__class__.__name__} must define command_keyword")

        super().__init__(
            command_keyword=self.command_keyword,
            help_message=self.help_message,
            card=self.card,
            delete_previous_message=self.delete_previous_message,
            exact_command_keyword_match=self.exact_command_keyword_match
        )

    def execute(self, message, attachment_actions, activity):
        """Override this method to implement command logic.

        Subclasses should decorate their execute() with @toodles_log_activity.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement execute() method"
        )


class CardOnlyCommand(ToodlesCommand):
    """
    Base class for commands that only display a card with no execute logic.

    Use this when the command just shows a card (form) and doesn't need
    any processing in the execute method.

    Example:
        class GetMyForm(CardOnlyCommand):
            command_keyword = "get_my_form"
            help_message = "Show the form"
            card = MY_FORM_CARD

        # That's it! No execute() method needed.
    """

    @toodles_log_activity
    def execute(self, message, attachment_actions, activity):
        pass  # Card-only commands don't need execute logic
