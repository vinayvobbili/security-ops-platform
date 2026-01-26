"""Decorators for Toodles bot with pre-configured parameters."""

from src.utils.logging_utils import log_activity
from my_config import get_config

CONFIG = get_config()


def toodles_log_activity(func):
    """
    Decorator for Toodles bot activity logging with pre-configured parameters.

    This wraps the generic log_activity decorator with Toodles-specific settings,
    eliminating the need to repeat configuration in every command class.

    Usage:
        from src.utils.toodles_decorators import toodles_log_activity

        class MyCommand(ToodlesCommand):
            @toodles_log_activity
            def execute(self, message, attachment_actions, activity):
                ...
    """
    return log_activity(
        bot_access_token=CONFIG.webex_bot_access_token_toodles,
        log_file_name="toodles_activity_log.csv"
    )(func)
