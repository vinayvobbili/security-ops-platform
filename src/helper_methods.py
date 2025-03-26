import csv
from datetime import datetime
from functools import wraps
from pathlib import Path

from pytz import timezone

from config import get_config
from services.bot_rooms import get_room_name

eastern = timezone('US/Eastern')

config = get_config()

root_directory = Path(__file__).parent.parent
LOG_FILE_DIR = root_directory / 'data' / 'transient' / 'logs'


def log_moneyball_activity(bot_access_token):
    """
    Decorator that logs activity, using the provided bot access token.
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attachment_actions = args[2]
            activity = args[3]

            now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M:%S %p %Z')
            try:
                actor = activity["actor"]["displayName"]
                if actor != config.my_name:
                    with open(f"{LOG_FILE_DIR}/moneyball_activity_log.csv", "a", newline="") as f:
                        writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)  # Use csv.writer for proper quoting
                        writer.writerow([
                            f'"{activity["actor"]["displayName"]}"',  # Quote the name field
                            attachment_actions.json_data.get('inputs', {}).get('command_keyword') or attachment_actions.json_data['text'],
                            get_room_name(attachment_actions.json_data['roomId'], bot_access_token),
                            now_eastern
                        ])
            except Exception as e:
                print(f"Error logging activity: {e}")
            return func(*args, **kwargs)

        return wrapper

    return decorator


def log_jarvais_activity(bot_access_token):
    """
    Decorator that logs activity, using the provided bot access token.
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attachment_actions = args[2]
            activity = args[3]

            now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M:%S %p %Z')
            try:
                actor = activity["actor"]["displayName"]
                if actor != config.my_name:
                    with open(f"{LOG_FILE_DIR}/jarvais_activity_log.csv", "a", newline="") as f:
                        writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
                        writer.writerow([
                            f'"{activity["actor"]["displayName"]}"',
                            attachment_actions.json_data.get('inputs', {}).get('command_keyword') or attachment_actions.json_data['text'],
                            get_room_name(attachment_actions.json_data['roomId'], bot_access_token),
                            now_eastern
                        ])
            except Exception as e:
                print(f"Error logging activity: {e}")
            return func(*args, **kwargs)

        return wrapper

    return decorator


def log_barnacles_activity(bot_access_token):
    """
    Decorator that logs activity, using the provided bot access token.
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attachment_actions = args[2]
            activity = args[3]

            now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M:%S %p %Z')
            try:
                actor = activity["actor"]["displayName"]
                if actor != config.my_name:
                    with open(f"{LOG_FILE_DIR}/barnacles_activity_log.csv", "a", newline="") as f:
                        writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)  # Use csv.writer for proper quoting
                        writer.writerow([
                            f'"{activity["actor"]["displayName"]}"',  # Quote the name field
                            attachment_actions.json_data.get('inputs', {}).get('command_keyword') or attachment_actions.json_data['text'],
                            get_room_name(attachment_actions.json_data['roomId'], bot_access_token),
                            now_eastern
                        ])
            except Exception as e:
                print(f"Error logging activity: {e}")
            return func(*args, **kwargs)

        return wrapper

    return decorator
