import csv
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import request
from pytz import timezone

from config import get_config
from services.bot_rooms import get_room_name

eastern = timezone('US/Eastern')
config = get_config()

# Directory for logs (should be set by the main app)
LOG_FILE_DIR = Path(__file__).parent.parent.parent / 'data' / 'transient' / 'logs'


def log_activity(bot_access_token, log_file_name):
    """
    Decorator for logging bot activity to a CSV file.
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
                    with open(LOG_FILE_DIR / log_file_name, "a", newline="") as f:
                        writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
                        writer.writerow([
                            actor,
                            attachment_actions.json_data.get('inputs', {}).get('command_keyword'),
                            get_room_name(attachment_actions.json_data['roomId'], bot_access_token),
                            now_eastern
                        ])
            except Exception as e:
                print(f"Error logging activity for {log_file_name}: {e}")
            return func(*args, **kwargs)

        return wrapper

    return decorator


def log_web_activity(func):
    """
    Decorator for logging web activity to a CSV file.
    Simplified version that doesn't require bot access token.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M:%S %p %Z')
        log_file_name = "web_server_activity_log.csv"
        try:
            with open(LOG_FILE_DIR / log_file_name, "a", newline="") as f:
                writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
                writer.writerow([
                    request.remote_addr,
                    request.method,
                    request.path,
                    now_eastern
                ])
        except Exception as e:
            print(f"Error logging web activity: {e}")
        return func(*args, **kwargs)

    return wrapper
