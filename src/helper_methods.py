import csv
import os
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import request
from pytz import timezone

from config import get_config
from services.bot_rooms import get_room_name

eastern = timezone('US/Eastern')

config = get_config()

root_directory = Path(__file__).parent.parent
LOG_FILE_DIR = root_directory / 'data' / 'transient' / 'logs'
CHARTS_DIR_PATH = root_directory / 'web' / 'static' / 'charts'


def _log_activity(bot_access_token, log_file_name):
    """
    Generic decorator for logging activity across different bots.

    Args:
        bot_access_token (str): Access token for bot API
        log_file_name (str): Name of the log file to write to

    Returns:
        Decorator function for logging bot activity
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
                            activity["actor"]["displayName"],
                            attachment_actions.json_data.get('inputs', {}).get('command_keyword'),  # or attachment_actions.json_data['text']
                            get_room_name(attachment_actions.json_data['roomId'], bot_access_token),
                            now_eastern
                        ])
            except Exception as e:
                print(f"Error logging activity for {log_file_name}: {e}")

            return func(*args, **kwargs)

        return wrapper

    return decorator


def log_moneyball_activity(bot_access_token):
    """
    Decorator that logs Moneyball bot activity.

    Args:
        bot_access_token (str): Access token for bot API

    Returns:
        Decorator for logging Moneyball bot activity
    """
    return _log_activity(bot_access_token, 'moneyball_activity_log.csv')


def log_jarvais_activity(bot_access_token):
    """
    Decorator that logs Jarvais bot activity.

    Args:
        bot_access_token (str): Access token for bot API

    Returns:
        Decorator for logging Jarvais bot activity
    """
    return _log_activity(bot_access_token, 'jarvais_activity_log.csv')


def log_barnacles_activity(bot_access_token):
    """
    Decorator that logs Barnacles bot activity.

    Args:
        bot_access_token (str): Access token for bot API

    Returns:
        Decorator for logging Barnacles bot activity
    """
    return _log_activity(bot_access_token, 'barnacles_activity_log.csv')


def log_toodles_activity(bot_access_token):
    """
    Decorator that logs Toodles bot activity.

    Args:
        bot_access_token (str): Access token for bot API

    Returns:
        Decorator for logging Barnacles bot activity
    """
    return _log_activity(bot_access_token, 'toodles_activity_log.csv')


def make_dir_for_todays_charts():
    today_date = datetime.now().strftime('%m-%d-%Y')
    charts_dir = os.path.join(CHARTS_DIR_PATH, today_date)
    os.makedirs(charts_dir, exist_ok=True)


def log_web_activity(func):
    """Logs web activity to a CSV file."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        if request:
            client_ip = request.remote_addr
            if client_ip not in ['192.168.1.100', '127.0.0.1', '192.168.1.101']:  # don't log the activity for my IP address
                now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M:%S %p %Z')
                with open('../data/transient/logs/web_server_activity_log.csv', 'a', newline='\n') as csvfile:
                    csv.writer(csvfile).writerow([request.path, client_ip, now_eastern])
        return func(*args, **kwargs)

    return wrapper
