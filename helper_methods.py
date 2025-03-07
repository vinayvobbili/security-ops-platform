import csv
from datetime import datetime

from pytz import timezone

from bot_rooms import get_room_name
from config import get_config

eastern = timezone('US/Eastern')

config = get_config()


def log_activity(func):
    def wrapper(*args, **kwargs):
        attachment_actions = args[2]
        activity = args[3]

        now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M:%S %p %Z')
        try:
            actor = activity["actor"]["displayName"]
            if actor is not config.my_name:
                with open("data/moneyball_activity_log.csv", "a", newline="") as f:
                    writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)  # Use csv.writer for proper quoting
                    writer.writerow([
                        f'"{activity["actor"]["displayName"]}"',  # Quote the name field
                        attachment_actions.json_data.get('inputs', {}).get('command_keyword') or attachment_actions.json_data['text'],
                        get_room_name(attachment_actions.json_data['roomId']),
                        now_eastern
                    ])
        except Exception as e:
            print(f"Error logging activity: {e}")
        return func(*args, **kwargs)

    return wrapper
