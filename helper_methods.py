from datetime import datetime
from pytz import timezone

from bot_rooms import get_room_name

eastern = timezone('US/Eastern')


def log_activity(func):
    def wrapper(*args, **kwargs):
        attachment_actions = args[2]
        activity = args[3]

        now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M:%S %p %Z')
        with open("activity_log.txt", "a") as f:
            f.write(f"{activity['actor']['displayName']},{attachment_actions.json_data['text']},{get_room_name(attachment_actions.json_data['roomId'])},{now_eastern}\n")
        return func(*args, **kwargs)

    return wrapper
