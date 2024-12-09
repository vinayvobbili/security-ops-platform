from datetime import datetime
from pytz import timezone

from bot_rooms import get_room_name

eastern = timezone('US/Eastern')


def log_activity(func):
    def wrapper(*args, **kwargs):
        attachment_actions = args[2]
        activity = args[3]

        now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M:%S %p %Z')
        try:
            with open("activity_log.csv", "a") as f:
                f.write(f"{activity['actor']['displayName']},{attachment_actions.json_data.get('inputs', {}).get('command_keyword') or attachment_actions.json_data['text']},{get_room_name(attachment_actions.json_data['roomId'])},{now_eastern}\n")
        except Exception as e:
            print(f"Error logging activity: {e}")
        return func(*args, **kwargs)

    return wrapper
