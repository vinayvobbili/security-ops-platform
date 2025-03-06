from webexteamssdk import WebexTeamsAPI
from config import get_config

config = get_config()
BOT_ACCESS_TOKEN = config.webex_bot_access_token_toodles


def get_webex_bot_rooms(bot_access_token: str) -> list:
    """
    Retrieve the rooms (spaces) where the Webex bot is a member.

    :param bot_access_token: Webex API access token for the bot
    :return: List of rooms the bot is in
    """
    api = WebexTeamsAPI(access_token=bot_access_token)
    try:
        rooms = api.rooms.list()
        bot_rooms = []
        for room in rooms:
            bot_rooms.append({
                'room_id': room.id,
                'room_title': room.title,
                'room_type': room.type
            })
        return bot_rooms
    except Exception as e:
        print(f"Error: {e}")
        return []



# Usage example
def main():
    bot_rooms = get_webex_bot_rooms(BOT_ACCESS_TOKEN)

    if bot_rooms:
        print("Rooms the bot is in:")
        for room in bot_rooms:
            print(f"Room ID: {room['room_id']}")
            print(f"Room Title: {room['room_title']}")
            print(f"Room Type: {room['room_type']}")
            print("---")
    else:
        print("No rooms found or error occurred.")


if __name__ == "__main__":
    main()
