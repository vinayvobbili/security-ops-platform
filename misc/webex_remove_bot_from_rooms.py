import requests

from my_config import get_config

config = get_config()


def remove_bot_from_all_rooms(bot_access_token):
    """
    Remove bot from all Webex rooms it's currently in.

    :param bot_access_token: Webex API access token for the bot
    :return: List of rooms the bot was removed from
    """
    # Get rooms the bot is in
    rooms_url = "https://webexapis.com/v1/rooms"
    headers = {
        "Authorization": f"Bearer {bot_access_token}",
        "Content-Type": "application/json"
    }

    try:
        # Fetch rooms
        rooms_response = requests.get(rooms_url, headers=headers)
        if rooms_response.status_code != 200:
            print(f"Error fetching rooms: {rooms_response.text}")
            return []

        rooms = rooms_response.json()['items']

        # List to track removed rooms
        removed_rooms = []

        # Remove bot from each room
        for room in rooms:
            membership_url = f"https://webexapis.com/v1/memberships?roomId={room['id']}"
            memberships_response = requests.get(membership_url, headers=headers)

            if memberships_response.status_code == 200:
                memberships = memberships_response.json()['items']

                # Find bot's membership in this room
                for membership in memberships:
                    if membership.get('personEmail') == membership.get('personEmail'):
                        # Delete bot's membership
                        delete_url = f"https://webexapis.com/v1/memberships/{membership['id']}"
                        delete_response = requests.delete(delete_url, headers=headers)

                        if delete_response.status_code == 204:
                            removed_rooms.append(room['title'])
                            print(f"Removed from room: {room['title']}")
                        else:
                            print(f"Failed to remove from room {room['title']}")

        return removed_rooms

    except requests.RequestException as e:
        print(f"Request error: {e}")
        return []


# Usage
BOT_ACCESS_TOKEN = config.bot_access_token
removed = remove_bot_from_all_rooms(BOT_ACCESS_TOKEN)
print(f"Bot removed from {len(removed)} rooms")
