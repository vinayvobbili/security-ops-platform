import requests
from config import get_config


def get_webex_bot_rooms(bot_access_token):
    """
    Retrieve the rooms (spaces) where the Webex bot is a member.

    :param bot_access_token: Webex API access token for the bot
    :return: List of rooms the bot is in
    """
    # Webex API endpoint for listing rooms
    url = "https://webexapis.com/v1/rooms"

    # Headers for API authentication
    headers = {
        "Authorization": f"Bearer {bot_access_token}",
        "Content-Type": "application/json"
    }

    try:
        # Make the API request
        response = requests.get(url, headers=headers)

        # Check if the request was successful
        if response.status_code == 200:
            # Parse the JSON response
            rooms_data = response.json()

            # List to store room details
            bot_rooms = []

            # Iterate through rooms
            for room in rooms_data['items']:
                bot_rooms.append({
                    'room_id': room['id'],
                    'room_title': room['title'],
                    'room_type': room['type']
                })

            return bot_rooms
        else:
            print(f"Error: {response.status_code}")
            print(response.text)
            return []

    except requests.RequestException as e:
        print(f"Request error: {e}")
        return []


config = get_config()
BOT_ACCESS_TOKEN = config.webex_bot_access_token


# Usage example
def main():
    # Get rooms the bot is in
    bot_rooms = get_webex_bot_rooms(BOT_ACCESS_TOKEN)

    # Print room details
    if bot_rooms:
        print("Rooms the bot is in:")
        for room in bot_rooms:
            print(f"Room ID: {room['room_id']}")
            print(f"Room Title: {room['room_title']}")
            print(f"Room Type: {room['room_type']}")
            print("---")
    else:
        print("No rooms found or error occurred.")


class InvalidRoomIDException(Exception):
    """Exception raised when the room ID is invalid."""
    pass


def get_room_name(room_id):
    """
    Retrieve the room name for a given room ID.

    :param room_id: The ID of the room
    :return: The name of the room
    :raises InvalidRoomIDException: If the room ID is invalid
    """
    url = f"https://webexapis.com/v1/rooms/{room_id}"
    headers = {
        "Authorization": f"Bearer {BOT_ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            room_data = response.json()
            return room_data['title']
        elif response.status_code == 404:
            raise InvalidRoomIDException(f"Room ID {room_id} is invalid.")
        else:
            print(f"Error: {response.status_code}")
            print(response.text)
            return None
    except requests.RequestException as e:
        print(f"Request error: {e}")
        return None

if __name__ == "__main__":
    main()
