import requests
from webexteamssdk import WebexTeamsAPI

from my_config import get_config

# Load configuration
config = get_config()
BOT_ACCESS_TOKEN = config.webex_bot_access_token_tars

# Initialize Webex API client
webex_api = WebexTeamsAPI(access_token=BOT_ACCESS_TOKEN)


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
        response = requests.get(url, headers=headers, verify=False)

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


class InvalidRoomIDException(Exception):
    """Exception raised when the room ID is invalid."""
    pass


def get_room_name(room_id, bot_access_token):
    """
    Retrieve the room name for a given room ID.

    :param room_id: The ID of the room
    :param bot_access_token: The Webex API access token for the bot
    :return: The name of the room
    :raises InvalidRoomIDException: If the room ID is invalid
    """
    url = f"https://webexapis.com/v1/rooms/{room_id}"
    headers = {
        "Authorization": f"Bearer {bot_access_token}",
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


def send_file_to_webex_room(room_id, file_path, message=None):
    """
    Sends a file to a specified Webex room.

    :param room_id: The ID of the Webex room
    :param file_path: The path to the file to be sent
    :param message: Optional message to accompany the file
    """
    try:
        if message is None:
            message = "Here's the file you requested."

        # SAMPLE FILEPATH = 'IR/web/static/charts/07-02-2025/CrowdStrike Detection Efficacy-Month.png'
        webex_api.messages.create(
            roomId=room_id,
            text=message,
            files=[file_path]
        )
        print(f"File sent to room {room_id} successfully.")
    except Exception as e:
        print(f"Failed to send file to room {room_id}: {e}")


# Usage example
def main():
    # pprint(get_webex_bot_rooms(BOT_ACCESS_TOKEN))
    send_file_to_webex_room(
        room_id=config.webex_room_id_epp_tanium_tagging,
        file_path='/Users/user/PycharmProjects/IR/data/transient/epp_device_tagging/11-21-2025/Tanium_Ring_Tags_Report.xlsx',
        message="Here's the list of Tanium hosts without a Ring Tag. Ring tags have also been generated for your review."
    )


if __name__ == "__main__":
    main()
