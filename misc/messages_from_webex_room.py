import time

from webexteamssdk import WebexTeamsAPI

from config import get_config


def get_messages_from_room(room_id, bot_access_token, max_messages=10):
    """
    Retrieves messages from a specified Webex room.

    Args:
        room_id (str): The ID of the Webex room.
        bot_access_token (str): The access token for the Webex bot.
        max_messages (int): The maximum number of messages to retrieve (default: 10).

    Returns:
        list: A list of messages (dictionaries), or None if an error occurs.
    """
    try:
        api = WebexTeamsAPI(access_token=bot_access_token)
        messages = api.messages.list(roomId=room_id, max=max_messages)
        message_list = []
        for message in messages:
            message_list.append({
                'message_id': message.id,
                'room_id': message.roomId,
                'person_id': message.personId,
                'person_email': message.personEmail,
                'text': message.text,
                'created': message.created
            })
        return message_list
    except Exception as e:
        print(f"Error retrieving messages from room {room_id}: {e}")
        return None


def main():
    """
    Example usage of get_messages_from_room to retrieve and print messages.
    """
    config = get_config()
    bot_access_token = config.webex_bot_access_token_moneyball

    # Get the room ID from the config
    room_id_to_query = config.webex_room_id_vinay_test_space

    print(f"Attempting to get messages from room: {room_id_to_query}")
    messages = get_messages_from_room(room_id_to_query, bot_access_token, max_messages=20)
    time.sleep(5)

    if messages:
        print(f"Messages from room {room_id_to_query}:")
        for message in messages:
            print(f"  - Message ID: {message['message_id']}")
            print(f"  - Person: {message['person_email']} ({message['person_id']})")
            print(f"  - Text: {message['text']}")
            print(f"  - Created: {message['created']}")
            print("---")
    else:
        print(f"No messages found or error occurred in room {room_id_to_query}.")


if __name__ == "__main__":
    main()
