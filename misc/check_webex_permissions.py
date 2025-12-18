#!/usr/bin/env python3

from webexteamssdk import WebexTeamsAPI
from my_config import get_config


def check_bot_permissions():
    """Check bot token scopes and permissions"""
    config = get_config()
    bot_access_token = config.webex_bot_access_token_moneyball
    room_id = config.webex_room_id_test_space

    api = WebexTeamsAPI(access_token=bot_access_token)

    print("=== Webex Bot Permission Check ===\n")

    # 1. Check bot identity
    try:
        bot_info = api.people.me()
        print(f"✓ Bot Identity: {bot_info.displayName} ({bot_info.emails[0]})")
        print(f"  Bot ID: {bot_info.id}")
    except Exception as e:
        print(f"✗ Failed to get bot identity: {e}")
        return

    # 2. Check room membership
    try:
        memberships = api.memberships.list(roomId=room_id)
        bot_in_room = False
        for membership in memberships:
            if membership.personId == bot_info.id:
                bot_in_room = True
                print(f"✓ Bot is member of room: {room_id}")
                print(f"  Membership ID: {membership.id}")
                print(f"  Is Moderator: {membership.isModerator}")
                break

        if not bot_in_room:
            print(f"✗ Bot is NOT a member of room: {room_id}")
            return

    except Exception as e:
        print(f"✗ Failed to check room membership: {e}")
        print("  This could indicate insufficient permissions to read memberships")

    # 3. Check room details
    try:
        room = api.rooms.get(room_id)
        print(f"✓ Can read room details: {room.title}")
        print(f"  Room Type: {room.type}")
        print(f"  Room Created: {room.created}")
    except Exception as e:
        print(f"✗ Failed to get room details: {e}")

    # 4. Test message listing (the failing operation)
    try:
        messages = api.messages.list(roomId=room_id, max=1)
        message_count = len(list(messages))
        print(f"✓ Can read messages: Found {message_count} message(s)")
    except Exception as e:
        print(f"✗ Failed to read messages: {e}")
        print("  This is the root cause of your 403 error")

    # 5. Test sending a message (we know this works)
    try:
        test_message = api.messages.create(roomId=room_id, text="🤖 Permission test - please ignore")
        print(f"✓ Can send messages: {test_message.id}")

        # Clean up the test message
        api.messages.delete(test_message.id)
        print("✓ Can delete messages (cleanup successful)")

    except Exception as e:
        print(f"✗ Failed to send/delete test message: {e}")

    # 6. Check what scopes the token might have
    print(f"\n=== Token Analysis ===")
    print("Based on the test results:")
    if bot_in_room:
        print("• Bot has basic room access (can see room, memberships)")
    print("• Bot can send messages (write permission)")
    print("• Bot CANNOT read message history (missing read permission)")
    print("\nThis suggests the bot token was created with limited scopes.")
    print("The token likely has 'spark:messages_write' but NOT 'spark:messages_read' scope.")


if __name__ == "__main__":
    check_bot_permissions()