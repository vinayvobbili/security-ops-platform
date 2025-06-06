from webexteamssdk import WebexTeamsAPI

from config import get_config

# Load configuration
config = get_config()

# Initialize Webex API client
webex_api = WebexTeamsAPI(access_token=config.webex_bot_access_token_jarvais)

"""Sends a file to a Webex room."""
webex_api.messages.create(
    roomId=config.webex_room_id_epp_tagging,
    text=f"CS servers with Invalid Ring tags. Please review. Count=364",
    files=[
        '/Users/user/PycharmProjects/IR/data/transient/epp_device_tagging/06-06-2025/cs_servers_with_invalid_ring_tags_only.xlsx'
    ]
)
