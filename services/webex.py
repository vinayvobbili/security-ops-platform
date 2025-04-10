from webexteamssdk import WebexTeamsAPI

from config import get_config

# Load configuration
config = get_config()

# Initialize Webex API client
webex_api = WebexTeamsAPI(access_token=config.webex_bot_access_token_jarvais)

"""Sends a file to a Webex room."""
webex_api.messages.create(
    roomId=config.webex_room_id_epp_tagging,
    text=f"A complete list of UNIQUE CS hosts without a Ring tag, along with their SNOW details, is attached!",
    files=[
        '/Users/user/PycharmProjects/IR/data/transient/epp_device_tagging/enriched_unique_hosts.xlsx'
    ]
)
