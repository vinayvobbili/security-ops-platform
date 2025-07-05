from webexteamssdk import WebexTeamsAPI

from config import get_config

# Load configuration
config = get_config()

# Initialize Webex API client
webex_api = WebexTeamsAPI(access_token=config.webex_bot_access_token_soar)

"""Sends a file to a Webex room."""
webex_api.messages.create(
    roomId=config.webex_room_id_threatcon_collab,
    text=f"The one at the bottom is a lot of noise 🤯",
    files=[
        '/Users/user/PycharmProjects/IR/web/static/charts/07-02-2025/CrowdStrike Detection Efficacy-Month.png'
    ]
)
