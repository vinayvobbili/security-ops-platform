from webexteamssdk import WebexTeamsAPI

from config import get_config

# Load configuration
config = get_config()

# Initialize Webex API client
webex_api = WebexTeamsAPI(access_token=config.webex_bot_access_token_toodles)

"""Sends a file to a Webex room."""
webex_api.messages.create(
    roomId=config.webex_room_id_threatcon_collab,
    text=f"It's good to see the volume decreasing after two months of heavy inflow❣️👌🏾",
    files=[
        '/Users/user/PycharmProjects/IR/web/static/charts/04-29-2025/Inflow Past 12 Months - Impact Only.png'
    ]
)
