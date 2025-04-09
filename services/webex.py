from webexteamssdk import WebexTeamsAPI

from config import get_config

# Load configuration
config = get_config()

# Initialize Webex API client
webex_api = WebexTeamsAPI(access_token=config.webex_bot_access_token_toodles)

"""Sends a file to a Webex room."""
webex_api.messages.create(
    roomId=config.webex_room_id_threatcon_collab,
    text=f"QR chart for today's FP review!",
    files=[
        # '/Users/user/PycharmProjects/IR/web/static/charts/04-08-2025/QR Rule Efficacy-Week.png',
        '/Users/user/PycharmProjects/IR/web/static/charts/04-08-2025/QR Rule Efficacy-Month.png'
    ]
)
