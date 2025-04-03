from webexteamssdk import WebexTeamsAPI

from config import get_config

# Load configuration
config = get_config()

# Initialize Webex API client
webex_api = WebexTeamsAPI(access_token=config.webex_bot_access_token_moneyball)

"""Sends a chart image to a Webex room."""
webex_api.messages.create(
    roomId=config.webex_room_id_metrics,
    text=f"CrowdStrike Efficacy chart!",
    files=['/Users/user/PycharmProjects/IR/web/static/charts/CrowdStrike Efficacy.png']
)
