import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


def load_config():
    return Config(
        bot_api_token=os.environ["BOT_API_TOKEN"],
        webex_recipient_room_id=os.environ["WEBEX_RECIPIENT_ROOM_ID"],
        xsoar_api_base_url=os.environ["XSOAR_API_URL"],
        xsoar_auth_token=os.environ["XSOAR_AUTH_TOKEN"],
        xsoar_auth_id=os.environ["XSOAR_AUTH_ID"]
    )


@dataclass
class Config:
    """Configuration settings for the application."""
    bot_api_token: str
    webex_recipient_room_id: str
    xsoar_api_base_url: str
    xsoar_auth_token: str
    xsoar_auth_id: str
    webex_api_url: str = "https://webexapis.com/v1/messages"
