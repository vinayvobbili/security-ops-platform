import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


def get_config():
    return Config(
        bot_access_token=os.environ["BOT_ACCESS_TOKEN"],
        xsoar_api_base_url=os.environ["XSOAR_API_BASE_URL"],
        xsoar_auth_token=os.environ["XSOAR_AUTH_TOKEN"],
        xsoar_auth_id=os.environ["XSOAR_AUTH_ID"],
        approved_domains=os.environ["APPROVED_DOMAINS"],
        approved_rooms=os.environ["APPROVED_ROOMS"],
        ticket_type_prefix=os.environ["TICKET_TYPE_PREFIX"],
    )


@dataclass
class Config:
    """Configuration settings for the application."""
    bot_access_token: str
    xsoar_api_base_url: str
    xsoar_auth_token: str
    xsoar_auth_id: str
    ticket_type_prefix: str
    approved_domains: str
    approved_rooms: str
    webex_api_url: str = "https://webexapis.com/v1/messages"
