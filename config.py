import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


def get_config():
    return Config(
        webex_bot_access_token=os.environ["WEBEX_BOT_ACCESS_TOKEN"],
        xsoar_api_base_url=os.environ["XSOAR_API_BASE_URL"],
        xsoar_auth_token=os.environ["XSOAR_AUTH_TOKEN"],
        xsoar_auth_id=os.environ["XSOAR_AUTH_ID"],
        approved_domains=os.environ["APPROVED_DOMAINS"],
        approved_rooms=os.environ["APPROVED_ROOMS"],
        ticket_type_prefix=os.environ["TICKET_TYPE_PREFIX"],
        azdo_org=os.environ["AZDO_ORGANIZATION"],
        azdo_de_project=os.environ["AZDO_DE_PROJECT"],
        azdo_re_project=os.environ["AZDO_RE_PROJECT"],
        azdo_pat=os.environ["AZDO_PERSONAL_ACCESS_TOKEN"]
    )


@dataclass
class Config:
    """Configuration settings for the application."""
    webex_bot_access_token: str
    xsoar_api_base_url: str
    xsoar_auth_token: str
    xsoar_auth_id: str
    ticket_type_prefix: str
    approved_domains: str
    approved_rooms: str
    azdo_org: str
    azdo_de_project: str
    azdo_re_project: str
    azdo_pat: str
    webex_api_url: str = "https://webexapis.com/v1/messages"
