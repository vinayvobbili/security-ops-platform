import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


def get_config():
    return Config(
        webex_bot_access_token_moneyball=os.environ["WEBEX_BOT_ACCESS_TOKEN_MONEYBALL"],
        webex_bot_access_token_soar=os.environ["WEBEX_BOT_ACCESS_TOKEN_SOAR"],
        webex_bot_access_token_toodles=os.environ["WEBEX_BOT_ACCESS_TOKEN_TOODLES"],
        webex_room_id_aging_tickets=os.environ["WEBEX_ROOM_ID_AGING_TICKETS"],
        webex_room_id_vinay_test_space=os.environ["WEBEX_ROOM_ID_VINAY_TEST_SPACE"],
        webex_room_id_soc_shift_updates=os.environ["WEBEX_ROOM_ID_SOC_SHIFT_UPDATES"],
        xsoar_api_base_url=os.environ["XSOAR_API_BASE_URL"],
        xsoar_ui_base_url=os.environ["XSOAR_UI_BASE_URL"],
        xsoar_auth_token=os.environ["XSOAR_AUTH_TOKEN"],
        xsoar_auth_id=os.environ["XSOAR_AUTH_ID"],
        approved_domains=os.environ["APPROVED_DOMAINS"],
        approved_rooms=os.environ["APPROVED_ROOMS"],
        ticket_type_prefix=os.environ["TICKET_TYPE_PREFIX"],
        azdo_org=os.environ["AZDO_ORGANIZATION"],
        azdo_de_project=os.environ["AZDO_DE_PROJECT"],
        azdo_re_project=os.environ["AZDO_RE_PROJECT"],
        azdo_pat=os.environ["AZDO_PERSONAL_ACCESS_TOKEN"],
        cs_ro_client_id=os.environ["CROWD_STRIKE_RO_CLIENT_ID"],
        cs_ro_client_secret=os.environ["CROWD_STRIKE_RO_CLIENT_SECRET"],
        cs_rtr_client_id=os.environ["CROWD_STRIKE_RTR_CLIENT_ID"],
        cs_rtr_client_secret=os.environ["CROWD_STRIKE_RTR_CLIENT_SECRET"],
        webex_host_announcements_room_id=os.environ["WEBEX_HOST_ANNOUNCEMENTS_ROOM_ID"],
        triage_timer=os.environ["TRIAGE_TIMER"],
        lessons_learned_time=os.environ["LESSONS_LEARNED_TIME"],
        investigation_time=os.environ["INVESTIGATION_TIME"],
        eradication_time=os.environ["ERADICATION_TIME"],
        closure_time=os.environ["CLOSURE_TIME"],
        secops_shift_staffing_filename=os.environ["SECOPS_STAFFING_FILENAME"],
        snow_creds=os.environ["SNOW_CREDS"],
    )


@dataclass
class Config:
    """Configuration settings for the application."""
    webex_bot_access_token_moneyball: str
    webex_bot_access_token_soar: str
    webex_bot_access_token_toodles: str
    webex_room_id_aging_tickets: str
    webex_room_id_vinay_test_space: str
    webex_room_id_soc_shift_updates: str
    xsoar_api_base_url: str
    xsoar_ui_base_url: str
    xsoar_auth_token: str
    xsoar_auth_id: str
    ticket_type_prefix: str
    approved_domains: str
    approved_rooms: str
    azdo_org: str
    azdo_de_project: str
    azdo_re_project: str
    azdo_pat: str
    cs_ro_client_id: str
    cs_ro_client_secret: str
    cs_rtr_client_id: str
    cs_rtr_client_secret: str
    webex_host_announcements_room_id: str
    triage_timer: str
    lessons_learned_time: str
    investigation_time: str
    eradication_time: str
    closure_time: str
    secops_shift_staffing_filename: str
    snow_creds: str

    webex_api_url: str = "https://webexapis.com/v1/messages"
