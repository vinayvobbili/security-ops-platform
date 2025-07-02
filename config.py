import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


def get_config():
    return Config(
        webex_bot_access_token_moneyball=os.environ["WEBEX_BOT_ACCESS_TOKEN_MONEYBALL"],
        webex_bot_access_token_soar=os.environ["WEBEX_BOT_ACCESS_TOKEN_SOAR"],
        webex_bot_access_token_toodles=os.environ["WEBEX_BOT_ACCESS_TOKEN_TOODLES"],
        webex_bot_access_token_jarvais=os.environ["WEBEX_BOT_ACCESS_TOKEN_JARVAIS"],
        webex_bot_access_token_barnacles=os.environ["WEBEX_BOT_ACCESS_TOKEN_BARNACLES"],
        webex_bot_access_token_hal9000=os.environ["WEBEX_BOT_ACCESS_TOKEN_HAL9000"],
        webex_room_id_aging_tickets=os.environ["WEBEX_ROOM_ID_AGING_TICKETS"],
        webex_room_id_vinay_test_space=os.environ["WEBEX_ROOM_ID_VINAY_TEST_SPACE"],
        webex_room_id_soc_shift_updates=os.environ["WEBEX_ROOM_ID_SOC_SHIFT_UPDATES"],
        webex_room_id_epp_tagging=os.environ["WEBEX_ROOM_ID_EPP_TAGGING"],
        webex_room_id_metrics=os.environ["WEBEX_ROOM_ID_METRICS"],
        webex_room_id_threatcon_collab=os.environ["WEBEX_ROOM_ID_THREATCON_COLLAB"],
        webex_room_id_gosc_t2=os.environ["WEBEX_ROOM_ID_GOSC_T2"],
        webex_room_id_automation_engineering=os.environ["WEBEX_ROOM_ID_AUTOMATION_ENGINEERING"],
        webex_room_id_response_engineering=os.environ["WEBEX_ROOM_ID_RESPONSE_ENGINEERING"],
        webex_room_id_phish_fort=os.environ["WEBEX_ROOM_ID_PHISH_FORT"],
        webex_room_id_host_announcements=os.environ["WEBEX_ROOM_ID_HOST_ANNOUNCEMENTS"],
        webex_room_id_response_sla_risk=os.environ["WEBEX_ROOM_ID_RESPONSE_SLA_RISK"],
        webex_room_id_containment_sla_risk=os.environ["WEBEX_ROOM_ID_CONTAINMENT_SLA_RISK"],
        xsoar_prod_api_base_url=os.environ["XSOAR_PROD_API_BASE_URL"],
        xsoar_prod_ui_base_url=os.environ["XSOAR_PROD_UI_BASE_URL"],
        xsoar_dev_api_base_url=os.environ["XSOAR_DEV_API_BASE_URL"],
        xsoar_dev_ui_base_url=os.environ["XSOAR_DEV_UI_BASE_URL"],
        xsoar_prod_auth_key=os.environ["XSOAR_PROD_AUTH_KEY"],
        xsoar_prod_auth_id=os.environ["XSOAR_PROD_AUTH_ID"],
        xsoar_dev_auth_key=os.environ["XSOAR_DEV_AUTH_KEY"],
        xsoar_dev_auth_id=os.environ["XSOAR_DEV_AUTH_ID"],
        xsoar_lists_filename=os.environ["XSOAR_LISTS_FILENAME"],
        barnacles_approved_users=os.environ["BARNACLES_APPROVED_USERS"],
        team_name=os.environ["TEAM_NAME"],
        azdo_org=os.environ["AZDO_ORGANIZATION"],
        azdo_de_project=os.environ["AZDO_DE_PROJECT"],
        azdo_re_project=os.environ["AZDO_RE_PROJECT"],
        azdo_platforms_parent_url=os.environ["AZDO_PLATFORMS_PARENT_URL"],
        azdo_rea_parent_url=os.environ["AZDO_REA_PARENT_URL"],
        azdo_pat=os.environ["AZDO_PERSONAL_ACCESS_TOKEN"],
        cs_ro_client_id=os.environ["CROWD_STRIKE_RO_CLIENT_ID"],
        cs_ro_client_secret=os.environ["CROWD_STRIKE_RO_CLIENT_SECRET"],
        cs_host_write_client_id=os.environ["CROWD_STRIKE_HOST_WRITE_CLIENT_ID"],
        cs_host_write_client_secret=os.environ["CROWD_STRIKE_HOST_WRITE_CLIENT_SECRET"],
        cs_rtr_client_id=os.environ["CROWD_STRIKE_RTR_CLIENT_ID"],
        cs_rtr_client_secret=os.environ["CROWD_STRIKE_RTR_CLIENT_SECRET"],
        cisco_amp_client_id=os.environ["CISCO_AMP_CLIENT_ID"],
        cisco_amp_client_secret=os.environ["CISCO_AMP_CLIENT_SECRET"],
        triage_timer=os.environ["TRIAGE_TIMER"],
        lessons_learned_time=os.environ["LESSONS_LEARNED_TIME"],
        investigation_time=os.environ["INVESTIGATION_TIME"],
        eradication_time=os.environ["ERADICATION_TIME"],
        closure_time=os.environ["CLOSURE_TIME"],
        secops_shift_staffing_filename=os.environ["SECOPS_STAFFING_FILENAME"],
        snow_client_key=os.environ["SNOW_CLIENT_KEY"],
        snow_client_secret=os.environ["SNOW_CLIENT_SECRET"],
        snow_functional_account_id=os.environ["SNOW_FUNCTIONAL_ACCOUNT_ID"],
        snow_functional_account_password=os.environ["SNOW_FUNCTIONAL_ACCOUNT_PASSWORD"],
        snow_base_url=os.environ["SNOW_BASE_URL"],
        my_name=os.environ["MY_NAME"],
        my_web_domain=os.environ["MY_WEB_DOMAIN"],
        resp_eng_auto_lead=os.environ["RESP_ENG_AUTO_LEAD"],
        resp_eng_ops_lead=os.environ["RESP_ENG_OPS_LEAD"],
        efficacy_charts_receiver=os.environ["EFFICACY_CHARTS_RECEIVER"],
        phish_fort_api_key=os.environ["PHISH_FORT_API_KEY"],
        my_email_address=os.environ["MY_EMAIL_ADDRESS"],
        twilio_account_sid=os.environ["TWILIO_ACCOUNT_SID"],
        twilio_auth_token=os.environ["TWILIO_AUTH_TOKEN"],
        twilio_whatsapp_number=os.environ["TWILIO_WHATSAPP_NUMBER"],
        my_whatsapp_number=os.environ["MY_WHATSAPP_NUMBER"],
        whatsapp_receiver_numbers=os.environ["WHATSAPP_RECEIVER_NUMBERS"],
        vonage_api_key=os.environ["VONAGE_API_KEY"],
        vonage_api_secret=os.environ["VONAGE_API_SECRET"],
        webex_api_url=os.environ["WEBEX_API_URL"],
        jump_server_host=os.environ["JUMP_SERVER_HOST"],
        tanium_cloud_api_token=os.environ["TANIUM_CLOUD_API_TOKEN"],
        tanium_cloud_api_url=os.environ["TANIUM_CLOUD_API_URL"],
        tanium_onprem_api_token=os.environ["TANIUM_ONPREM_API_TOKEN"],
        tanium_onprem_api_url=os.environ["TANIUM_ONPREM_API_URL"],

    )


@dataclass
class Config:
    """Configuration settings for the application."""
    webex_bot_access_token_moneyball: str
    webex_bot_access_token_soar: str
    webex_bot_access_token_toodles: str
    webex_bot_access_token_jarvais: str
    webex_bot_access_token_barnacles: str
    webex_bot_access_token_hal9000: str
    webex_room_id_aging_tickets: str
    webex_room_id_vinay_test_space: str
    webex_room_id_soc_shift_updates: str
    webex_room_id_epp_tagging: str
    webex_room_id_metrics: str
    webex_room_id_threatcon_collab: str
    webex_room_id_gosc_t2: str
    webex_room_id_automation_engineering: str
    webex_room_id_response_engineering: str
    webex_room_id_phish_fort: str
    webex_room_id_host_announcements: str
    webex_room_id_response_sla_risk: str
    webex_room_id_containment_sla_risk: str
    xsoar_prod_api_base_url: str
    xsoar_prod_ui_base_url: str
    xsoar_dev_api_base_url: str
    xsoar_dev_ui_base_url: str
    xsoar_prod_auth_key: str
    xsoar_prod_auth_id: str
    xsoar_dev_auth_key: str
    xsoar_dev_auth_id: str
    xsoar_lists_filename: str
    team_name: str
    barnacles_approved_users: str
    azdo_org: str
    azdo_de_project: str
    azdo_re_project: str
    azdo_platforms_parent_url: str
    azdo_rea_parent_url: str
    azdo_pat: str
    cs_ro_client_id: str
    cs_ro_client_secret: str
    cs_host_write_client_id: str
    cs_host_write_client_secret: str
    cs_rtr_client_id: str
    cs_rtr_client_secret: str
    cisco_amp_client_id: str
    cisco_amp_client_secret: str
    triage_timer: str
    lessons_learned_time: str
    investigation_time: str
    eradication_time: str
    closure_time: str
    secops_shift_staffing_filename: str
    snow_client_key: str
    snow_client_secret: str
    snow_functional_account_id: str
    snow_functional_account_password: str
    snow_base_url: str
    my_name: str
    my_web_domain: str
    resp_eng_auto_lead: str
    resp_eng_ops_lead: str
    efficacy_charts_receiver: str
    phish_fort_api_key: str
    my_email_address: str
    twilio_account_sid: str
    twilio_auth_token: str
    twilio_whatsapp_number: str
    my_whatsapp_number: str
    whatsapp_receiver_numbers: str
    vonage_api_key: str
    vonage_api_secret: str
    webex_api_url: str
    jump_server_host: str
    tanium_cloud_api_token: str
    tanium_cloud_api_url: str
    tanium_onprem_api_token: str
    tanium_onprem_api_url: str
