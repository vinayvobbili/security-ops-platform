import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Import encrypted environment loader
from src.utils.env_encryption import load_encrypted_env, load_plaintext_env, EncryptionError

# Load environment variables from two sources:
# 1. .env (project root) - non-sensitive config like model names
# 2. .secrets.age (data/transient/) - encrypted secrets (API keys, passwords)
ROOT_DIR = Path(__file__).parent

# Load plaintext .env first (low confidentiality config)
env_file = ROOT_DIR / '.env'
if env_file.exists():
    load_plaintext_env(env_file)
    print(f"✓ Loaded config from .env")

# Load encrypted secrets from data/transient/.secrets.age with optional dev bypass
DEV_ALLOW_MISSING_SECRETS = os.environ.get('DEV_ALLOW_MISSING_SECRETS', '').lower() == 'true'
try:
    load_encrypted_env(encrypted_path=str(ROOT_DIR / 'data' / 'transient' / '.secrets.age'))
except EncryptionError as e:
    if DEV_ALLOW_MISSING_SECRETS:
        print(f"⚠️ Proceeding without encrypted secrets (DEV_ALLOW_MISSING_SECRETS=true): {e}")
    else:
        raise


def get_config():
    return Config(
        webex_bot_access_token_moneyball=os.environ.get("WEBEX_BOT_ACCESS_TOKEN_MONEYBALL"),
        webex_bot_access_token_soar=os.environ.get("WEBEX_BOT_ACCESS_TOKEN_SOAR"),
        webex_bot_access_token_dev_xsoar=os.environ.get("WEBEX_BOT_ACCESS_TOKEN_DEV_XSOAR"),
        webex_bot_access_token_toodles=os.environ.get("WEBEX_BOT_ACCESS_TOKEN_TOODLES"),
        webex_bot_access_token_jarvais=os.environ.get("WEBEX_BOT_ACCESS_TOKEN_JARVAIS"),
        webex_bot_access_token_barnacles=os.environ.get("WEBEX_BOT_ACCESS_TOKEN_BARNACLES"),
        webex_bot_access_token_hal9000=os.environ.get("WEBEX_BOT_ACCESS_TOKEN_HAL9000"),
        webex_bot_access_token_pokedex=os.environ.get("WEBEX_BOT_ACCESS_TOKEN_POKEDEX"),
        webex_bot_email_pokedex=os.environ.get("WEBEX_BOT_EMAIL_POKEDEX"),
        webex_bot_email_hal9000=os.environ.get("WEBEX_BOT_EMAIL_HAL9000"),
        webex_room_id_aging_tickets=os.environ.get("WEBEX_ROOM_ID_AGING_TICKETS"),
        webex_room_id_vinay_test_space=os.environ.get("WEBEX_ROOM_ID_VINAY_TEST_SPACE"),
        webex_room_id_soc_shift_updates=os.environ.get("WEBEX_ROOM_ID_SOC_SHIFT_UPDATES"),
        webex_room_id_epp_tagging=os.environ.get("WEBEX_ROOM_ID_EPP_TAGGING"),
        webex_room_id_metrics=os.environ.get("WEBEX_ROOM_ID_METRICS"),
        webex_room_id_threatcon_collab=os.environ.get("WEBEX_ROOM_ID_THREATCON_COLLAB"),
        webex_room_id_gosc_t2=os.environ.get("WEBEX_ROOM_ID_GOSC_T2"),
        webex_room_id_automation_engineering=os.environ.get("WEBEX_ROOM_ID_AUTOMATION_ENGINEERING"),
        webex_room_id_response_engineering=os.environ.get("WEBEX_ROOM_ID_RESPONSE_ENGINEERING"),
        webex_room_id_phish_fort=os.environ.get("WEBEX_ROOM_ID_PHISH_FORT"),
        webex_room_id_host_announcements=os.environ.get("WEBEX_ROOM_ID_HOST_ANNOUNCEMENTS"),
        webex_room_id_response_sla_risk=os.environ.get("WEBEX_ROOM_ID_RESPONSE_SLA_RISK"),
        webex_room_id_containment_sla_risk=os.environ.get("WEBEX_ROOM_ID_CONTAINMENT_SLA_RISK"),
        webex_room_id_qa_tickets=os.environ.get("WEBEX_ROOM_ID_QA_TICKETS"),
        webex_room_id_new_ticket_notifications=os.environ.get("WEBEX_ROOM_ID_NEW_TICKET_NOTIFICATIONS"),
        xsoar_prod_api_base_url=os.environ.get("XSOAR_PROD_API_BASE_URL"),
        xsoar_prod_ui_base_url=os.environ.get("XSOAR_PROD_UI_BASE_URL"),
        xsoar_dev_api_base_url=os.environ.get("XSOAR_DEV_API_BASE_URL"),
        xsoar_dev_ui_base_url=os.environ.get("XSOAR_DEV_UI_BASE_URL"),
        xsoar_prod_auth_key=os.environ.get("XSOAR_PROD_AUTH_KEY"),
        xsoar_prod_auth_id=os.environ.get("XSOAR_PROD_AUTH_ID"),
        xsoar_dev_auth_key=os.environ.get("XSOAR_DEV_AUTH_KEY"),
        xsoar_dev_auth_id=os.environ.get("XSOAR_DEV_AUTH_ID"),
        xsoar_lists_filename=os.environ.get("XSOAR_LISTS_FILENAME"),
        barnacles_approved_users=os.environ.get("BARNACLES_APPROVED_USERS"),
        team_name=os.environ.get("TEAM_NAME"),
        ollama_llm_model=os.environ.get("OLLAMA_LLM_MODEL"),
        ollama_embedding_model=os.environ.get("OLLAMA_EMBEDDING_MODEL", "nomic-embed-text"),
        azdo_org=os.environ.get("AZDO_ORGANIZATION"),
        azdo_de_project=os.environ.get("AZDO_DE_PROJECT"),
        azdo_re_project=os.environ.get("AZDO_RE_PROJECT"),
        azdo_platforms_parent_url=os.environ.get("AZDO_PLATFORMS_PARENT_URL"),
        azdo_rea_parent_url=os.environ.get("AZDO_REA_PARENT_URL"),
        azdo_rea_iteration=os.environ.get("AZDO_REA_ITERATION"),
        azdo_pat=os.environ.get("AZDO_PERSONAL_ACCESS_TOKEN"),
        cs_ro_client_id=os.environ.get("CROWD_STRIKE_RO_CLIENT_ID"),
        cs_ro_client_secret=os.environ.get("CROWD_STRIKE_RO_CLIENT_SECRET"),
        cs_host_write_client_id=os.environ.get("CROWD_STRIKE_HOST_WRITE_CLIENT_ID"),
        cs_host_write_client_secret=os.environ.get("CROWD_STRIKE_HOST_WRITE_CLIENT_SECRET"),
        cs_rtr_client_id=os.environ.get("CROWD_STRIKE_RTR_CLIENT_ID"),
        cs_rtr_client_secret=os.environ.get("CROWD_STRIKE_RTR_CLIENT_SECRET"),
        cisco_amp_client_id=os.environ.get("CISCO_AMP_CLIENT_ID"),
        cisco_amp_client_secret=os.environ.get("CISCO_AMP_CLIENT_SECRET"),
        triage_timer=os.environ.get("TRIAGE_TIMER"),
        lessons_learned_time=os.environ.get("LESSONS_LEARNED_TIME"),
        investigation_time=os.environ.get("INVESTIGATION_TIME"),
        eradication_time=os.environ.get("ERADICATION_TIME"),
        closure_time=os.environ.get("CLOSURE_TIME"),
        secops_shift_staffing_filename=os.environ.get("SECOPS_STAFFING_FILENAME"),
        secops_shift_staffing_sheet_name=os.environ.get("SECOPS_STAFFING_SHEETNAME"),
        snow_client_key=os.environ.get("SNOW_CLIENT_KEY"),
        snow_client_secret=os.environ.get("SNOW_CLIENT_SECRET"),
        snow_functional_account_id=os.environ.get("SNOW_FUNCTIONAL_ACCOUNT_ID"),
        snow_functional_account_password=os.environ.get("SNOW_FUNCTIONAL_ACCOUNT_PASSWORD"),
        snow_base_url=os.environ.get("SNOW_BASE_URL"),
        my_name=os.environ.get("MY_NAME"),
        my_web_domain=os.environ.get("MY_WEB_DOMAIN"),
        resp_eng_auto_lead=os.environ.get("RESP_ENG_AUTO_LEAD"),
        resp_eng_ops_lead=os.environ.get("RESP_ENG_OPS_LEAD"),
        efficacy_charts_receiver=os.environ.get("EFFICACY_CHARTS_RECEIVER"),
        phish_fort_api_key=os.environ.get("PHISH_FORT_API_KEY"),
        my_email_address=os.environ.get("MY_EMAIL_ADDRESS"),
        twilio_account_sid=os.environ.get("TWILIO_ACCOUNT_SID"),
        twilio_auth_token=os.environ.get("TWILIO_AUTH_TOKEN"),
        twilio_whatsapp_number=os.environ.get("TWILIO_WHATSAPP_NUMBER"),
        my_whatsapp_number=os.environ.get("MY_WHATSAPP_NUMBER"),
        whatsapp_receiver_numbers=os.environ.get("WHATSAPP_RECEIVER_NUMBERS"),
        vonage_api_key=os.environ.get("VONAGE_API_KEY"),
        vonage_api_secret=os.environ.get("VONAGE_API_SECRET"),
        webex_api_url=os.environ.get("WEBEX_API_URL"),
        jump_server_host=os.environ.get("JUMP_SERVER_HOST"),
        tanium_cloud_api_token=os.environ.get("TANIUM_CLOUD_API_TOKEN"),
        tanium_cloud_api_url=os.environ.get("TANIUM_CLOUD_API_URL"),
        tanium_onprem_api_token=os.environ.get("TANIUM_ONPREM_API_TOKEN"),
        tanium_onprem_api_url=os.environ.get("TANIUM_ONPREM_API_URL"),
        zscaler_base_url=os.environ.get("ZSCALER_BASE_URL"),
        zscaler_username=os.environ.get("ZSCALER_USERNAME"),
        zscaler_password=os.environ.get("ZSCALER_PASSWORD"),
        zscaler_api_key=os.environ.get("ZSCALER_API_KEY"),
        infoblox_base_url=os.environ.get("INFOBLOX_BASE_URL"),
        infoblox_username=os.environ.get("INFOBLOX_USERNAME"),
        infoblox_password=os.environ.get("INFOBLOX_PASSWORD"),
        palo_alto_host=os.environ.get("PALO_ALTO_HOST"),
        palo_alto_api_key=os.environ.get("PALO_ALTO_API_KEY"),
        open_weather_map_api_key=os.environ.get("OPEN_WEATHER_MAP_API_KEY"),
        web_server_debug_mode_on=str(os.environ.get("WEB_SERVER_DEBUG_MODE_ON", "False")).lower() == "true",
        web_server_port=int(os.environ.get("WEB_SERVER_PORT", "8080")),
        # Microsoft Teams Toodles Bot configuration (from Azure Bot Service)
        teams_toodles_app_id=os.environ.get("TEAMS_TOODLES_APP_ID"),
        teams_toodles_app_password=os.environ.get("TEAMS_TOODLES_APP_PASSWORD"),
        teams_toodles_tenant_id=os.environ.get("TEAMS_TOODLES_TENANT_ID"),
        toodles_password=os.environ.get("TOODLES_PASSWORD"),
        flask_secret_key=os.environ.get("FLASK_SECRET_KEY"),
    )


@dataclass
class Config:
    """Configuration settings for the application."""
    webex_bot_access_token_moneyball: Optional[str] = None
    webex_bot_access_token_soar: Optional[str] = None
    webex_bot_access_token_dev_xsoar: Optional[str] = None
    webex_bot_access_token_toodles: Optional[str] = None
    webex_bot_access_token_jarvais: Optional[str] = None
    webex_bot_access_token_barnacles: Optional[str] = None
    webex_bot_access_token_hal9000: Optional[str] = None
    webex_bot_access_token_pokedex: Optional[str] = None
    webex_bot_email_pokedex: Optional[str] = None
    webex_bot_email_hal9000: Optional[str] = None
    webex_room_id_aging_tickets: Optional[str] = None
    webex_room_id_vinay_test_space: Optional[str] = None
    webex_room_id_soc_shift_updates: Optional[str] = None
    webex_room_id_epp_tagging: Optional[str] = None
    webex_room_id_metrics: Optional[str] = None
    webex_room_id_threatcon_collab: Optional[str] = None
    webex_room_id_gosc_t2: Optional[str] = None
    webex_room_id_automation_engineering: Optional[str] = None
    webex_room_id_response_engineering: Optional[str] = None
    webex_room_id_phish_fort: Optional[str] = None
    webex_room_id_host_announcements: Optional[str] = None
    webex_room_id_response_sla_risk: Optional[str] = None
    webex_room_id_containment_sla_risk: Optional[str] = None
    webex_room_id_qa_tickets: Optional[str] = None
    webex_room_id_new_ticket_notifications: Optional[str] = None
    xsoar_prod_api_base_url: Optional[str] = None
    xsoar_prod_ui_base_url: Optional[str] = None
    xsoar_dev_api_base_url: Optional[str] = None
    xsoar_dev_ui_base_url: Optional[str] = None
    xsoar_prod_auth_key: Optional[str] = None
    xsoar_prod_auth_id: Optional[str] = None
    xsoar_dev_auth_key: Optional[str] = None
    xsoar_dev_auth_id: Optional[str] = None
    xsoar_lists_filename: Optional[str] = None
    team_name: Optional[str] = None
    ollama_llm_model: Optional[str] = None
    ollama_embedding_model: Optional[str] = "nomic-embed-text"
    barnacles_approved_users: Optional[str] = None
    azdo_org: Optional[str] = None
    azdo_de_project: Optional[str] = None
    azdo_re_project: Optional[str] = None
    azdo_platforms_parent_url: Optional[str] = None
    azdo_rea_parent_url: Optional[str] = None
    azdo_rea_iteration: Optional[str] = None
    azdo_pat: Optional[str] = None
    cs_ro_client_id: Optional[str] = None
    cs_ro_client_secret: Optional[str] = None
    cs_host_write_client_id: Optional[str] = None
    cs_host_write_client_secret: Optional[str] = None
    cs_rtr_client_id: Optional[str] = None
    cs_rtr_client_secret: Optional[str] = None
    cisco_amp_client_id: Optional[str] = None
    cisco_amp_client_secret: Optional[str] = None
    triage_timer: Optional[str] = None
    lessons_learned_time: Optional[str] = None
    investigation_time: Optional[str] = None
    eradication_time: Optional[str] = None
    closure_time: Optional[str] = None
    secops_shift_staffing_filename: Optional[str] = None
    secops_shift_staffing_sheet_name: Optional[str] = None
    snow_client_key: Optional[str] = None
    snow_client_secret: Optional[str] = None
    snow_functional_account_id: Optional[str] = None
    snow_functional_account_password: Optional[str] = None
    snow_base_url: Optional[str] = None
    my_name: Optional[str] = None
    my_web_domain: Optional[str] = None
    resp_eng_auto_lead: Optional[str] = None
    resp_eng_ops_lead: Optional[str] = None
    efficacy_charts_receiver: Optional[str] = None
    phish_fort_api_key: Optional[str] = None
    my_email_address: Optional[str] = None
    twilio_account_sid: Optional[str] = None
    twilio_auth_token: Optional[str] = None
    twilio_whatsapp_number: Optional[str] = None
    my_whatsapp_number: Optional[str] = None
    whatsapp_receiver_numbers: Optional[str] = None
    vonage_api_key: Optional[str] = None
    vonage_api_secret: Optional[str] = None
    webex_api_url: Optional[str] = None
    jump_server_host: Optional[str] = None
    tanium_cloud_api_token: Optional[str] = None
    tanium_cloud_api_url: Optional[str] = None
    tanium_onprem_api_token: Optional[str] = None
    tanium_onprem_api_url: Optional[str] = None
    zscaler_base_url: Optional[str] = None
    zscaler_username: Optional[str] = None
    zscaler_password: Optional[str] = None
    zscaler_api_key: Optional[str] = None
    infoblox_base_url: Optional[str] = None
    infoblox_username: Optional[str] = None
    infoblox_password: Optional[str] = None
    palo_alto_host: Optional[str] = None
    palo_alto_api_key: Optional[str] = None
    open_weather_map_api_key: Optional[str] = None
    web_server_debug_mode_on: bool = False
    web_server_port: Optional[int] = None
    # Microsoft Teams Toodles Bot configuration (from Azure Bot Service)
    teams_toodles_app_id: Optional[str] = None
    teams_toodles_app_password: Optional[str] = None
    teams_toodles_tenant_id: Optional[str] = None
    toodles_password: Optional[str] = None
    flask_secret_key: Optional[str] = None
