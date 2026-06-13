"""Web server configuration and shared resources."""

import os

import pytz

from my_config import get_config
from services import xsoar
from services.xsoar import XsoarEnvironment

CONFIG = get_config(bot_name='web_app')

# Server configuration constants.
# The :8081 forward proxy is the server half of the jump-server egress path
# (only consumed by services/crowdstrike.py when SHOULD_USE_JUMP_SERVER=true).
# Default OFF: on the isolated lab net nothing uses it, and leaving it bound to
# 0.0.0.0 is an unauthenticated open relay. Set SHOULD_START_PROXY=true in the
# env to re-enable if this host ever becomes a corp jump server again.
SHOULD_START_PROXY = os.environ.get("SHOULD_START_PROXY", "false").lower() == "true"
USE_DEBUG_MODE = CONFIG.web_server_debug_mode_on
PROXY_PORT = int(os.environ.get("PROXY_PORT", "8081"))
WEB_SERVER_PORT = CONFIG.web_server_port
COMPANY_EMAIL_DOMAIN = '@' + (CONFIG.my_web_domain or 'example.com')

# Timezone
EASTERN = pytz.timezone('US/Eastern')

# Public config values that can be exposed to templates and JavaScript
# These are non-sensitive values that help with branding/customization
PUBLIC_CONFIG = {
    'company_name': CONFIG.company_name,
    'team_name': CONFIG.team_name,
    'email_domain': CONFIG.my_web_domain,
    'security_email': f"security@{CONFIG.my_web_domain}",
    'logs_viewer_url': CONFIG.logs_viewer_url,
    'watermark_author': CONFIG.watermark_author,
    'environment': CONFIG.environment,
    'is_production': CONFIG.is_production,
    'is_dev': not CONFIG.is_production,
}

# Initialize XSOAR handlers (shared across routes)
prod_list_handler = xsoar.ListHandler(XsoarEnvironment.PROD)
dev_list_handler = xsoar.ListHandler(XsoarEnvironment.DEV)
prod_ticket_handler = xsoar.TicketHandler(XsoarEnvironment.PROD)
dev_ticket_handler = xsoar.TicketHandler(XsoarEnvironment.DEV)
