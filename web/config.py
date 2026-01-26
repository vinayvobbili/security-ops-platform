"""Web server configuration and shared resources."""

import pytz

from my_config import get_config
from services import xsoar
from services.xsoar import XsoarEnvironment

CONFIG = get_config()

# Server configuration constants
SHOULD_START_PROXY = True
USE_DEBUG_MODE = CONFIG.web_server_debug_mode_on
PROXY_PORT = 8081
WEB_SERVER_PORT = CONFIG.web_server_port
COMPANY_EMAIL_DOMAIN = '@' + CONFIG.my_web_domain

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
}

# Initialize XSOAR handlers (shared across routes)
prod_list_handler = xsoar.ListHandler(XsoarEnvironment.PROD)
prod_ticket_handler = xsoar.TicketHandler(XsoarEnvironment.PROD)
dev_ticket_handler = xsoar.TicketHandler(XsoarEnvironment.DEV)
