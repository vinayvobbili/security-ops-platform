#!/usr/bin/python3

"""
Toodles Bot - Configuration Guide
==================================

This bot supports three operating modes:

1. FULL RESILIENCE MODE (for ZScaler/corporate proxy environments)
   SHOULD_USE_RESILIENCY = True
   USE_AUTO_RECONNECT = ignored
   Features: SSL patching, WebSocket patching, device cleanup, auto-reconnect

2. LITE RESILIENCE MODE (recommended for production without ZScaler)
   SHOULD_USE_RESILIENCY = False
   USE_AUTO_RECONNECT = True
   Features: Device cleanup, auto-reconnect (handles WebSocket timeouts)

3. STANDARD MODE (no resilience, manual restart required on disconnection)
   SHOULD_USE_RESILIENCY = False
   USE_AUTO_RECONNECT = False
   Features: None (standard WebexBot)

Recommended configuration: LITE RESILIENCE MODE
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# Setup logging FIRST before any imports that might use it
import logging

ROOT_DIRECTORY = Path(__file__).parent.parent

from src.utils.logging_utils import setup_logging

# Configure logging with centralized utility
setup_logging(
    bot_name='toodles',
    log_level=logging.WARNING,
    log_dir=str(ROOT_DIRECTORY / "logs"),
    info_modules=['__main__', 'src.utils.bot_resilience', 'src.utils.webex_device_manager', 'src.utils.connection_health']
)

logger = logging.getLogger(__name__)

# Suppress noisy warnings from webex_bot module
logging.getLogger('webex_bot.webex_bot').setLevel(logging.ERROR)

# Load configuration early (before SSL config)
from my_config import get_config

CONFIG = get_config()

# ALWAYS configure SSL for proxy environments (auto-detects ZScaler/proxies)
from src.utils.ssl_config import configure_ssl_if_needed

configure_ssl_if_needed(verbose=True)

# ALWAYS apply enhanced WebSocket patches for connection resilience
# This is critical to prevent the bot from going to sleep
from src.utils.enhanced_websocket_client import patch_websocket_client

patch_websocket_client()

import ipaddress
import re
from datetime import datetime, timedelta
from urllib.parse import quote
from zoneinfo import ZoneInfo

import pandas
import requests
import webexpythonsdk.models.cards.inputs as INPUTS
import webexpythonsdk.models.cards.options as OPTIONS
from tabulate import tabulate
from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot
from webexpythonsdk import WebexAPI
from webexpythonsdk.models.cards import (
    Colors, TextBlock, FontWeight, Column, AdaptiveCard, ColumnSet, HorizontalAlignment, ActionSet, ActionStyle,
    options
)
from webexpythonsdk.models.cards.actions import Submit

import src.components.oncall as oncall
from data.data_maps import azdo_projects, azdo_orgs, azdo_area_paths

from services import xsoar, azdo
from services.approved_testing_utils import add_approved_testing_entry
from services.crowdstrike import CrowdStrikeClient
from services.xsoar import ListHandler, TicketHandler, XsoarEnvironment
from src.components.url_lookup_traffic import URLChecker
from src.utils.http_utils import get_session
from src.utils.logging_utils import log_activity
from src.utils.webex_device_manager import cleanup_devices_on_startup

# Get robust HTTP session instance
http_session = get_session()

# Increase timeout from default 60s to 180s for unreliable networks
webex_api = WebexAPI(
    access_token=CONFIG.webex_bot_access_token_toodles,
    single_request_timeout=180
)

# Global variables
bot_instance = None

# Timezone constant for consistent usage
EASTERN_TZ = ZoneInfo("America/New_York")

# Fun toodles-themed messages and features
TOODLES_MESSAGES = [
    "🛠️ Fixing things faster than you can say 'toodles'!",
    "🔧 Engineering magic in progress...",
    "⚡ Supercharging your workflow!",
    "🎯 Targeting peak efficiency!",
    "🚀 Launching productivity rockets!",
    "🧠 Brain-powering your operations!",
    "⚙️ Fine-tuning the digital machinery!",
    "🎪 Orchestrating a symphony of solutions!",
    "🏃‍♂️ Running at warp speed through tasks!",
    "✨ Sprinkling some automation fairy dust!"
]

ACHIEVEMENT_MESSAGES = {
    "ticket_master": "🎫 **Ticket Master!** You've handled {count} tickets today!",
    "early_responder": "🌅 **Early Responder!** Up and running before the sun!",
    "night_shift": "🌙 **Night Shift Hero!** Keeping watch while others sleep!",
    "weekend_warrior": "⚔️ **Weekend Warrior!** Dedication that never rests!",
    "efficiency_expert": "⚡ **Efficiency Expert!** Speed and precision combined!",
    "problem_solver": "🧩 **Problem Solver!** No challenge too complex!"
}

TOODLES_GREETINGS = [
    "👋 Toodles is here to help!",
    "🎉 Ready to tackle some tickets!",
    "🔥 Let's get this workflow blazing!",
    "⚡ Powered up and ready to go!",
    "🚀 Mission control, standing by!"
]


def get_random_toodles_message():
    """Get a random fun toodles message."""
    import random
    return random.choice(TOODLES_MESSAGES)


def get_random_greeting():
    """Get a random toodles greeting."""
    import random
    return random.choice(TOODLES_GREETINGS)


def get_achievement_message(activity_type, count=1):
    """Generate achievement messages based on usage patterns."""
    import random
    current_time = datetime.now(EASTERN_TZ)
    hour = current_time.hour
    weekday = current_time.weekday()

    achievements = []

    # Time-based achievements
    if 5 <= hour <= 8:
        achievements.append(ACHIEVEMENT_MESSAGES["early_responder"])
    elif 22 <= hour or hour <= 2:
        achievements.append(ACHIEVEMENT_MESSAGES["night_shift"])

    # Weekend achievement
    if weekday >= 5:  # Saturday = 5, Sunday = 6
        achievements.append(ACHIEVEMENT_MESSAGES["weekend_warrior"])

    # Activity-based achievements
    if activity_type == "ticket" and count >= 5:
        achievements.append(ACHIEVEMENT_MESSAGES["ticket_master"].format(count=count))
    elif activity_type == "efficiency":
        achievements.append(ACHIEVEMENT_MESSAGES["efficiency_expert"])

    return achievements if achievements else [random.choice(list(ACHIEVEMENT_MESSAGES.values()))]


approved_testing_list_name: str = f"{CONFIG.team_name}_Approved_Testing"
approved_testing_master_list_name: str = f"{CONFIG.team_name}_Approved_Testing_MASTER"

prod_headers = {
    "authorization": CONFIG.xsoar_prod_auth_key,
    "x-xdr-auth-id": CONFIG.xsoar_prod_auth_id,
    "Accept": "application/json"
}
dev_headers = {
    "authorization": CONFIG.xsoar_dev_auth_key,
    "x-xdr-auth-id": CONFIG.xsoar_dev_auth_id,
    "Accept": "application/json"
}
headers = prod_headers

# Initialize XSOAR handlers for production environment
prod_incident_handler = TicketHandler(XsoarEnvironment.PROD)
prod_list_handler = ListHandler(XsoarEnvironment.PROD)

NEW_TICKET_CARD = {
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "type": "AdaptiveCard",
    "version": "1.3",
    "body": [
        {
            "type": "TextBlock",
            "text": "New X Ticket",
            "color": "Accent",
            "weight": "Bolder",
            "size": "Medium",
            "horizontalAlignment": "Center"
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": 1,
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "Title",
                            "wrap": True,
                            "horizontalAlignment": "right"
                        }
                    ]
                },
                {
                    "type": "Column",
                    "width": 6,
                    "items": [
                        {
                            "type": "Input.Text",
                            "id": "title",
                            "placeholder": ""
                        }
                    ]
                }
            ]
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": 1,
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "Details",
                            "wrap": True,
                            "horizontalAlignment": "right"
                        }
                    ]
                },
                {
                    "type": "Column",
                    "width": 6,
                    "items": [
                        {
                            "type": "Input.Text",
                            "id": "details",
                            "placeholder": "",
                            "isMultiline": True
                        }
                    ]
                }
            ],
            "spacing": "None"
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": 1,
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "Detection Source",
                            "wrap": True,
                            "horizontalAlignment": "left"
                        }
                    ]
                },
                {
                    "type": "Column",
                    "width": 2,
                    "items": [
                        {
                            "type": "Input.ChoiceSet",
                            "id": "detection_source",
                            "choices": [
                                {
                                    "title": "Threat Hunt",
                                    "value": "Threat Hunt"
                                },
                                {
                                    "title": "CrowdStrike Falcon",
                                    "value": "CrowdStrike Falcon"
                                },
                                {
                                    "title": "Employee Reported",
                                    "value": "Employee Reported"
                                },
                                {
                                    "title": "Recorded Future",
                                    "value": "Recorded Future"
                                },
                                {
                                    "title": "Third Party",
                                    "value": "Third Party"
                                },
                                {
                                    "title": "Abnormal Security",
                                    "value": "Abnormal Security"
                                },
                                {
                                    "title": "Akamai",
                                    "value": "Akamai"
                                },
                                {
                                    "title": "AppDynamics",
                                    "value": "AppDynamics"
                                },
                                {
                                    "title": "Area1",
                                    "value": "Area1"
                                },
                                {
                                    "title": "Cisco AMP",
                                    "value": "Cisco AMP"
                                },
                                {
                                    "title": "CrowdStrike Falcon IDP",
                                    "value": "CrowdStrike Falcon IDP"
                                },
                                {
                                    "title": "Customer Reported",
                                    "value": "Customer Reported"
                                },
                                {
                                    "title": "Cyberbit",
                                    "value": "Cyberbit"
                                },
                                {
                                    "title": "Flashpoint",
                                    "value": "Flashpoint"
                                },
                                {
                                    "title": "ForcePoint",
                                    "value": "ForcePoint"
                                },
                                {
                                    "title": "Illusive",
                                    "value": "Illusive"
                                },
                                {
                                    "title": "Infoblox",
                                    "value": "Infoblox"
                                },
                                {
                                    "title": "Intel471",
                                    "value": "Intel471"
                                },
                                {
                                    "title": "IronPort",
                                    "value": "IronPort"
                                },
                                {
                                    "title": "Lumen",
                                    "value": "Lumen"
                                },
                                {
                                    "title": "PaloAlto",
                                    "value": "PaloAlto"
                                },
                                {
                                    "title": "Prisma Cloud",
                                    "value": "Prisma Cloud"
                                },
                                {
                                    "title": "Rubrik",
                                    "value": "Rubrik"
                                },
                                {
                                    "title": "Tanium",
                                    "value": "Tanium"
                                },
                                {
                                    "title": "Vectra MDR",
                                    "value": "Vectra MDR"
                                },
                                {
                                    "title": "ZeroFox",
                                    "value": "ZeroFox"
                                },
                                {
                                    "title": "ZScaler",
                                    "value": "ZScaler"
                                },
                                {
                                    "title": "Other",
                                    "value": "Other"
                                }
                            ],
                            "placeholder": "Select an option",
                            "isRequired": True,
                            "errorMessage": "Required"
                        },
                    ]
                }
            ],
            "spacing": "None"
        },
        {
            "type": "ActionSet",
            "spacing": "small",
            "actions": [
                {
                    "type": "Action.Submit",
                    "title": "Submit",
                    "data": {
                        "callback_keyword": "create_x_ticket"
                    },
                    "style": "positive"
                }
            ],
            "horizontalAlignment": "right"
        }
    ]
}

IOC_HUNT = {
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "version": "1.3",
    "type": "AdaptiveCard",
    "body": [
        {
            "type": "TextBlock",
            "text": "Title",
            "wrap": True
        },
        {
            "type": "Input.Text",
            "id": "ioc_hunt_title",
            "wrap": True
        },
        {
            "type": "TextBlock",
            "text": "IOCs",
            "wrap": True
        },
        {
            "type": "Input.Text",
            "id": "ioc_hunt_iocs",
            "placeholder": "Domains/Email-Addresses/Files",
            "wrap": True,
            "isMultiline": True
        },
        {
            "type": "ActionSet",
            "spacing": "none",
            "actions": [
                {
                    "type": "Action.Submit",
                    "title": "Submit",
                    "data": {
                        "callback_keyword": "ioc_hunt"
                    },
                    "style": "positive"
                }
            ],
            "horizontalAlignment": "right"
        }
    ]
}

THREAT_HUNT = {
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "version": "1.3",
    "type": "AdaptiveCard",
    "body": [
        {
            "type": "TextBlock",
            "text": "Hunt Title:",
            "wrap": True
        },
        {
            "type": "Input.Text",
            "id": "threat_hunt_title",
            "wrap": True
        },
        {
            "type": "TextBlock",
            "text": "Hunt Description:",
            "wrap": True
        },
        {
            "type": "Input.Text",
            "id": "threat_hunt_desc",
            "wrap": True,
            "isMultiline": True
        },
        {
            "type": "ActionSet",
            "spacing": "small",
            "actions": [
                {
                    "type": "Action.Submit",
                    "title": "Submit",
                    "data": {
                        "callback_keyword": "threat_hunt"
                    },
                    "style": "positive"
                }
            ],
            "horizontalAlignment": "right"
        }
    ]
}

AZDO_CARD = {
    "type": "AdaptiveCard",
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "version": "1.3",
    "body": [
        {
            "type": "TextBlock",
            "text": "New AZDO Work Item",
            "horizontalAlignment": "center",
            "weight": "bolder",
            "size": "medium",
            "color": "accent"
        },
        {
            "type": "TextBlock",
            "text": "Title",
            "color": "Accent"
        },
        {
            "type": "Input.Text",
            "wrap": True,
            "id": "wit_title"
        },
        {
            "type": "TextBlock",
            "text": "Description",
            "color": "Accent"
        },
        {
            "type": "Input.Text",
            "wrap": True,
            "id": "wit_description",
            "isMultiline": True
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "Type",
                            "color": "Accent"
                        },
                        {
                            "type": "Input.ChoiceSet",
                            "wrap": True,
                            "id": "wit_type",
                            "choices": [
                                {
                                    "title": "User Story",
                                    "value": "User%20Story"
                                },
                                {
                                    "title": "Bug",
                                    "value": "Bug"
                                },
                                {
                                    "title": "Task",
                                    "value": "Task"
                                }
                            ],
                        }
                    ]
                },
                {
                    "type": "Column",
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "Project",
                            "color": "Accent"
                        },
                        {
                            "type": "Input.ChoiceSet",
                            "wrap": True,
                            "id": "project",
                            "choices": [
                                {
                                    "title": "Cyber Platforms",
                                    "value": "platforms"
                                },
                                {
                                    "title": "Resp Engg Automation",
                                    "value": "rea"
                                },
                                {
                                    "title": "Resp Engg Operations",
                                    "value": "reo"
                                },
                                {
                                    "title": "Detection Engineering",
                                    "value": "de"
                                },
                                {
                                    "title": "Global Detection and Response Shared",
                                    "value": "gdr"
                                }
                            ],
                        }
                    ]
                },
                {
                    "type": "Column",
                    "items": [
                        {
                            "type": "ActionSet",
                            "actions": [
                                {
                                    "type": "Action.Submit",
                                    "title": "Create",
                                    "data": {
                                        "callback_keyword": "azdo_wit"
                                    },
                                    "style": "positive"
                                }
                            ]
                        }
                    ],
                    "verticalContentAlignment": "Bottom",
                    "horizontalAlignment": "Right"
                }
            ]
        }
    ]
}

APPROVED_TESTING_CARD = {
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "type": "AdaptiveCard",
    "version": "1.3",
    "body": [
        {
            "type": "TextBlock",
            "text": "Approved Testing",
            "horizontalAlignment": "center",
            "weight": "bolder",
            "size": "medium",
            "color": "accent"
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": 1,
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "Username(s)",
                            "horizontalAlignment": "right"
                        }
                    ],
                    "verticalContentAlignment": "Center"
                },
                {
                    "type": "Column",
                    "width": 3,
                    "items": [
                        {
                            "type": "Input.Text",
                            "id": "usernames",
                            "placeholder": "Use , as seperator"
                        }
                    ]
                }
            ],
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": 1,
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "IP(s), Hostname(s) of Tester",
                            "wrap": True,
                            "horizontalAlignment": "right"
                        }
                    ],
                    "verticalContentAlignment": "Center"
                },
                {
                    "type": "Column",
                    "width": 3,
                    "items": [
                        {
                            "type": "Input.Text",
                            "id": "ip_addresses_and_host_names_of_tester",
                            "placeholder": "Use , as seperator",
                            "isMultiline": True
                        }
                    ]
                }
            ]
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": 1,
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "IP(s), Hostname(s) to be tested",
                            "wrap": True,
                            "horizontalAlignment": "right"
                        }
                    ],
                    "verticalContentAlignment": "Center"
                },
                {
                    "type": "Column",
                    "width": 3,
                    "items": [
                        {
                            "type": "Input.Text",
                            "id": "ip_addresses_and_host_names_to_be_tested",
                            "placeholder": "Use , as seperator",
                            "isMultiline": True
                        }
                    ]
                }
            ]
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": 1,
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "Description",
                            "horizontalAlignment": "right"
                        }
                    ],
                    "verticalContentAlignment": "Center"
                },
                {
                    "type": "Column",
                    "width": 3,
                    "items": [
                        {
                            "type": "Input.Text",
                            "id": "description",
                            "isMultiline": True
                        }
                    ]
                }
            ]
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": 1,
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "Notes/Scope",
                            "wrap": True,
                            "horizontalAlignment": "right"
                        }
                    ],
                    "verticalContentAlignment": "Center"
                },
                {
                    "type": "Column",
                    "width": 3,
                    "items": [
                        {
                            "type": "Input.Text",
                            "id": "scope"
                        }
                    ]
                }
            ],
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": 1,
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "Keep until",
                            "horizontalAlignment": "right"
                        }
                    ],
                    "verticalContentAlignment": "Center"
                },
                {
                    "type": "Column",
                    "width": 3,
                    "items": [
                        {
                            "type": "ColumnSet",
                            "columns": [
                                {
                                    "type": "Column",
                                    "width": 2,
                                    "items": [
                                        {
                                            "type": "Input.Date",
                                            "id": "expiry_date",
                                            "placeholder": "Enter a date"
                                        }
                                    ]
                                },
                                {
                                    "type": "Column",
                                    "width": 1,
                                    "items": [
                                        {
                                            "type": "TextBlock",
                                            "text": "5 PM ET"
                                        }
                                    ],
                                    "verticalContentAlignment": "Center"
                                }
                            ]
                        }
                    ]
                }
            ],
        },
        {
            "type": "ActionSet",
            "spacing": "small",
            "actions": [
                {
                    "type": "Action.Submit",
                    "title": "Get Current List",
                    "data": {
                        "callback_keyword": "current_approved_testing"
                    }
                },
                {
                    "type": "Action.Submit",
                    "title": "Remove",
                    "data": {
                        "callback_keyword": "remove_approved_testing"
                    },
                    "style": "positive"
                },
                {
                    "type": "Action.Submit",
                    "title": "Add",
                    "data": {
                        "callback_keyword": "add_approved_testing"
                    },
                    "style": "destructive"
                },
            ],
            "horizontalAlignment": "right"
        }
    ]
}

TICKET_IMPORT_CARD = AdaptiveCard(
    body=[
        ColumnSet(
            columns=[
                Column(
                    items=[
                        TextBlock(
                            text="Prod ticket#",
                            horizontalAlignment=HorizontalAlignment.RIGHT,
                        )
                    ],
                    width="auto",
                    verticalContentAlignment=OPTIONS.VerticalContentAlignment.CENTER
                ),
                Column(
                    items=[
                        INPUTS.Text(
                            id="prod_ticket_number",
                            placeholder="Enter prod ticket number",
                            isRequired=True,
                            errorMessage='Required'
                        )
                    ],
                    width="stretch",
                    verticalContentAlignment=OPTIONS.VerticalContentAlignment.CENTER
                )
            ]
        ),
        ActionSet(
            actions=[
                Submit(
                    title="Submit",
                    style=ActionStyle.POSITIVE,
                    data={"callback_keyword": "import"}
                )
            ]
        )
    ]
)

TUNING_REQUEST_CARD = AdaptiveCard(
    body=[
        TextBlock(
            text="New Tuning Request",
            wrap=True,
            horizontalAlignment=HorizontalAlignment.CENTER,
            weight=FontWeight.BOLDER,
            color=Colors.ACCENT,
        ),
        INPUTS.Text(
            id="title",
            label="Title",
            isRequired=True,
            errorMessage="Required"
        ),
        INPUTS.Text(
            id="description",
            label="Description",
            isMultiline=True,
            isRequired=True,
            errorMessage="Required"
        ),
        INPUTS.Text(
            id="tickets",
            placeholder="A few recent X tix created by this rule!",
            label="X ticket(s)",
            isRequired=True,
            errorMessage="Required"
        ),
        INPUTS.Text(
            id="ticket_volume",
            placeholder="Example: 10 tickets/week",
            label="Approx. Ticket Volume",
            isRequired=True,
            errorMessage="Required"
        ),
        ActionSet(
            actions=[
                Submit(
                    title="Submit",
                    style=ActionStyle.POSITIVE,
                    data={"callback_keyword": "tuning_request"}
                )
            ],
        )
    ]
)

URL_BLOCK_VERDICT_CARD = {
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "type": "AdaptiveCard",
    "version": "1.3",
    "body": [
        {
            "type": "TextBlock",
            "text": "Check URL Block Verdict",
            "wrap": True,
            "horizontalAlignment": "Center",
            "weight": "Bolder",
            "color": "Accent"
        },
        {
            "type": "Input.Text",
            "id": "urls_to_check",
            "label": "URLs to Check (comma-separated)",
            "placeholder": "Enter the URLs to check",
            "isRequired": True,
            "errorMessage": "Required",
            "isMultiline": True
        },
        {
            "type": "ActionSet",
            "horizontalAlignment": "Right",
            "actions": [
                {
                    "type": "Action.Submit",
                    "title": "Get Block Verdict",
                    "style": "positive",
                    "data": {
                        "callback_keyword": "url_verdict"
                    }
                }
            ]
        }
    ]
}

all_options_card = {
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "type": "AdaptiveCard",
    "version": "1.3",
    "actions": [
        {
            "type": "Action.ShowCard",
            "title": "Approved Testing",
            "card": APPROVED_TESTING_CARD
        },
        {
            "type": "Action.ShowCard",
            "title": "On Call",
            "card": {
                "type": "AdaptiveCard",
                "body": [{
                    "type": "ActionSet",
                    "spacing": "None",
                    "actions": [
                        {
                            "type": "Action.Submit",
                            "title": "Who",
                            "data": {
                                "callback_keyword": "who"
                            }
                        },
                        {
                            "type": "Action.Submit",
                            "title": "Rotation",
                            "data": {
                                "callback_keyword": "rotation"
                            }
                        }
                    ]
                }]
            }
        },
        {
            "type": "Action.ShowCard",
            "title": "CrowdStrike",
            "card": {
                "type": "AdaptiveCard",
                "body": [
                    {
                        "type": "TextBlock",
                        "size": "small",
                        "weight": "bolder",
                        "text": "CS Containment Status",
                        "horizontalAlignment": "center",
                        "wrap": True,
                        "style": "heading"
                    },
                    {
                        "type": "ColumnSet",
                        "columns": [
                            {
                                "type": "Column",
                                "width": "1",
                                "items": [
                                    {
                                        "type": "TextBlock",
                                        "text": "Host Name:",
                                        "wrap": True,
                                        "horizontalAlignment": "right"
                                    }
                                ]
                            },
                            {
                                "type": "Column",
                                "width": 3,
                                "items": [
                                    {
                                        "type": "Input.Text",
                                        "id": "host_name_cs"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "type": "ActionSet",
                        "spacing": "None",
                        "actions": [
                            {
                                "type": "Action.Submit",
                                "title": "Check Status",
                                "data": {
                                    "callback_keyword": "status"
                                }
                            },
                            {
                                "type": "Action.Submit",
                                "title": "Uncontain",
                                "data": {
                                    "callback_keyword": "uncontain"
                                },
                                "style": "positive"
                            },
                            {
                                "type": "Action.Submit",
                                "title": "Contain",
                                "data": {
                                    "callback_keyword": "contain"
                                },
                                "style": "destructive"
                            }
                        ],
                        "horizontalAlignment": "right"
                    }
                ]
            }
        },
        {
            "type": "Action.ShowCard",
            "title": "XSOAR",
            "card": {
                "type": "AdaptiveCard",
                "body": [
                    {
                        "type": "ActionSet",
                        "spacing": "None",
                        "actions": [
                            {
                                "type": "Action.ShowCard",
                                "title": "IOC Hunt",
                                "card": IOC_HUNT
                            },
                            {
                                "type": "Action.ShowCard",
                                "title": "Threat Hunt",
                                "card": THREAT_HUNT
                            },
                            {
                                "type": "Action.ShowCard",
                                "title": "Import Ticket",
                                "card": TICKET_IMPORT_CARD.to_dict()
                            }
                        ]
                    }
                ]
            },
        },
        {
            "type": "Action.ShowCard",
            "title": "Misc",
            "card": {
                "type": "AdaptiveCard",
                "body": [
                    {
                        "type": "ActionSet",
                        "spacing": "None",
                        "actions": [
                            {
                                "type": "Action.Submit",
                                "title": "Fav URLs",
                                "data": {
                                    "callback_keyword": "urls"
                                }
                            },
                            {
                                "type": "Action.Submit",
                                "title": "Holidays",
                                "data": {
                                    "callback_keyword": "holidays"
                                }
                            }
                        ]
                    }
                ]
            }
        }
    ]
}


def get_url_card():
    """
    Get URL card with METCIRT URLs from XSOAR.
    Returns a card with error message if XSOAR is not configured or list is unavailable.
    """
    try:
        metcirt_urls = prod_list_handler.get_list_data_by_name('METCIRT URLs')
        actions = []

        # Handle case where list is not found or XSOAR is not configured
        if metcirt_urls is None:
            logger.warning("⚠️ METCIRT URLs list not available from XSOAR")
            actions = [{
                "type": "Action.Submit",
                "title": "URLs unavailable (XSOAR not configured)",
                "data": {}
            }]
        else:
            # Iterate through the list of URLs and create button actions
            for item in metcirt_urls:
                if "url" in item:  # Handle URL buttons with Action.OpenUrl
                    url = item['url']
                    # Ensure URL has a protocol (add https:// if missing)
                    if not url.startswith(('http://', 'https://')):
                        url = f"https://{url}"

                    actions.append({
                        "type": "Action.OpenUrl",
                        "title": item['name'],
                        "url": url,
                        "style": "positive"
                    })
                elif "phone_number" in item:  # Handle data buttons by just displaying it
                    actions.append({
                        "type": "Action.Submit",
                        "title": f"{item['name']} ({item['phone_number']})",
                        "data": {}  # No actual data submission, just for display
                    })

        # Create the adaptive card
        card = {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.3",
            "body": [
                {
                    "type": "ActionSet",
                    "actions": actions if actions else [{
                        "type": "Action.Submit",
                        "title": "No URLs configured",
                        "data": {}
                    }]
                }
            ]
        }

        return card

    except Exception as e:
        logger.error(f"❌ Error creating URL card: {e}", exc_info=True)
        # Return a minimal error card
        return {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.3",
            "body": [
                {
                    "type": "TextBlock",
                    "text": "Error loading URLs",
                    "color": "Attention"
                }
            ]
        }


class URLs(Command):
    def __init__(self):
        try:
            url_card = get_url_card()
            logger.info(f"✅ URL card generated successfully with {len(url_card.get('body', []))} body elements")
        except Exception as e:
            logger.error(f"❌ Error generating URL card: {e}", exc_info=True)
            # Fallback to a simple error card
            url_card = {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.3",
                "body": [{
                    "type": "TextBlock",
                    "text": f"Error loading URLs: {str(e)}",
                    "color": "Attention"
                }]
            }

        super().__init__(
            command_keyword="urls",
            help_message="Favorite URLs 🔗",
            card=url_card,
            delete_previous_message=True
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles, log_file_name="toodles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        pass


class GetNewXTicketForm(Command):
    def __init__(self):
        super().__init__(
            card=NEW_TICKET_CARD,
            command_keyword="get_x_ticket_form",
            help_message="Create X Ticket 𝑿",
            delete_previous_message=True
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles, log_file_name="toodles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        pass


class CreateXSOARTicket(Command):
    def __init__(self):
        super().__init__(
            command_keyword="create_x_ticket",
            card=None,
            delete_previous_message=True
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles, log_file_name="toodles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        if attachment_actions.inputs['title'].strip() == "" or attachment_actions.inputs['details'].strip() == "":
            reply = "Please fill in both fields to create a new ticket."
            logger.info(f"Reply from CreateXSOARTicket is {len(reply)} characters")
            return reply

        incident = {
            'name': attachment_actions.inputs['title'].strip(),
            'details': attachment_actions.inputs[
                           'details'].strip() + f"\nSubmitted by: {activity['actor']['emailAddress']}",
            'CustomFields': {
                'detectionsource': attachment_actions.inputs['detection_source'],
                'isusercontacted': False,
                'securitycategory': 'CAT-5: Scans/Probes/Attempted Access'
            }
        }
        result = prod_incident_handler.create(incident)
        new_incident_id = result.get('id')
        incident_url = CONFIG.xsoar_prod_ui_base_url + '/Custom/caseinfoid/' + new_incident_id
        reply = f"{activity['actor']['displayName']}, Ticket [#{new_incident_id}]({incident_url}) has been created in XSOAR Prod."
        logger.info(f"Reply from CreateXSOARTicket is {len(reply)} characters")
        return reply


class IOC(Command):
    def __init__(self):
        super().__init__(
            command_keyword="ioc",
            card=IOC_HUNT,
            delete_previous_message=True
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles, log_file_name="toodles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        pass


class IOCHunt(Command):
    def __init__(self):
        super().__init__(
            command_keyword="ioc_hunt",
            card=None,
            delete_previous_message=True
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles, log_file_name="toodles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        if attachment_actions.inputs['ioc_hunt_title'].strip() == "" or attachment_actions.inputs[
            'ioc_hunt_iocs'].strip() == "":
            return "Please fill in both fields to create a new ticket."

        incident = {
            'name': attachment_actions.inputs['ioc_hunt_title'].strip(),
            'details': attachment_actions.inputs['ioc_hunt_iocs'].strip(),
            'type': "METCIRT IOC Hunt",
            'CustomFields': {
                'huntsource': 'Other'
            }
        }
        result = prod_incident_handler.create(incident)
        ticket_no = result.get('id')
        incident_url = CONFIG.xsoar_prod_ui_base_url + '/Custom/caseinfoid/' + ticket_no

        return f"{activity['actor']['displayName']}, A New IOC Hunt has been created in XSOAR. Ticket: [#{ticket_no}]({incident_url})"


class ThreatHunt(Command):
    def __init__(self):
        super().__init__(
            command_keyword="threat",
            card=THREAT_HUNT,
            delete_previous_message=True
        )

    def execute(self, message, attachment_actions, activity):
        pass


class CreateThreatHunt(Command):
    def __init__(self):
        super().__init__(
            command_keyword="threat_hunt",
            card=None,
            delete_previous_message=True
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles, log_file_name="toodles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        if attachment_actions.inputs['threat_hunt_title'].strip() == "" or attachment_actions.inputs[
            'threat_hunt_desc'].strip() == "":
            return "Please fill in both fields to create a new ticket."

        incident = {
            'name': attachment_actions.inputs['threat_hunt_title'].strip(),
            'details': attachment_actions.inputs[
                           'threat_hunt_desc'].strip() + f"\nSubmitted by: {activity['actor']['emailAddress']}",
            'type': "Threat Hunt"
        }
        result = prod_incident_handler.create(incident)
        ticket_no = result.get('id')
        ticket_title = attachment_actions.inputs['threat_hunt_title'].strip()
        incident_url = CONFIG.xsoar_prod_ui_base_url + '/Custom/caseinfoid/' + ticket_no
        person_id = attachment_actions.personId

        announce_new_threat_hunt(ticket_no, ticket_title, incident_url, person_id)
        return None


class CreateAZDOWorkItem(Command):
    def __init__(self):
        super().__init__(
            command_keyword="azdo_wit",
            help_message="Create AZDO Work Item 💼",
            card=AZDO_CARD,
            delete_previous_message=True
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles, log_file_name="toodles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):

        try:
            parent_url = None
            assignee = None
            area_path = None
            iteration = None
            inputs = attachment_actions.inputs
            wit_title = inputs['wit_title']
            wit_type = inputs['wit_type']
            submitter_display_name = activity['actor']['displayName']
            wit_description = inputs['wit_description']
            project = inputs['project']

            if project == 'platforms':
                assignee = CONFIG.resp_eng_auto_lead
                parent_url = CONFIG.azdo_platforms_parent_url
            elif project == 'rea':
                assignee = CONFIG.resp_eng_auto_lead
                area_path = azdo_area_paths['re']
                parent_url = CONFIG.azdo_rea_parent_url
                iteration = CONFIG.azdo_rea_iteration
            elif project == 'reo':
                assignee = CONFIG.resp_eng_ops_lead
                area_path = azdo_area_paths['re']

            wit_id = azdo.create_wit(
                title=wit_title,
                description=wit_description,
                item_type=wit_type,
                project=project,
                submitter=submitter_display_name,
                assignee=assignee,
                parent_url=parent_url,
                area_path=area_path,
                iteration=iteration
            )
            azdo_wit_url = f'https://dev.azure.com/{azdo_orgs.get(project)}/{quote(azdo_projects.get(project))}/_workitems/edit/{wit_id}'
            wit_type = wit_type.replace('%20', ' ')
            return_message = f'{activity['actor']['displayName']}, A new AZDO {wit_type} has been created \n [{wit_id}]({azdo_wit_url}) - {wit_title}'

            webex_api.messages.create(
                roomId=CONFIG.webex_room_id_automation_engineering,
                markdown=f"{submitter_display_name} has created a new AZDO {wit_type} \n [{wit_id}]({azdo_wit_url}) - {wit_title}"
            )

            return return_message
        except Exception as e:
            return str(e)


class Review(Command):
    def __init__(self):
        super().__init__(
            command_keyword="review",
            card=None,
            delete_previous_message=True
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles, log_file_name="toodles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        if attachment_actions.inputs["review_notes"] == "":
            return "Please add a comment to submit this ticket for review."

        curr_date = datetime.now()
        ticket_no = attachment_actions.inputs["incident_id"]

        list_dict = prod_list_handler.get_list_data_by_name("review").get('Tickets')
        add_entry_to_reviews(list_dict, ticket_no, activity['actor']['emailAddress'], curr_date.strftime("%x"),
                             attachment_actions.inputs["review_notes"])
        reformat = {"Tickets": list_dict}
        prod_list_handler.save(str(reformat), "review")

        return f"Ticket {ticket_no} has been added to Reviews."


class GetApprovedTestingCard(Command):
    def __init__(self):
        super().__init__(
            command_keyword="testing",
            help_message="Submit Approved Testing 🧪",
            card=APPROVED_TESTING_CARD,
            delete_previous_message=True
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles, log_file_name="toodles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        pass


# Helper function to convert date format from YYYY-MM-DD to MM/DD/YYYY
def reformat_date(date_str):
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").strftime("%m/%d/%Y")
    except ValueError:
        return date_str  # If there's an issue with the date format, return it as-is


def get_approved_testing_entries_table():
    approved_test_items = prod_list_handler.get_list_data_by_name(approved_testing_list_name)

    # Prepare data for tabulation
    table_data = []
    categories = ["USERNAMES", "ENDPOINTS", "IP_ADDRESSES"]
    column_headers = ["USERNAMES", "HOST NAMES", "IP ADDRESSES"]

    # Find out how many rows we need
    max_items = max(len(approved_test_items.get(category, [])) for category in categories)

    # Create data rows with formatted dates
    for i in range(max_items):
        row = []
        for category in categories:
            items = approved_test_items.get(category, [])
            if i < len(items):
                item = items[i]
                expiry_date = reformat_date(item.get('expiry_date'))
                row.append(f"{item.get('data')} ({expiry_date})")
            else:
                row.append("")
        table_data.append(row)

    # Create the table using tabulate
    table = tabulate(
        table_data,
        headers=column_headers,
        tablefmt="pipe",  # Use pipe format to match the original markdown-style table
        stralign="left"
    )
    return table


class GetCurrentApprovedTestingEntries(Command):
    def __init__(self):
        super().__init__(
            command_keyword="current_approved_testing",
            card=None
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles, log_file_name="toodles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        approved_testing_items_table = get_approved_testing_entries_table()
        # Webex message length limit: 7439 chars before encryption
        max_length = 7400
        result = (
            f"{activity['actor']['displayName']}, here are the current Approved Security Testing entries\n"
            "```\n"
            f"{approved_testing_items_table}\n"
            "```\n"
            "\n*Entries expire at 5 PM ET on the date shown"
        )
        logger.info(f"Reply from GetCurrentApprovedTestingEntries is {len(result)} characters")
        if len(result) > max_length:
            logger.warning(f"Reply from GetCurrentApprovedTestingEntries exceeded max length: {len(result)}")
            return (f"{activity['actor']['displayName']}, the current list is too long to be displayed here. "
                    "You may find the same list at http://gdnr.company.com/get-approved-testing-entries")
        return result


def announce_new_approved_testing_entry(new_item) -> None:
    payload = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.3",
        "body": [
            {
                "type": "TextBlock",
                "text": "New Approved Testing",
                "style": "heading",
                "size": "Large",
                "weight": "Bolder",
                "color": "Attention",
                "horizontalAlignment": "center"
            },
            {
                "type": "FactSet",
                "facts": [
                    {
                        "title": "Submitter",
                        "value": new_item.get('submitter')
                    },
                    {
                        "title": "Description",
                        "wrap": True,
                        "value": new_item.get('description')
                    },
                    {
                        "title": "Username(s)",
                        "wrap": True,
                        "value": new_item.get('usernames')
                    },
                    {
                        "title": "IPs/Hostnames of Tester",
                        "wrap": True,
                        "value": new_item.get('items_of_tester')
                    },
                    {
                        "title": "IPs/Hostnames to be tested",
                        "wrap": True,
                        "value": new_item.get('items_to_be_tested')
                    },
                    {
                        "title": "Scope",
                        "wrap": True,
                        "value": new_item.get('scope')
                    },
                    {
                        "title": "Keep until",
                        "value": new_item.get('expiry_date')
                    }
                ],
                "height": "stretch",
                "style": "accent"
            },
            {
                "type": "ActionSet",
                "spacing": "small",
                "actions": [
                    {
                        "type": "Action.Submit",
                        "title": "Get Current List",
                        "data": {
                            "callback_keyword": "current_approved_testing"
                        }
                    }
                ],
                "horizontalAlignment": "right"
            }
        ]
    }
    webex_api.messages.create(
        roomId=CONFIG.webex_room_id_gosc_t2,
        text="New Approved Testing!",
        attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": payload}]
    )


def is_valid_ip(address: str) -> bool:
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


class AddApprovedTestingEntry(Command):
    def __init__(self):
        super().__init__(
            command_keyword="add_approved_testing",
            card=None,
            delete_previous_message=True
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles, log_file_name="toodles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        usernames = attachment_actions.inputs['usernames'].strip()
        items_of_tester = attachment_actions.inputs['ip_addresses_and_host_names_of_tester'].strip()
        items_to_be_tested = attachment_actions.inputs['ip_addresses_and_host_names_to_be_tested'].strip()
        description = attachment_actions.inputs['description'].strip()
        scope = attachment_actions.inputs['scope'].strip()
        submitter = activity['actor']['emailAddress']
        expiry_date = attachment_actions.inputs['expiry_date']
        if attachment_actions.inputs['callback_keyword'] == 'add_approved_testing' and expiry_date == "":
            expiry_date = (datetime.now(EASTERN_TZ) + timedelta(days=1)).strftime("%Y-%m-%d")
        submit_date = datetime.now().strftime("%m/%d/%Y")
        try:
            add_approved_testing_entry(
                prod_list_handler,
                approved_testing_list_name,
                approved_testing_master_list_name,
                usernames,
                items_of_tester,
                items_to_be_tested,
                description,
                scope,
                submitter,
                expiry_date,
                submit_date
            )
        except ValueError as e:
            return str(e)
        approved_testing_items_table = get_approved_testing_entries_table()
        return (
            f"{activity['actor']['displayName']}, your entry has been added to the Approved Testing list. Here's the current list\n"
            "```\n"
            f"{approved_testing_items_table}\n"
            "```\n"
            "\n*Entries expire at 5 PM ET on the date shown"
        )


class RemoveApprovedTestingEntry(Command):
    def __init__(self):
        super().__init__(
            command_keyword="remove_approved_testing",
            card=None,
            delete_previous_message=True
        )

    def execute(self, message, attachment_actions, activity):
        pass


def add_entry_to_reviews(dict_full, ticket_id, person, date, message):
    """
    adds the ticket to the list for further review
    """
    dict_full.append({"ticket_id": ticket_id, "by": person, "date": date, "message": message})


def announce_new_threat_hunt(ticket_no, ticket_title, incident_url, person_id):
    webex_data = prod_list_handler.get_list_data_by_name('METCIRT Webex')
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f"Bearer {CONFIG.webex_bot_access_token_toodles}"
    }
    payload_json = {
        'roomId': webex_data.get("channels").get("threat_hunt"),
        'markdown': f"<@personId:{person_id}> created a new Threat Hunt in XSOAR. Ticket: [#{ticket_no}]({incident_url}) - {ticket_title}"
    }
    requests.post(webex_data.get('api_url'), headers=headers, json=payload_json)


class Who(Command):
    """Return who the on-call person is"""

    def __init__(self):
        super().__init__(
            command_keyword="who",
            help_message="On-Call ☎️",
            card=None,
            delete_previous_message=False  # Keep the welcome card visible
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles, log_file_name="toodles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        on_call_person = oncall.get_on_call_person()
        return f"{activity['actor']['displayName']}, the DnR On-call person is {on_call_person.get('name')} - {on_call_person.get('email_address')} - {on_call_person.get('phone_number')}"


class Rotation(Command):
    """Return who the on-call person is"""

    def __init__(self):
        super().__init__(
            command_keyword="rotation",
            card=None,
            delete_previous_message=False  # Keep the welcome card visible
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles, log_file_name="toodles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        rotation = oncall.get_rotation()

        data_frame = pandas.DataFrame(rotation, columns=["Monday_date", "analyst_name"])
        data_frame.columns = ['Monday', 'Analyst']

        return data_frame.to_string(index=False)


class ContainmentStatusCS(Command):
    """Return the containment status of a host"""

    def __init__(self):
        super().__init__(
            command_keyword="status",
            card=None,
            delete_previous_message=True
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles, log_file_name="toodles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):

        if message.strip() != "":
            host_name_cs = message.strip()
        else:
            host_name_cs = attachment_actions.inputs['host_name_cs'].strip()

        host_name_cs = host_name_cs.replace("METCIRT_Toodles status", "").strip()
        if host_name_cs is None or host_name_cs == "":
            return "Please enter a host name and try again"

        try:
            crowdstrike = CrowdStrikeClient()
            return f'{activity['actor']['displayName']}, The network containment status of {host_name_cs} in CS is **{crowdstrike.get_device_containment_status(host_name_cs)}**'
        except Exception as e:
            return f'There seems to be an issue with finding the host you entered. Please make sure the host is valid. Error: {str(e)}'


class GetAllOptions(Command):
    def __init__(self):
        super().__init__(
            command_keyword="options",
            help_message="More Commands",
            card=all_options_card,
            delete_previous_message=False  # Keep the welcome card visible
        )

    def execute(self, message, attachment_actions, activity):
        pass


class ImportTicket(Command):
    def __init__(self):
        super().__init__(
            command_keyword="import",
            card=TICKET_IMPORT_CARD.to_dict(),
            delete_previous_message=True
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles, log_file_name="toodles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        prod_ticket_number = attachment_actions.inputs['prod_ticket_number']
        requestor_email_address = activity['actor']['emailAddress']
        destination_ticket_number, destination_ticket_link = xsoar.import_ticket(prod_ticket_number, requestor_email_address)
        return f'{activity['actor']['displayName']}, the Prod ticket X#{prod_ticket_number} has been copied to Dev [X#{destination_ticket_number}]({destination_ticket_link})'


class CreateTuningRequest(Command):
    def __init__(self):
        super().__init__(
            help_message="Create Tuning Request 🎶",
            command_keyword="tuning_request",
            card=TUNING_REQUEST_CARD.to_dict(),
            delete_previous_message=True
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles, log_file_name="toodles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        title = attachment_actions.inputs['title']
        description = attachment_actions.inputs['description']
        tickets = attachment_actions.inputs['tickets']
        ticket_volume = attachment_actions.inputs['ticket_volume']
        description += f'<br><br>Sample tickets: {tickets}<br>Approx. ticket volume: {ticket_volume}'
        submitter_display_name = activity['actor']['displayName']
        project = 'de'
        area_path = azdo_area_paths['tuning_request']

        tuning_request_id = azdo.create_wit(title=title, description=description, item_type='User Story',
                                            project=project, area_path=area_path, submitter=submitter_display_name)
        tuning_request_url = f'https://dev.azure.com/{azdo_orgs.get(project)}/{quote(azdo_projects.get(project))}/_workitems/edit/{tuning_request_id}'
        return f"{activity['actor']['displayName']}, Your tuning request has been submitted! \n [{tuning_request_id}]({tuning_request_url}) - {title}"


SEARCH_X_CARD = AdaptiveCard(
    body=[
        TextBlock(
            text="Search X",
            wrap=True,
            horizontalAlignment=HorizontalAlignment.CENTER,
            weight=FontWeight.BOLDER,
            color=Colors.ACCENT,
        ),
        INPUTS.Text(
            id="username",
            label="Username",
            placeholder="Enter username"
        ),
        INPUTS.Text(
            id="email",
            label="Email Address",
            placeholder="Enter email address"
        ),
        INPUTS.Text(
            id="hostname",
            label="Hostname",
            placeholder="Enter hostname"
        ),
        ActionSet(
            actions=[
                Submit(
                    title=f"Get {CONFIG.team_name} Tickets",
                    style=ActionStyle.POSITIVE,
                    data={"callback_keyword": "fetch_xsoar_tickets"}
                )
            ],
        )
    ]
)


class GetSearchXSOARCard(Command):
    def __init__(self):
        super().__init__(
            help_message="Search 𝗫",
            command_keyword="get_search_xsoar_card",
            card=SEARCH_X_CARD.to_dict(),
            delete_previous_message=True
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles, log_file_name="toodles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        pass


class FetchXSOARTickets(Command):
    def __init__(self):
        super().__init__(
            command_keyword="fetch_xsoar_tickets",
            card=None
        )

    def execute(self, message, attachment_actions, activity):
        username = attachment_actions.inputs['username']
        email = attachment_actions.inputs['email']
        hostname = attachment_actions.inputs['hostname']

        query = f'type:{CONFIG.team_name}'
        query += f" username:{username}" if username else ''
        query += f" email:{email}" if email else ''
        query += f" hostname:{hostname}" if hostname else ''

        prod_ticket_handler = TicketHandler(XsoarEnvironment.PROD)
        tickets = prod_ticket_handler.get_tickets(query=query)
        if tickets:
            for ticket in tickets:
                message = f"[X#{ticket.get('id')}]({CONFIG.xsoar_prod_ui_base_url}/Custom/caseinfoid/{ticket.get('id')}) - {ticket.get('name')}\n"
        else:
            message = 'None Found'
        return message


class GetCompanyHolidays(Command):
    def __init__(self):
        super().__init__(
            command_keyword="holidays",
            card=None,
            delete_previous_message=True
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles, log_file_name="toodles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        today = datetime.now()
        holidays = []
        next_holiday_idx = None
        next_holiday_date = None
        today_holiday_idx = None
        emoji_map = {
            "New Year's Day": "🥳",
            "Martin Luther King, Jr. Day": "🕊️",
            "Memorial Day": "🇺🇸",
            "Independence Day": "🎆",
            "Labor Day": "💼",
            "Thanksgiving Day": "🦃",
            "Day After Thanksgiving": "🍂",
            "Christmas Day": "🎄"
        }

        with open("../data/transient/company_holidays.txt", "r") as f:
            for idx, line in enumerate(f.readlines()):
                # Extract date from line
                match = re.search(r", ([A-Za-z]+) (\d+)", line)
                if match:
                    month_str, day_str = match.groups()
                    try:
                        holiday_date = datetime.strptime(f"2025 {month_str} {day_str}", "%Y %B %d")

                        # Check if this is today's holiday
                        if holiday_date.date() == today.date():
                            today_holiday_idx = idx
                        # Find next future holiday (after today)
                        elif holiday_date > today and next_holiday_idx is None:
                            next_holiday_idx = idx
                            next_holiday_date = holiday_date

                        # Determine styling
                        if holiday_date.date() < today.date():
                            style = 'italic'
                        else:
                            style = None
                    except Exception:
                        style = None
                else:
                    style = None

                # Add emoji if available
                holiday_name = line.split(' - ')[0]
                emoji = emoji_map.get(holiday_name, "")
                holiday_line = f"{emoji} {line.rstrip()}" if emoji else line.rstrip()
                holidays.append((holiday_line, style))

        # Add seasonal greeting based on current date
        month = today.month
        if month in [12, 1, 2]:
            seasonal_greeting = "❄️ Winter holidays ahead!"
        elif month in [3, 4, 5]:
            seasonal_greeting = "🌸 Spring celebrations coming up!"
        elif month in [6, 7, 8]:
            seasonal_greeting = "☀️ Summer holidays to enjoy!"
        else:  # 9, 10, 11
            seasonal_greeting = "🍂 Fall festivities approaching!"

        # Enhanced title with seasonal greeting
        title = f"🎉 **2025 Company Holidays** 🎉\n{seasonal_greeting}\n═══════════════════════════════════\n"

        # Build output with styles and merged countdown
        output_lines = []
        for i, (h, style) in enumerate(holidays):
            # Handle today's holiday with special formatting
            if i == today_holiday_idx:
                h = f"🎊 **{h}** 🎊 (TODAY!)"
                style = None  # Don't italicize today's holiday
            # Handle next holiday
            elif i == next_holiday_idx:
                if next_holiday_date:
                    days_until = (next_holiday_date - today).days
                    if days_until == 1:
                        h = f"⏰ **{h}** (TOMORROW!)"
                    else:
                        h = f"**{h}** ({days_until} days until⏱️)"
                else:
                    h = f"**{h}**"

            # Apply italic styling for past holidays
            if style == 'italic':
                h = f"*{h}*"

            output_lines.append(h)

        # Enhanced footer with visual separator
        note = f"\n═══════════════════════════════════\n"
        return title + "\n".join(output_lines) + note


class GetBotHealth(Command):
    """Command to check bot health and status."""

    def __init__(self):
        super().__init__(
            command_keyword="health",
            delete_previous_message=True,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles, log_file_name="toodles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId
        current_time = datetime.now(EASTERN_TZ)

        # Determine current mode
        if CONFIG.should_use_proxy_resilience:
            mode = "Full Resilience"
            health_detail = "ZScaler features + Auto-reconnect"
            features = "SSL config, WebSocket patching, device cleanup, auto-restart"
        elif CONFIG.should_auto_reconnect:
            mode = "Lite Resilience"
            health_detail = "Auto-reconnect + Device cleanup"
            features = "Device cleanup, auto-reconnect on WebSocket timeout"
        else:
            mode = "Standard"
            health_detail = "No resilience features"
            features = "Standard WebexBot"

        health_status = "🟢 Healthy"

        # Format current time with timezone
        tz_name = "EST" if current_time.dst().total_seconds() == 0 else "EDT"

        # Create status card with enhanced details
        status_card = AdaptiveCard(
            body=[
                TextBlock(
                    text="🤖 Toodles Bot Status",
                    color=options.Colors.GOOD,
                    size=options.FontSize.LARGE,
                    weight=options.FontWeight.BOLDER,
                    horizontalAlignment=HorizontalAlignment.CENTER
                ),
                ColumnSet(
                    columns=[
                        Column(
                            width="stretch",
                            items=[
                                TextBlock(text="📊 **Status Information**", weight=options.FontWeight.BOLDER),
                                TextBlock(text=f"Status: {health_status}"),
                                TextBlock(text=f"Mode: {mode}"),
                                TextBlock(text=f"Details: {health_detail}"),
                                TextBlock(text=f"Features: {features}"),
                                TextBlock(text=f"Current Time: {current_time.strftime(f'%Y-%m-%d %H:%M:%S {tz_name}')}")
                            ]
                        )
                    ]
                )
            ]
        )

        webex_api.messages.create(
            roomId=room_id,
            text="Bot Status Information",
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": status_card.to_dict()}]
        )


class Hi(Command):
    """Simple Hi command to check if bot is alive."""

    def __init__(self):
        super().__init__(
            command_keyword="hi",
            delete_previous_message=False,
            exact_command_keyword_match=False,
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles, log_file_name="toodles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        return "Hi 👋🏾"


class GetUrlBlockVerdictForm(Command):
    """Test URL filtering across ZScaler and Bloxone."""

    def __init__(self):
        super().__init__(
            command_keyword="get_url_block_verdict_form",
            help_message="URL Block Verdict ⚖️",
            card=URL_BLOCK_VERDICT_CARD,
            delete_previous_message=False
        )

    def execute(self, message, attachment_actions, activity):
        pass


class ProcessUrlBlockVerdict(Command):
    """Process URL filtering submission from the card."""

    def __init__(self):
        super().__init__(
            command_keyword="url_verdict",
            card=None,
            delete_previous_message=True
        )

    @log_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles, log_file_name="toodles_activity_log.csv")
    def execute(self, message, attachment_actions, activity):
        import time
        start_time = time.time()

        # Handle both card submission and direct text command
        if hasattr(attachment_actions, 'inputs') and 'urls_to_check' in attachment_actions.inputs:
            # This is a card submission
            urls_text = attachment_actions.inputs['urls_to_check'].strip()
        else:
            # This is a direct text command - extract URLs from message
            urls_text = message.replace("url_verdict", "").strip()

        if not urls_text:
            return f"{activity['actor']['displayName']}, please provide URLs to test. Example: @toodles url_verdict facebook.com, google.com"

        try:
            # Create tester and parse/normalize URLs using backend logic
            url_checker = URLChecker()
            urls = url_checker.parse_and_normalize_urls(urls_text)

            if not urls:
                return f"{activity['actor']['displayName']}, please provide valid URLs to test."

            # Test URLs and collect results
            result = url_checker.get_block_verdict(urls, normalize=False)  # Already normalized
            results = result['details']

            # Build table data for tabulate
            table_rows = []
            for result in results:
                url = result['url']
                zs = result['zscaler']
                bo = result['bloxone']

                # Status indicators
                zs_status = '✅' if zs.get('allowed') else '❌'

                if 'skipped' in bo:
                    bo_status = 'SKIPPED'
                else:
                    bo_status = '✅' if bo.get('allowed') else '❌'

                # Truncate URL if too long for cleaner display
                display_url = url if len(url) <= 50 else url[:47] + '...'

                table_rows.append([display_url, zs_status, bo_status])

            # Create table using tabulate
            headers = ['URL', 'ZScaler', 'Bloxone']
            table_str = tabulate(table_rows, headers=headers, tablefmt='simple', colalign=['left', 'center', 'center'])

            # Calculate response time
            response_time = round(time.time() - start_time)

            # Build final response with Markdown formatting
            response = (f"**{activity['actor']['displayName']}, URL block verdict results:**\n"
                        f"```\n{table_str}\n\nLegend: ✅=ALLOWED ❌=BLOCKED\n"
                        f"Response Time: {response_time}s\n```")

            # Check length and fallback to summary if needed
            if len(response) > 7000:  # Conservative limit for Webex
                total = len(results)
                zs_blocked = sum(1 for r in results if not r['zscaler'].get('allowed'))
                bo_blocked = sum(1 for r in results if not r['bloxone'].get('allowed', True) and 'skipped' not in r['bloxone'])

                response = (f"{activity['actor']['displayName']}, tested {total} URLs.\n"
                            f"ZScaler blocked: {zs_blocked}/{total}\n"
                            f"Bloxone blocked: {bo_blocked}/{total}\n"
                            f"Results too long for chat - reduce the number of URLs in the input.\n"
                            f"Responded in {response_time}s")

            return response

        except Exception as e:
            logger.error(f"URL testing error: {str(e)}")
            return f"{activity['actor']['displayName']}, error testing URLs: {str(e)}"


def toodles_bot_factory():
    """Create Toodles bot instance"""
    # Clean up stale device registrations before starting
    # (to prevent device buildup from automatic restarts)
    cleanup_devices_on_startup(
        CONFIG.webex_bot_access_token_toodles,
        bot_name="Toodles"
    )

    return WebexBot(
        CONFIG.webex_bot_access_token_toodles,
        bot_name="Toodles Bot",
        approved_domains=[CONFIG.my_web_domain],
        # approved_rooms disabled - bot lacks spark:memberships_read scope for validation
        # Security: Only add this bot to authorized rooms to control access
        log_level="ERROR",
        threads=True,
        bot_help_subtitle="Your friendly toolbox bot!"
    )


def toodles_initialization(bot_instance=None):
    """Initialize Toodles commands"""
    if bot_instance:
        # Add all commands
        bot_instance.add_command(GetApprovedTestingCard())
        bot_instance.add_command(GetCurrentApprovedTestingEntries())
        bot_instance.add_command(AddApprovedTestingEntry())
        bot_instance.add_command(RemoveApprovedTestingEntry())
        bot_instance.add_command(Who())
        bot_instance.add_command(Rotation())
        bot_instance.add_command(ContainmentStatusCS())
        # bot_instance.add_command(Review())
        bot_instance.add_command(GetNewXTicketForm())
        bot_instance.add_command(CreateXSOARTicket())
        bot_instance.add_command(IOC())
        bot_instance.add_command(IOCHunt())
        bot_instance.add_command(URLs())
        bot_instance.add_command(ThreatHunt())
        bot_instance.add_command(CreateThreatHunt())
        bot_instance.add_command(CreateAZDOWorkItem())
        bot_instance.add_command(GetAllOptions())
        bot_instance.add_command(ImportTicket())
        bot_instance.add_command(CreateTuningRequest())
        bot_instance.add_command(GetSearchXSOARCard())
        bot_instance.add_command(FetchXSOARTickets())
        bot_instance.add_command(GetCompanyHolidays())
        bot_instance.add_command(GetBotHealth())
        bot_instance.add_command(Hi())
        bot_instance.add_command(GetUrlBlockVerdictForm())
        bot_instance.add_command(ProcessUrlBlockVerdict())
        return True
    return False


def main():
    """Toodles main - always uses resilience framework"""
    from src.utils.bot_resilience import ResilientBot

    logger.info("Starting Toodles with standard resilience framework")

    resilient_runner = ResilientBot(
        bot_name="Toodles",
        bot_factory=toodles_bot_factory,
        initialization_func=toodles_initialization,
        max_retries=5,
        initial_retry_delay=30,
        max_retry_delay=300,
        keepalive_interval=75,  # Staggered to avoid synchronized API load (60s, 75s, 90s, 105s, 120s)
    )
    resilient_runner.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
