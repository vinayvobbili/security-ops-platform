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
    log_level=logging.INFO,
    log_dir=str(ROOT_DIRECTORY / "logs"),
    info_modules=['__main__', 'src.utils.bot_resilience', 'src.utils.webex_device_manager', 'src.utils.connection_health'],
    rotate_on_startup=False  # Keep logs continuous, rely on RotatingFileHandler for size-based rotation
)

logger = logging.getLogger(__name__)
# Suppress noisy messages from webex libraries
logging.getLogger('webex_bot').setLevel(logging.ERROR)  # Suppress bot-to-bot and self-message warnings
logging.getLogger('webexteamssdk').setLevel(logging.ERROR)
logging.getLogger('webex_websocket_client').setLevel(logging.WARNING)

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

# Import datetime before using it
from datetime import datetime, timedelta
import ipaddress
import signal
import atexit
import json

# Log clear startup marker for visual separation in logs
logger.warning("=" * 100)
logger.warning(f"🚀 TOODLES BOT STARTED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
logger.warning("=" * 100)
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
from src.components import birthdays_anniversaries
from data.data_maps import azdo_projects, azdo_orgs, azdo_area_paths

from services import xsoar, azdo
from services.approved_testing_utils import add_approved_testing_entry
from services.crowdstrike import CrowdStrikeClient
from services.xsoar import ListHandler, TicketHandler, XsoarEnvironment

# Import cards from extracted package
from webex_bots.cards import (
    NEW_TICKET_CARD, IOC_HUNT, THREAT_HUNT, AZDO_CARD,
    APPROVED_TESTING_CARD, TICKET_IMPORT_CARD, TUNING_REQUEST_CARD,
    URL_BLOCK_VERDICT_CARD, DOMAIN_LOOKALIKE_CARD, BIRTHDAY_ANNIVERSARY_CARD,
    all_options_card
)
from src.components.url_lookup_traffic import URLChecker
from src.utils.http_utils import get_session
from src.utils.toodles_decorators import toodles_log_activity
from src.utils.webex_validation import validate_required_inputs, get_input_value
from src.utils.xsoar_helpers import build_incident_url, create_incident_with_response
from src.utils.webex_responses import format_user_response, get_user_email, get_user_display_name
from src.utils.webex_device_manager import cleanup_devices_on_startup
from webex_bots.base import ToodlesCommand, CardOnlyCommand
from src.components.domain_lookalike_scanner import DomainLookalikeScanner

# Get robust HTTP session instance
http_session = get_session()

# Import connection pool configuration utility
from src.utils.webex_pool_config import configure_webex_api_session

# Increase timeout from default 60s to 180s for unreliable networks
# Configure with larger connection pool to prevent timeout issues
webex_api = configure_webex_api_session(
    WebexAPI(
        access_token=CONFIG.webex_bot_access_token_toodles,
        single_request_timeout=180
    ),
    pool_connections=50,  # Increased from default 10
    pool_maxsize=50,  # Increased from default 10
    max_retries=3  # Enable automatic retry on transient failures
)

# Component instances
domain_scanner = DomainLookalikeScanner(webex_api)

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



def get_url_card():
    """
    Get URL card with {CONFIG.team_name} URLs from XSOAR.
    Returns a card with error message if XSOAR is not configured or list is unavailable.
    """
    try:
        team_urls = prod_list_handler.get_list_data_by_name(f'{CONFIG.team_name} URLs')
        actions = []

        # Handle case where list is not found or XSOAR is not configured
        if team_urls is None:
            logger.warning(f"⚠️ {CONFIG.team_name} URLs list not available from XSOAR")
            actions = [{
                "type": "Action.Submit",
                "title": "URLs unavailable (XSOAR not configured)",
                "data": {}
            }]
        else:
            # Iterate through the list of URLs and create button actions
            for item in team_urls:
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


class URLs(CardOnlyCommand):
    """Display favorite URLs dynamically loaded from XSOAR."""
    command_keyword = "urls"
    help_message = "Favorite URLs 🔗"
    card = None  # Will be set dynamically in __init__

    def __init__(self):
        # Generate card dynamically before calling parent __init__
        try:
            self.card = get_url_card()
            logger.info(f"✅ URL card generated successfully with {len(self.card.get('body', []))} body elements")
        except Exception as e:
            logger.error(f"❌ Error generating URL card: {e}", exc_info=True)
            # Fallback to a simple error card
            self.card = {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.3",
                "body": [{
                    "type": "TextBlock",
                    "text": f"Error loading URLs: {str(e)}",
                    "color": "Attention"
                }]
            }
        super().__init__()


class GetNewXTicketForm(CardOnlyCommand):
    """Display the X ticket creation form."""
    command_keyword = "get_x_ticket_form"
    help_message = "Create X Ticket 𝑿"
    card = NEW_TICKET_CARD


class CreateXSOARTicket(ToodlesCommand):
    """Create a new XSOAR ticket from form submission."""
    command_keyword = "create_x_ticket"
    card = None

    @toodles_log_activity
    def execute(self, message, attachment_actions, activity):
        valid, error = validate_required_inputs(
            attachment_actions,
            ['title', 'details'],
            "Please fill in both fields to create a new ticket."
        )
        if not valid:
            logger.info(f"Reply from CreateXSOARTicket is {len(error)} characters")
            return error

        incident = {
            'name': get_input_value(attachment_actions, 'title'),
            'details': get_input_value(attachment_actions, 'details'),
            'CustomFields': {
                'detectionsource': attachment_actions.inputs['detection_source'],
                'isusercontacted': False,
                'securitycategory': 'CAT-5: Scans/Probes/Attempted Access'
            }
        }

        reply = create_incident_with_response(
            prod_incident_handler,
            incident,
            activity,
            "{actor}, Ticket [#{ticket_no}]({ticket_url}) has been created in XSOAR Prod."
        )
        logger.info(f"Reply from CreateXSOARTicket is {len(reply)} characters")
        return reply


class IOC(CardOnlyCommand):
    """Display the IOC hunt form."""
    command_keyword = "ioc"
    card = IOC_HUNT


class IOCHunt(ToodlesCommand):
    """Create a new IOC Hunt in XSOAR."""
    command_keyword = "ioc_hunt"
    card = None

    @toodles_log_activity
    def execute(self, message, attachment_actions, activity):
        valid, error = validate_required_inputs(
            attachment_actions,
            ['ioc_hunt_title', 'ioc_hunt_iocs'],
            "Please fill in both fields to create a new ticket."
        )
        if not valid:
            return error

        incident = {
            'name': get_input_value(attachment_actions, 'ioc_hunt_title'),
            'details': get_input_value(attachment_actions, 'ioc_hunt_iocs'),
            'type': f'{CONFIG.team_name} IOC Hunt',
            'CustomFields': {
                'huntsource': 'Other'
            }
        }

        return create_incident_with_response(
            prod_incident_handler,
            incident,
            activity,
            "{actor}, A New IOC Hunt has been created in XSOAR. Ticket: [#{ticket_no}]({ticket_url})",
            append_submitter=False
        )


class ThreatHunt(CardOnlyCommand):
    """Display the threat hunt form."""
    command_keyword = "threat"
    card = THREAT_HUNT


class CreateThreatHunt(ToodlesCommand):
    """Create a new Threat Hunt in XSOAR and announce it."""
    command_keyword = "threat_hunt"
    card = None

    @toodles_log_activity
    def execute(self, message, attachment_actions, activity):
        valid, error = validate_required_inputs(
            attachment_actions,
            ['threat_hunt_title', 'threat_hunt_desc'],
            "Please fill in both fields to create a new ticket."
        )
        if not valid:
            return error

        ticket_title = get_input_value(attachment_actions, 'threat_hunt_title')
        incident = {
            'name': ticket_title,
            'details': get_input_value(attachment_actions, 'threat_hunt_desc') + f"\nSubmitted by: {get_user_email(activity)}",
            'type': "Threat Hunt"
        }
        result = prod_incident_handler.create(incident)
        ticket_no = result.get('id')
        incident_url = build_incident_url(ticket_no)
        person_id = attachment_actions.personId

        announce_new_threat_hunt(ticket_no, ticket_title, incident_url, person_id)
        return None


class CreateAZDOWorkItem(ToodlesCommand):
    """Create an Azure DevOps work item."""
    command_keyword = "azdo_wit"
    help_message = "Create AZDO Work Item 💼"
    card = AZDO_CARD

    @toodles_log_activity
    def execute(self, message, attachment_actions, activity):
        try:
            parent_url = None
            assignee = None
            area_path = None
            iteration = None
            inputs = attachment_actions.inputs
            wit_title = inputs['wit_title']
            wit_type = inputs['wit_type']
            submitter_display_name = get_user_display_name(activity)
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

            webex_api.messages.create(
                roomId=CONFIG.webex_room_id_automation_engineering,
                markdown=f"{submitter_display_name} has created a new AZDO {wit_type} \n [{wit_id}]({azdo_wit_url}) - {wit_title}"
            )

            return format_user_response(activity, f"A new AZDO {wit_type} has been created \n [{wit_id}]({azdo_wit_url}) - {wit_title}")
        except Exception as e:
            return str(e)


class Review(ToodlesCommand):
    """Submit a ticket for review."""
    command_keyword = "review"
    card = None

    @toodles_log_activity
    def execute(self, message, attachment_actions, activity):
        valid, error = validate_required_inputs(
            attachment_actions,
            ['review_notes'],
            "Please add a comment to submit this ticket for review."
        )
        if not valid:
            return error

        curr_date = datetime.now()
        ticket_no = attachment_actions.inputs["incident_id"]

        list_dict = prod_list_handler.get_list_data_by_name("review").get('Tickets')
        add_entry_to_reviews(list_dict, ticket_no, get_user_email(activity), curr_date.strftime("%x"),
                             attachment_actions.inputs["review_notes"])
        reformat = {"Tickets": list_dict}
        prod_list_handler.save(str(reformat), "review")

        return f"Ticket {ticket_no} has been added to Reviews."


class GetApprovedTestingCard(CardOnlyCommand):
    """Display the approved testing submission form."""
    command_keyword = "testing"
    help_message = "Submit Approved Testing 🧪"
    card = APPROVED_TESTING_CARD


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


class GetCurrentApprovedTestingEntries(ToodlesCommand):
    """Display current approved testing entries."""
    command_keyword = "current_approved_testing"
    card = None
    delete_previous_message = False

    @toodles_log_activity
    def execute(self, message, attachment_actions, activity):
        approved_testing_items_table = get_approved_testing_entries_table()
        # Webex message length limit: 7439 chars before encryption
        max_length = 7400
        result = format_user_response(
            activity,
            f"here are the current Approved Security Testing entries\n"
            "```\n"
            f"{approved_testing_items_table}\n"
            "```\n"
            "\n*Entries expire at 5 PM ET on the date shown"
        )
        logger.info(f"Reply from GetCurrentApprovedTestingEntries is {len(result)} characters")
        if len(result) > max_length:
            logger.warning(f"Reply from GetCurrentApprovedTestingEntries exceeded max length: {len(result)}")
            return format_user_response(
                activity,
                "the current list is too long to be displayed here. "
                "You may find the same list at http://ir.company.com/get-approved-testing-entries"
            )
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


class AddApprovedTestingEntry(ToodlesCommand):
    """Add a new approved testing entry."""
    command_keyword = "add_approved_testing"
    card = None

    @toodles_log_activity
    def execute(self, message, attachment_actions, activity):
        usernames = get_input_value(attachment_actions, 'usernames')
        items_of_tester = get_input_value(attachment_actions, 'ip_addresses_and_host_names_of_tester')
        items_to_be_tested = get_input_value(attachment_actions, 'ip_addresses_and_host_names_to_be_tested')
        description = get_input_value(attachment_actions, 'description')
        scope = get_input_value(attachment_actions, 'scope')
        submitter = get_user_email(activity)
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
        return format_user_response(
            activity,
            f"your entry has been added to the Approved Testing list. Here's the current list\n"
            "```\n"
            f"{approved_testing_items_table}\n"
            "```\n"
            "\n*Entries expire at 5 PM ET on the date shown"
        )


class RemoveApprovedTestingEntry(CardOnlyCommand):
    """Placeholder for removing approved testing entries."""
    command_keyword = "remove_approved_testing"
    card = None


def add_entry_to_reviews(dict_full, ticket_id, person, date, message):
    """
    adds the ticket to the list for further review
    """
    dict_full.append({"ticket_id": ticket_id, "by": person, "date": date, "message": message})


def announce_new_threat_hunt(ticket_no, ticket_title, incident_url, person_id):
    webex_data = prod_list_handler.get_list_data_by_name(f'{CONFIG.team_name} Webex')
    request_headers = {
        'Content-Type': 'application/json',
        'Authorization': f"Bearer {CONFIG.webex_bot_access_token_toodles}"
    }
    payload_json = {
        'roomId': webex_data.get("channels").get("threat_hunt"),
        'markdown': f"<@personId:{person_id}> created a new Threat Hunt in XSOAR. Ticket: [#{ticket_no}]({incident_url}) - {ticket_title}"
    }
    requests.post(webex_data.get('api_url'), headers=request_headers, json=payload_json)


class Who(ToodlesCommand):
    """Return who the on-call person is."""
    command_keyword = "who"
    help_message = "On-Call ☎️"
    card = None
    delete_previous_message = False  # Keep the welcome card visible
    exact_command_keyword_match = False  # Allow "@bot who" syntax in group chats

    @toodles_log_activity
    def execute(self, message, attachment_actions, activity):
        on_call_person = oncall.get_on_call_person()
        return format_user_response(
            activity,
            f"the DnR On-call person is {on_call_person.get('name')} - {on_call_person.get('email_address')} - {on_call_person.get('phone_number')}"
        )


class Rotation(ToodlesCommand):
    """Display the on-call rotation schedule."""
    command_keyword = "rotation"
    card = None
    delete_previous_message = False  # Keep the welcome card visible
    exact_command_keyword_match = False  # Allow "@bot rotation" syntax in group chats

    @toodles_log_activity
    def execute(self, message, attachment_actions, activity):
        rotation = oncall.get_rotation()
        data_frame = pandas.DataFrame(rotation, columns=["Monday_date", "analyst_name"])
        data_frame.columns = ['Monday', 'Analyst']
        return data_frame.to_string(index=False)


class ContainmentStatusCS(ToodlesCommand):
    """Return the containment status of a host in CrowdStrike."""
    command_keyword = "status"
    card = None
    exact_command_keyword_match = False  # Allow "status hostname" syntax

    @toodles_log_activity
    def execute(self, message, attachment_actions, activity):
        if message.strip() != "":
            host_name_cs = message.strip()
        elif attachment_actions and hasattr(attachment_actions, 'inputs'):
            host_name_cs = get_input_value(attachment_actions, 'host_name_cs')
        else:
            host_name_cs = ""

        host_name_cs = host_name_cs.replace(f"{CONFIG.team_name}_Toodles status", "").strip()
        if not host_name_cs:
            return "Please enter a host name and try again"

        try:
            crowdstrike = CrowdStrikeClient()
            return format_user_response(
                activity,
                f"The network containment status of {host_name_cs} in CS is **{crowdstrike.get_device_containment_status(host_name_cs)}**"
            )
        except Exception as e:
            return f'There seems to be an issue with finding the host you entered. Please make sure the host is valid. Error: {str(e)}'


class GetAllOptions(CardOnlyCommand):
    """Display the all options navigation card."""
    command_keyword = "options"
    help_message = "More Commands"
    card = all_options_card
    delete_previous_message = False  # Keep the welcome card visible


class ImportTicket(ToodlesCommand):
    """Import a ticket from production to dev."""
    command_keyword = "import"
    card = TICKET_IMPORT_CARD.to_dict()

    @toodles_log_activity
    def execute(self, message, attachment_actions, activity):
        prod_ticket_number = attachment_actions.inputs['prod_ticket_number']
        requestor_email_address = get_user_email(activity)
        destination_ticket_number, destination_ticket_link = xsoar.import_ticket(prod_ticket_number, requestor_email_address)
        return format_user_response(
            activity,
            f"the Prod ticket X#{prod_ticket_number} has been copied to Dev [X#{destination_ticket_number}]({destination_ticket_link})"
        )


class CreateTuningRequest(ToodlesCommand):
    """Create a tuning request in Azure DevOps."""
    command_keyword = "tuning_request"
    help_message = "Create Tuning Request 🎶"
    card = TUNING_REQUEST_CARD.to_dict()

    @toodles_log_activity
    def execute(self, message, attachment_actions, activity):
        title = attachment_actions.inputs['title']
        description = attachment_actions.inputs['description']
        tickets = attachment_actions.inputs['tickets']
        ticket_volume = attachment_actions.inputs['ticket_volume']
        description += f'<br><br>Sample tickets: {tickets}<br>Approx. ticket volume: {ticket_volume}'
        submitter_display_name = get_user_display_name(activity)
        project = 'de'
        area_path = azdo_area_paths['tuning_request']

        tuning_request_id = azdo.create_wit(title=title, description=description, item_type='User Story',
                                            project=project, area_path=area_path, submitter=submitter_display_name)
        tuning_request_url = f'https://dev.azure.com/{azdo_orgs.get(project)}/{quote(azdo_projects.get(project))}/_workitems/edit/{tuning_request_id}'
        return format_user_response(activity, f"Your tuning request has been submitted! \n [{tuning_request_id}]({tuning_request_url}) - {title}")


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


class GetSearchXSOARCard(CardOnlyCommand):
    """Display the XSOAR search form."""
    command_keyword = "get_search_xsoar_card"
    help_message = "Search 𝗫"
    card = SEARCH_X_CARD.to_dict()


class FetchXSOARTickets(ToodlesCommand):
    """Fetch XSOAR tickets based on search criteria."""
    command_keyword = "fetch_xsoar_tickets"
    card = None

    @toodles_log_activity
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
                message = f"[X#{ticket.get('id')}]({build_incident_url(ticket.get('id'))}) - {ticket.get('name')}\n"
        else:
            message = 'None Found'
        return message


class GetCompanyHolidays(ToodlesCommand):
    """Display company holidays for the year."""
    command_keyword = "holidays"
    card = None
    exact_command_keyword_match = False  # Allow "@bot holidays" syntax in group chats

    @toodles_log_activity
    def execute(self, message, attachment_actions, activity):
        today = datetime.now()

        # Load holidays from JSON
        with open("data/transient/company_holidays.json", "r") as f:
            holidays_data = json.load(f)

        year = holidays_data["year"]
        holidays = []
        next_holiday_idx = None
        next_holiday_date = None
        today_holiday_idx = None

        for idx, holiday in enumerate(holidays_data["holidays"]):
            holiday_date = datetime.strptime(holiday["date"], "%Y-%m-%d")
            emoji = holiday.get("emoji", "")
            name = holiday["name"]

            # Use observed date if present, otherwise use actual date
            display_date = holiday_date
            if "observed" in holiday:
                display_date = datetime.strptime(holiday["observed"], "%Y-%m-%d")

            # Check if this is today's holiday (using observed date)
            if display_date.date() == today.date():
                today_holiday_idx = idx
            # Find next future holiday (after today, using observed date)
            elif display_date > today and next_holiday_idx is None:
                next_holiday_idx = idx
                next_holiday_date = display_date

            # Determine styling
            if display_date.date() < today.date():
                style = 'italic'
            else:
                style = None

            # Format date parts for display
            day_of_week = display_date.strftime("%a")
            month_abbr = display_date.strftime("%b")
            day_num = display_date.strftime("%d")

            # Format as: "emoji  day_of_week  month day  -  holiday_name"
            holiday_line = f"{emoji}  {day_of_week:3s}  {month_abbr:3s} {day_num:2s}  -  {name}"
            holidays.append((holiday_line, style))

        # Add seasonal greeting based on current date
        month = today.month
        if month == 1:
            seasonal_greeting = "🎊 New year, new days off!"
        elif month == 2:
            seasonal_greeting = "❄️ Winter days off ahead!"
        elif month in [3, 4, 5]:
            seasonal_greeting = "🌸 Spring celebrations coming up!"
        elif month in [6, 7, 8]:
            seasonal_greeting = "☀️ Summer holidays to enjoy!"
        elif month in [9, 10, 11]:
            seasonal_greeting = "🍂 Fall festivities approaching!"
        else:  # 12
            seasonal_greeting = "🎄 Holiday season is here!"

        # Enhanced title with seasonal greeting
        title = f"🎉 **{year} Company Holidays** 🎉\n{seasonal_greeting}\n═══════════════════════════════════\n"

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


class GetBotHealth(ToodlesCommand):
    """Check bot health and status."""
    command_keyword = "health"
    card = None
    exact_command_keyword_match = False  # Allow "@bot health" syntax in group chats

    @toodles_log_activity
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


class Hi(ToodlesCommand):
    """Simple Hi command to check if bot is alive."""
    command_keyword = "hi"
    card = None
    delete_previous_message = False
    exact_command_keyword_match = False

    @toodles_log_activity
    def execute(self, message, attachment_actions, activity):
        return "Hi 👋🏾"


class GetDomainLookalikeCard(CardOnlyCommand):
    """Display the domain lookalike scanner form."""
    command_keyword = "domain_lookalike"
    help_message = "Domain Lookalike Scanner 🔍"
    card = DOMAIN_LOOKALIKE_CARD


class ProcessDomainLookalike(ToodlesCommand):
    """Process domain lookalike scan requests."""
    command_keyword = "domain_lookalike_scan"
    card = None

    @toodles_log_activity
    def execute(self, message, attachment_actions, activity):
        """Execute domain lookalike scan and return Excel file."""
        import re

        # Extract inputs
        domain = attachment_actions.inputs.get('domain', '').strip().lower()
        registered_only = attachment_actions.inputs.get('registered_only', 'false') == 'true'

        # Validate domain
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$'
        if not domain or not re.match(domain_pattern, domain):
            return "❌ Invalid domain format. Please enter a valid domain like 'example.com' (no http:// or www)"

        # Get room info for callbacks
        room_id = attachment_actions.roomId if attachment_actions else None
        if not room_id:
            logger.error(f"No room_id found in attachment_actions: {attachment_actions}")
            return "❌ Error: Unable to determine chat room. Please try again."

        # Delegate to scanner component
        if registered_only:
            return domain_scanner.start_full_scan(domain, room_id)
        else:
            return domain_scanner.start_quick_scan(domain, room_id)


class GetUrlBlockVerdictForm(CardOnlyCommand):
    """Display the URL block verdict form."""
    command_keyword = "get_url_block_verdict_form"
    help_message = "URL Block Verdict ⚖️"
    card = URL_BLOCK_VERDICT_CARD
    delete_previous_message = False


class ProcessUrlBlockVerdict(ToodlesCommand):
    """Process URL filtering submission from the card."""
    command_keyword = "url_verdict"
    card = None

    @toodles_log_activity
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
            table_headers = ['URL', 'ZScaler', 'Bloxone']
            table_str = tabulate(table_rows, headers=table_headers, tablefmt='simple', colalign=['left', 'center', 'center'])

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


class GetBirthdayAnniversaryForm(ToodlesCommand):
    """Display the birthday and anniversary input form."""
    command_keyword = "get_birthday_anniversary_form"
    help_message = "Birthday & Anniversary 🎉"
    card = None  # Will be dynamically created in execute()

    @toodles_log_activity
    def execute(self, message, attachment_actions, activity):
        import copy

        # Get user's existing data to pre-populate the form
        user_email = get_user_email(activity)
        existing_data = birthdays_anniversaries.get_employee_by_email(user_email)

        # Deep copy the card template to avoid modifying the original
        card = copy.deepcopy(BIRTHDAY_ANNIVERSARY_CARD)

        # Pre-populate values if user has existing data
        if existing_data:
            # Find and set birthday value (convert MM-DD to YYYY-MM-DD for Input.Date)
            if existing_data.get('birthday'):
                try:
                    birthday_value = f"2000-{existing_data['birthday']}"
                    # Navigate: body[2] (Container) -> items[0] (first ColumnSet) -> columns[1] -> items[0] (Input.Date)
                    card["body"][2]["items"][0]["columns"][1]["items"][0]["value"] = birthday_value
                except (KeyError, IndexError) as e:
                    logger.warning(f"Error setting birthday value in card: {e}")

            # Find and set anniversary value (already in YYYY-MM-DD format)
            if existing_data.get('anniversary'):
                try:
                    # Navigate: body[2] (Container) -> items[1] (second ColumnSet) -> columns[1] -> items[0] (Input.Date)
                    card["body"][2]["items"][1]["columns"][1]["items"][0]["value"] = existing_data['anniversary']
                except (KeyError, IndexError) as e:
                    logger.warning(f"Error setting anniversary value in card: {e}")

        # Send the card
        room_id = attachment_actions.roomId if attachment_actions else None
        if room_id:
            webex_api.messages.create(
                roomId=room_id,
                text="Birthday & Anniversary Form",
                attachments=[{
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": card
                }]
            )

        return None


class SaveBirthdayAnniversary(ToodlesCommand):
    """Save birthday and anniversary information from the form."""
    command_keyword = "save_birthday_anniversary"
    card = None
    delete_previous_message = False

    @toodles_log_activity
    def execute(self, message, attachment_actions, activity):
        try:
            # Get user info from activity
            user_email = get_user_email(activity)
            user_name = get_user_display_name(activity)

            # Get form inputs (both are optional)
            birthday_input = attachment_actions.inputs.get('birthday', '').strip()
            anniversary_input = attachment_actions.inputs.get('anniversary', '').strip()

            # Get existing data to check if user is clearing fields
            existing_data = birthdays_anniversaries.get_employee_by_email(user_email)

            # Convert birthday from YYYY-MM-DD to MM-DD format
            birthday = None
            if birthday_input:
                try:
                    date_obj = datetime.strptime(birthday_input, "%Y-%m-%d")
                    birthday = date_obj.strftime("%m-%d")
                except ValueError:
                    return f"{user_name}, invalid birthday format. Please use the date picker to select your birthday."

            # Keep anniversary in YYYY-MM-DD format (as entered)
            anniversary = anniversary_input if anniversary_input else None

            # Load current data for full update
            data = birthdays_anniversaries.load_data()

            # Find or create employee record
            employee = None
            for emp in data["employees"]:
                if emp["email"].lower() == user_email.lower():
                    employee = emp
                    break

            if employee is None:
                # New employee
                employee = {
                    "email": user_email,
                    "name": user_name,
                    "birthday": birthday,
                    "anniversary": anniversary
                }
                data["employees"].append(employee)
            else:
                # Update existing employee - ALWAYS overwrite with new values (including None to clear)
                employee["name"] = user_name  # Update name in case it changed
                employee["birthday"] = birthday  # Overwrite birthday (None clears it)
                employee["anniversary"] = anniversary  # Overwrite anniversary (None clears it)

            # Save updated data
            birthdays_anniversaries.save_data(data)

            # Build response message based on what was saved
            if birthday and anniversary:
                result_msg = f"🎉🎊 **Thank you, {user_name}!**\n\nWe'll make sure to celebrate both your **birthday** 🎂 and **work anniversary** 🏆!"
            elif birthday:
                result_msg = f"🎂 **Thank you, {user_name}!**\n\nWe'll make sure to celebrate your **birthday** with you! 🎉"
            elif anniversary:
                result_msg = f"🏆 **Thank you, {user_name}!**\n\nWe'll make sure to celebrate your **work anniversary** with you! 🎉"
            else:
                result_msg = f"✅ **{user_name}**, your birthday and anniversary information has been cleared."

            # Add user to Celebrations room if they submitted at least one date
            if (birthday or anniversary) and CONFIG.webex_room_id_celebrations:
                try:
                    webex_api.memberships.create(
                        roomId=CONFIG.webex_room_id_celebrations,
                        personEmail=user_email
                    )
                    logger.info(f"Added {user_email} to Celebrations room")
                    result_msg += "\n\n✨ _You've been added to the Celebrations room where we post birthday and anniversary wishes!_"
                except Exception as membership_error:
                    error_str = str(membership_error).lower()
                    if "already" in error_str or "409" in error_str or "conflict" in error_str:
                        logger.debug(f"{user_email} is already a member of Celebrations room")
                    else:
                        logger.warning(f"Could not add {user_email} to Celebrations room: {membership_error}")

            return result_msg

        except Exception as e:
            logger.error(f"Error saving birthday/anniversary: {e}", exc_info=True)
            return f"{activity['actor']['displayName']}, sorry, there was an error saving your information. Please try again."


def toodles_bot_factory():
    """Create Toodles bot instance"""
    # Clean up stale device registrations before starting
    # (to prevent device buildup from automatic restarts)
    cleanup_devices_on_startup(
        CONFIG.webex_bot_access_token_toodles,
        bot_name="Toodles"
    )

    # Build approved users list: employees + all bots for peer ping communication
    approved_bot_emails = [
        CONFIG.webex_bot_email_msoar,
        CONFIG.webex_bot_email_barnacles,
        CONFIG.webex_bot_email_money_ball,
        CONFIG.webex_bot_email_jarvis,
        CONFIG.webex_bot_email_pokedex,
        CONFIG.webex_bot_email_pinger,  # Pinger bot for keepalive
    ]

    return WebexBot(
        CONFIG.webex_bot_access_token_toodles,
        bot_name="Toodles Bot",
        approved_domains=[CONFIG.my_web_domain],
        approved_users=approved_bot_emails,  # Allow other bots for peer ping
        # approved_rooms disabled - bot lacks spark:memberships_read scope for validation
        # Security: Only add this bot to authorized rooms to control access
        log_level="ERROR",
        threads=True,
        bot_help_subtitle="Your friendly toolbox bot!",
        allow_bot_to_bot=True  # Enable peer ping health checks from other bots
    )


def toodles_initialization(bot=None):
    """Initialize Toodles commands"""
    if bot:
        # Add all commands
        bot.add_command(GetApprovedTestingCard())
        bot.add_command(GetCurrentApprovedTestingEntries())
        bot.add_command(AddApprovedTestingEntry())
        bot.add_command(RemoveApprovedTestingEntry())
        bot.add_command(Who())
        bot.add_command(Rotation())
        bot.add_command(ContainmentStatusCS())
        # bot.add_command(Review())
        bot.add_command(GetNewXTicketForm())
        bot.add_command(CreateXSOARTicket())
        bot.add_command(IOC())
        bot.add_command(IOCHunt())
        bot.add_command(URLs())
        bot.add_command(ThreatHunt())
        bot.add_command(CreateThreatHunt())
        bot.add_command(CreateAZDOWorkItem())
        bot.add_command(GetAllOptions())
        bot.add_command(ImportTicket())
        bot.add_command(CreateTuningRequest())
        bot.add_command(GetSearchXSOARCard())
        bot.add_command(FetchXSOARTickets())
        bot.add_command(GetCompanyHolidays())
        bot.add_command(GetBotHealth())
        bot.add_command(Hi())
        bot.add_command(GetUrlBlockVerdictForm())
        bot.add_command(ProcessUrlBlockVerdict())
        bot.add_command(GetBirthdayAnniversaryForm())
        bot.add_command(SaveBirthdayAnniversary())
        # Domain Lookalike Scanner
        bot.add_command(GetDomainLookalikeCard())
        bot.add_command(ProcessDomainLookalike())
        return True
    return False


def _shutdown_handler(signum=None, frame=None):
    """Log shutdown marker before exit"""
    logger.warning("=" * 100)
    logger.warning(f"🛑 TOODLES BOT STOPPED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.warning("=" * 100)


def main():
    """Toodles main - simplified to use basic WebexBot (keepalive handled by peer_ping_keepalive.py)"""
    logger.info("Starting Toodles with basic WebexBot")

    # Register shutdown handlers for graceful logging
    atexit.register(_shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    # Create bot instance
    bot = toodles_bot_factory()

    # Initialize commands
    toodles_initialization(bot)

    # Run bot (simple and direct)
    logger.info("🚀 Toodles is up and running...")
    print("🚀 Toodles is up and running...", flush=True)
    bot.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
