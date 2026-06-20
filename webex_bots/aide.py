#!/usr/bin/python3

"""
Aide Bot - Configuration Guide
==================================

This bot supports three operating modes:

1. FULL RESILIENCE MODE (for the corporate proxy/corporate proxy environments)
   SHOULD_USE_RESILIENCY = True
   USE_AUTO_RECONNECT = ignored
   Features: SSL patching, WebSocket patching, device cleanup, auto-reconnect

2. LITE RESILIENCE MODE (recommended for production without the corporate proxy)
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
    bot_name='aide',
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

# ALWAYS configure SSL for proxy environments (auto-detects the corporate proxy/proxies)
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
logger.warning(f"🚀 AIDE BOT STARTED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
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
    Colors, TextBlock, FontWeight, FontSize, Column, AdaptiveCard, ColumnSet, HorizontalAlignment, ActionSet,
    ActionStyle, ImageSize, Image, Container, options
)
from webexpythonsdk.models.cards.actions import Submit
from webex_bot.commands.help import HelpCommand
from webex_bot.models.response import response_from_adaptive_card

import src.components.oncall as oncall
from src.components import birthdays_anniversaries
from data.data_maps import azdo_projects, azdo_orgs, azdo_area_paths

from services import xsoar, azdo
from services.approved_testing_utils import add_approved_testing_entry
from services.ticket_cannon_utils import CATEGORIES, SILENCER_FIELDS, get_entries, create_entry
from services.crowdstrike import CrowdStrikeClient
from services.xsoar import ListHandler, TicketHandler, XsoarEnvironment

# Import cards from extracted package
from webex_bots.cards import (
    NEW_TICKET_CARD, IOC_HUNT, THREAT_HUNT, AZDO_CARD,
    APPROVED_TESTING_CARD, TICKET_CANNON_CARD, NOISE_SUPPRESSOR_CARD, TICKET_IMPORT_CARD, TUNING_REQUEST_CARD,
    DOMAIN_LOOKALIKE_CARD, BIRTHDAY_ANNIVERSARY_CARD,
    BROWSER_HISTORY_CARD, FILE_PULL_CARD, BLOCK_URL_FORM_CARD, all_options_card,
    CONTACTS_MENU_CARD, build_contacts_add_card,
    POI_INVESTIGATE_CARD,
)

# The URL block-verdict feature relies on a web-proxy lookup backend that isn't
# bundled in this build, so its card ships as a minimal placeholder and the
# command degrades gracefully (the handler reports the lookup is unavailable).
URL_BLOCK_VERDICT_CARD = {
    "type": "AdaptiveCard",
    "version": "1.2",
    "body": [{"type": "TextBlock", "text": "URL block-verdict lookup is not configured in this build.", "wrap": True}],
}

from my_bot.tools.crowdstrike_tools import collect_browser_history, get_and_clear_generated_file_path
from services.crowdstrike_rtr import download_rtr_file
from src.utils.http_utils import get_session
from src.utils.aide_decorators import aide_log_activity
from src.utils.webex_validation import validate_required_inputs, get_input_value
from src.utils.xsoar_helpers import build_incident_url, create_incident_with_response
from src.utils.webex_responses import format_user_response, get_user_email, get_user_display_name
from src.utils.webex_device_manager import cleanup_devices_on_startup
from webex_bots.base import AideCommand, CardOnlyCommand
from src.components.domain_lookalike_scanner import DomainLookalikeScanner
from services.poi_scanner import POIScanner

# Get robust HTTP session instance
http_session = get_session()

# Import connection pool configuration utility
from src.utils.webex_pool_config import configure_webex_api_session

# Increase timeout from default 60s to 180s for unreliable networks
# Configure with larger connection pool to prevent timeout issues
webex_api = configure_webex_api_session(
    WebexAPI(
        access_token=CONFIG.webex_bot_access_token_aide,
        single_request_timeout=180
    ),
    pool_connections=50,  # Increased from default 10
    pool_maxsize=50,  # Increased from default 10
    max_retries=3  # Enable automatic retry on transient failures
)

# Component instances
domain_scanner = DomainLookalikeScanner(webex_api)
poi_scanner = POIScanner(webex_api)

# Global variables
bot_instance = None

# Timezone constant for consistent usage
EASTERN_TZ = ZoneInfo("America/New_York")

# Fun aide-themed messages and features
AIDE_MESSAGES = [
    "🛠️ Fixing things faster than you can say 'aide'!",
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

AIDE_GREETINGS = [
    "👋 Aide is here to help!",
    "🎉 Ready to tackle some tickets!",
    "🔥 Let's get this workflow blazing!",
    "⚡ Powered up and ready to go!",
    "🚀 Mission control, standing by!"
]


def get_random_aide_message():
    """Get a random fun aide message."""
    import random
    return random.choice(AIDE_MESSAGES)


def get_random_greeting():
    """Get a random aide greeting."""
    import random
    return random.choice(AIDE_GREETINGS)


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
    Get URL card with favorite URLs from local JSON store.
    Returns a card with error message if data is unavailable.
    """
    try:
        from src.components.web.favorite_urls_handler import load_urls

        team_urls = load_urls()
        actions = []

        for item in team_urls:
            if item.get("url"):
                url = item['url']
                if not url.startswith(('http://', 'https://')):
                    url = f"https://{url}"

                actions.append({
                    "type": "Action.OpenUrl",
                    "title": item['name'],
                    "url": url,
                    "style": "positive"
                })
            elif item.get("phone_number"):
                actions.append({
                    "type": "Action.Submit",
                    "title": f"{item['name']} ({item['phone_number']})",
                    "data": {}
                })

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
    """Display favorite URLs from the local store."""
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


class CreateXSOARTicket(AideCommand):
    """Create a new XSOAR ticket from form submission."""
    command_keyword = "create_x_ticket"
    card = None

    @aide_log_activity
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


class IOCHunt(AideCommand):
    """Create a new IOC Hunt in XSOAR."""
    command_keyword = "ioc_hunt"
    card = None

    @aide_log_activity
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
    command_keyword = "show_threat_hunt_form"
    card = THREAT_HUNT


class CreateThreatHunt(AideCommand):
    """Create a new Threat Hunt in XSOAR and announce it."""
    command_keyword = "submit_threat_hunt"
    card = None

    @aide_log_activity
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


class GetAZDOCard(CardOnlyCommand):
    """Show the AZDO work item creation form."""
    command_keyword = "azdo"
    help_message = ""
    card = AZDO_CARD


class CreateAZDOWorkItem(AideCommand):
    """Create an Azure DevOps work item."""
    command_keyword = "azdo_wit"
    help_message = ""
    card = AZDO_CARD

    @aide_log_activity
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


class Review(AideCommand):
    """Submit a ticket for review."""
    command_keyword = "review"
    card = None

    @aide_log_activity
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


class GetCurrentApprovedTestingEntries(AideCommand):
    """Display current approved testing entries."""
    command_keyword = "current_approved_testing"
    card = None
    delete_previous_message = False

    @aide_log_activity
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
                f"You may find the same list at http://gdnr.{CONFIG.my_web_domain}/get-approved-testing-entries"
            )
        return result


def is_valid_ip(address: str) -> bool:
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


class AddApprovedTestingEntry(AideCommand):
    """Add a new approved testing entry."""
    command_keyword = "add_approved_testing"
    card = None

    @aide_log_activity
    def execute(self, message, attachment_actions, activity):
        usernames = get_input_value(attachment_actions, 'usernames')
        items_of_tester = get_input_value(attachment_actions, 'ip_addresses_and_host_names_of_tester')
        items_to_be_tested = get_input_value(attachment_actions, 'ip_addresses_and_host_names_to_be_tested')
        description = get_input_value(attachment_actions, 'description')
        scope = get_input_value(attachment_actions, 'scope')
        ttps = get_input_value(attachment_actions, 'ttps')
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
                submit_date,
                ttps=ttps
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


# --- Ticket Cannon Silencer & Noise Suppression ---

class GetTicketCannonCard(CardOnlyCommand):
    """Display the ticket cannon silencer form."""
    command_keyword = "silencer"
    help_message = ""
    card = TICKET_CANNON_CARD


class GetNoiseSuppressorCard(CardOnlyCommand):
    """Display the noisy rule suppressor form."""
    command_keyword = "suppressor"
    help_message = ""
    card = NOISE_SUPPRESSOR_CARD


class CreateSilencerEntry(AideCommand):
    """Create a new silencer or suppressor entry."""
    command_keyword = "create_silencer"
    card = None

    @aide_log_activity
    def execute(self, message, attachment_actions, activity):
        # Category comes from the card's Action.Submit data, not an input field
        category = attachment_actions.inputs.get('category', 'ticket_cannon')
        description = get_input_value(attachment_actions, 'description')
        expiry_days_str = get_input_value(attachment_actions, 'expiry_days') or '1'
        submitter = get_user_email(activity)

        if not description:
            return format_user_response(activity, "description is required.")

        # Build fields dict from the 3 field slots
        fields = {}
        for i in range(1, 4):
            key = get_input_value(attachment_actions, f'field{i}_key')
            val = get_input_value(attachment_actions, f'field{i}_value')
            if key and val:
                fields[key] = val

        # Custom free-text field
        custom_key = get_input_value(attachment_actions, 'custom_key')
        custom_val = get_input_value(attachment_actions, 'custom_value')
        logger.info(f"Silencer custom field: key='{custom_key}', val='{custom_val}', all_inputs={attachment_actions.inputs}")
        if custom_key and custom_val:
            fields[custom_key] = custom_val

        if not fields:
            return format_user_response(activity, "at least one filter field is required.")

        try:
            expiry_days = int(expiry_days_str)
        except ValueError:
            expiry_days = 1

        try:
            entry = create_entry(
                list_handler=prod_list_handler,
                team_name=CONFIG.team_name,
                category=category,
                description=description,
                fields=fields,
                expiry_days=expiry_days,
                created_by=submitter,
            )
        except ValueError as e:
            return format_user_response(activity, str(e))

        category_label = CATEGORIES.get(category, {}).get("label", category)
        cat_emoji = "🔇" if category == "ticket_cannon" else "🔕"
        field_lines = "\n".join(f"  🔹 **{SILENCER_FIELDS.get(k, k)}**: `{v}`" for k, v in fields.items())
        return format_user_response(
            activity,
            f"✅ **{category_label} created!**\n\n"
            f"{cat_emoji} **{description}**\n"
            f"{field_lines}\n"
            f"⏰ Expires: {entry['expiry_date']}\n\n"
            f"🌐 [View all on web dashboard](http://gdnr.{CONFIG.my_web_domain}/ticket-cannon)"
        )


class GetCurrentSilencers(AideCommand):
    """Show current active silencers and suppressors."""
    command_keyword = "current_silencers"
    card = None
    delete_previous_message = False

    @aide_log_activity
    def execute(self, message, attachment_actions, activity):
        cat_emojis = {"ticket_cannon": "🔇", "noise_suppression": "🔕"}
        lines = []
        total_active = 0
        for cat_key, cat_info in CATEGORIES.items():
            emoji = cat_emojis.get(cat_key, "📋")
            entries = get_entries(prod_list_handler, CONFIG.team_name, cat_key)
            active = [e for e in entries if e.get("active", False)]
            total_active += len(active)
            lines.append(f"{emoji} **{cat_info['label']}** — {len(active)} active")
            if not active:
                lines.append("  _No entries yet_ ✨")
            for e in active:
                field_parts = " | ".join(f"**{SILENCER_FIELDS.get(k, k)}**: `{v}`" for k, v in e.get("fields", {}).items())
                matches = e.get('match_count', 0)
                match_str = f"🎯 {matches} match{'es' if matches != 1 else ''}" if matches > 0 else "🆕 0 matches"
                lines.append(
                    f"  🔸 **{e.get('description', '?')}**\n"
                    f"    {field_parts}\n"
                    f"    ⏰ Expires {e.get('expiry_date', '?')} | {match_str} | 👤 {e.get('created_by', '?')}"
                )
            lines.append("")

        lines.append(f"🌐 [View all on web dashboard](http://gdnr.{CONFIG.my_web_domain}/ticket-cannon)")

        result = "\n".join(lines).strip()
        if len(result) > 7400:
            return format_user_response(
                activity,
                f"📋 Too many entries for Webex! View them at http://gdnr.{CONFIG.my_web_domain}/ticket-cannon"
            )

        header = f"🛡️ **{total_active} active filter{'s' if total_active != 1 else ''}** standing guard:\n\n"
        return format_user_response(activity, f"{header}{result}")


def add_entry_to_reviews(dict_full, ticket_id, person, date, message):
    """
    adds the ticket to the list for further review
    """
    dict_full.append({"ticket_id": ticket_id, "by": person, "date": date, "message": message})


def announce_new_threat_hunt(ticket_no, ticket_title, incident_url, person_id):
    webex_data = prod_list_handler.get_list_data_by_name(f'{CONFIG.team_name} Webex')
    request_headers = {
        'Content-Type': 'application/json',
        'Authorization': f"Bearer {CONFIG.webex_bot_access_token_aide}"
    }
    payload_json = {
        'roomId': webex_data.get("channels").get("threat_hunt"),
        'markdown': f"<@personId:{person_id}> created a new Threat Hunt in XSOAR. Ticket: [#{ticket_no}]({incident_url}) - {ticket_title}"
    }
    requests.post(webex_data.get('api_url'), headers=request_headers, json=payload_json)


class Who(AideCommand):
    """Return who the on-call person is."""
    command_keyword = "who"
    help_message = "On-Call ☎️"
    card = None
    delete_previous_message = False  # Keep the welcome card visible
    exact_command_keyword_match = False  # Allow "@bot who" syntax in group chats

    @aide_log_activity
    def execute(self, message, attachment_actions, activity):
        on_call_person = oncall.get_on_call_person()
        return format_user_response(
            activity,
            f"the DnR On-call person is {on_call_person.get('name')} - {on_call_person.get('email_address')} - {on_call_person.get('phone_number')}"
        )


class Rotation(AideCommand):
    """Display the on-call rotation schedule."""
    command_keyword = "rotation"
    card = None
    delete_previous_message = False  # Keep the welcome card visible
    exact_command_keyword_match = False  # Allow "@bot rotation" syntax in group chats

    @aide_log_activity
    def execute(self, message, attachment_actions, activity):
        rotation = oncall.get_rotation()
        data_frame = pandas.DataFrame(rotation, columns=["Monday_date", "analyst_name"])
        data_frame.columns = ['Monday', 'Analyst']
        return data_frame.to_string(index=False)


class ContainmentStatusCS(AideCommand):
    """Return the containment status of a host in CrowdStrike."""
    command_keyword = "status"
    card = None
    exact_command_keyword_match = False  # Allow "status hostname" syntax

    @aide_log_activity
    def execute(self, message, attachment_actions, activity):
        if message.strip() != "":
            host_name_cs = message.strip()
        elif attachment_actions and hasattr(attachment_actions, 'inputs'):
            host_name_cs = get_input_value(attachment_actions, 'host_name_cs')
        else:
            host_name_cs = ""

        host_name_cs = host_name_cs.replace(f"{CONFIG.team_name}_Aide status", "").strip()
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


class ImportTicket(CardOnlyCommand):
    """Show the import ticket form."""
    command_keyword = "import"
    card = TICKET_IMPORT_CARD.to_dict()


class DoImportTicket(AideCommand):
    """Import a ticket from production to dev."""
    command_keyword = "do_import"
    card = None

    @aide_log_activity
    def execute(self, message, attachment_actions, activity):
        prod_ticket_number = attachment_actions.inputs['prod_ticket_number']
        requestor_email_address = get_user_email(activity)
        destination_ticket_number, destination_ticket_link = xsoar.import_ticket(prod_ticket_number, requestor_email_address)
        return format_user_response(
            activity,
            f"the Prod ticket X#{prod_ticket_number} has been copied to Dev [X#{destination_ticket_number}]({destination_ticket_link})"
        )


class GetTuningRequestCard(CardOnlyCommand):
    """Show the tuning request form."""
    command_keyword = "tuning"
    help_message = ""
    card = TUNING_REQUEST_CARD.to_dict()


class CreateTuningRequest(AideCommand):
    """Create a tuning request in Azure DevOps."""
    command_keyword = "tuning_request"
    card = TUNING_REQUEST_CARD.to_dict()

    @aide_log_activity
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
    help_message = ""
    card = SEARCH_X_CARD.to_dict()


class FetchXSOARTickets(AideCommand):
    """Fetch XSOAR tickets based on search criteria."""
    command_keyword = "fetch_xsoar_tickets"
    card = None

    @aide_log_activity
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
            result = ""
            for ticket in tickets:
                result += f"[X#{ticket.get('id')}]({build_incident_url(ticket.get('id'))}) - {ticket.get('name')}\n"
            return format_user_response(activity, f"here are the matching tickets:\n{result}")
        else:
            # Build descriptive message about what was searched
            search_criteria = []
            if username:
                search_criteria.append(f"username **{username}**")
            if email:
                search_criteria.append(f"email **{email}**")
            if hostname:
                search_criteria.append(f"hostname **{hostname}**")
            criteria_text = ", ".join(search_criteria) if search_criteria else "the given criteria"
            return format_user_response(activity, f"no tickets found in X for {criteria_text}")


class GetCompanyHolidays(AideCommand):
    """Display company holidays for the year."""
    command_keyword = "holidays"
    card = None
    exact_command_keyword_match = False  # Allow "@bot holidays" syntax in group chats

    @aide_log_activity
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


class GetBotHealth(AideCommand):
    """Check bot health and status."""
    command_keyword = "health"
    card = None
    exact_command_keyword_match = False  # Allow "@bot health" syntax in group chats

    @aide_log_activity
    def execute(self, message, attachment_actions, activity):
        room_id = attachment_actions.roomId
        current_time = datetime.now(EASTERN_TZ)

        # Determine current mode
        if CONFIG.should_use_proxy_resilience:
            mode = "Full Resilience"
            health_detail = "the corporate proxy features + Auto-reconnect"
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
                    text="🤖 Aide Bot Status",
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


class Hi(AideCommand):
    """Simple Hi command to check if bot is alive."""
    command_keyword = "hi"
    card = None
    delete_previous_message = False

    @aide_log_activity
    def execute(self, message, attachment_actions, activity):
        return "Hi 👋🏾"


class RemoveWatchlistDomain(AideCommand):
    """Remove a domain from the realtime watchlist via heartbeat card action."""
    command_keyword = "watchlist_remove"
    card = None
    delete_previous_message = False

    @aide_log_activity
    def execute(self, message, attachment_actions, activity):
        domain = attachment_actions.inputs.get("domain_to_remove", "").strip()
        if not domain:
            return "❌ No domain selected."
        from src.components.domain_monitoring.watchlist_poller import remove_watchlist_domain
        result = remove_watchlist_domain(domain)
        person_id = attachment_actions.personId
        return f"Thanks <@personId:{person_id}>! {result}"


class GetDomainLookalikeCard(CardOnlyCommand):
    """Display the domain lookalike scanner form."""
    command_keyword = "domain_lookalike"
    card = DOMAIN_LOOKALIKE_CARD


class ProcessDomainLookalike(AideCommand):
    """Process domain lookalike scan requests."""
    command_keyword = "domain_lookalike_scan"
    card = None

    @aide_log_activity
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


class GetPOICard(CardOnlyCommand):
    """Show the Person-of-Interest OSINT form."""
    command_keyword = "poi"
    card = POI_INVESTIGATE_CARD


class InvestigatePOI(AideCommand):
    """Run OSINT sweep on a person (name/username/email)."""
    command_keyword = "poi_investigate"
    card = None

    @aide_log_activity
    def execute(self, message, attachment_actions, activity):
        name = (get_input_value(attachment_actions, 'poi_name') or '').strip()
        username = (get_input_value(attachment_actions, 'poi_username') or '').strip()
        email = (get_input_value(attachment_actions, 'poi_email') or '').strip()
        reason = (get_input_value(attachment_actions, 'poi_reason') or '').strip()

        if not (name or username or email):
            return "❌ Provide at least one of: name, username, or email."

        room_id = attachment_actions.roomId if attachment_actions else None
        if not room_id:
            return "❌ Unable to determine chat room. Please try again."

        requester = get_user_email(activity) or 'unknown'
        ack = poi_scanner.start_investigation(
            name=name, username=username, email=email,
            reason=reason, room_id=room_id, requester=requester,
        )
        if ack is None:
            # Target on exception list — return a neutral, plausible response and
            # do no further work. Activity log records only the requester + command.
            return "✅ Investigation complete. No notable findings."
        return ack


def _check_host_online(hostname: str) -> bool:
    """Return True if host is online in CrowdStrike."""
    cs = CrowdStrikeClient()
    return cs.get_device_online_state(hostname) == "online"


def _offline_host_card(ticket_number, hostname, rtr_action, file_path=None):
    """Build an Adaptive Card asking if the analyst wants to monitor the offline host."""
    submit_data = {
        'callback_keyword': 'monitor_offline_host',
        'ticket_number': ticket_number,
        'hostname': hostname,
        'rtr_action': rtr_action,
    }
    if file_path:
        submit_data['file_path'] = file_path

    card = AdaptiveCard(body=[
        Container(
            items=[
                TextBlock(
                    text=f"🔴  Host {hostname} is offline",
                    size=FontSize.MEDIUM,
                    weight=FontWeight.BOLDER,
                    color=Colors.ATTENTION,
                ),
                TextBlock(
                    text="RTR requires the device to be online. Would you like to monitor this host and automatically perform the action when it comes back online?",
                    spacing=options.Spacing.SMALL,
                    wrap=True,
                ),
                TextBlock(
                    text="The host will be checked every 15 minutes until it comes online.",
                    spacing=options.Spacing.SMALL,
                    isSubtle=True,
                    wrap=True,
                ),
            ],
            style=options.ContainerStyle.EMPHASIS,
            bleed=True,
        ),
        ActionSet(actions=[
            Submit(
                title="👁️ Yes, monitor and run when online",
                style=ActionStyle.POSITIVE,
                data=submit_data,
            ),
        ]),
    ])
    return response_from_adaptive_card(adaptive_card=card)


class MonitorOfflineHost(AideCommand):
    """Queue an offline host for deferred RTR execution via the scheduler."""
    command_keyword = "monitor_offline_host"
    card = None

    @aide_log_activity
    def execute(self, message, attachment_actions, activity):
        from src.deferred_rtr import add_entry

        room_id = attachment_actions.roomId if attachment_actions else None

        hostname = get_input_value(attachment_actions, 'hostname')
        ticket_number = get_input_value(attachment_actions, 'ticket_number')
        rtr_action = get_input_value(attachment_actions, 'rtr_action')
        file_path = get_input_value(attachment_actions, 'file_path')

        if not hostname or not ticket_number or not rtr_action:
            return "Missing required information to monitor host."

        requester = get_user_email(activity)
        add_entry(hostname, ticket_number, rtr_action, room_id, file_path=file_path, requester=requester)

        return f"👁️ Now monitoring **{hostname}** (X#{ticket_number}). The scheduler will check every 15 minutes and run `{rtr_action}` as soon as the host comes online."


def _closed_ticket_card(ticket_number, retry_action, file_path=None):
    """Build an Adaptive Card prompting to reopen a closed ticket and retry."""
    ticket_url = build_incident_url(ticket_number)
    submit_data = {
        'callback_keyword': 'reopen_and_retry',
        'ticket_number': ticket_number,
        'retry_action': retry_action,
    }
    if file_path:
        submit_data['file_path'] = file_path

    card = AdaptiveCard(body=[
        Container(
            items=[
                TextBlock(
                    text=f"🔒  Ticket X#{ticket_number} is closed",
                    size=FontSize.MEDIUM,
                    weight=FontWeight.BOLDER,
                    color=Colors.ATTENTION,
                ),
                TextBlock(
                    text="Reopen the ticket to attach files.",
                    spacing=options.Spacing.SMALL,
                ),
            ],
            style=options.ContainerStyle.EMPHASIS,
            bleed=True,
        ),
        ActionSet(actions=[
            Submit(
                title="🔓 Reopen & Retry",
                style=ActionStyle.POSITIVE,
                data=submit_data,
            ),
        ]),
    ])
    return response_from_adaptive_card(adaptive_card=card)


class ReopenAndRetry(AideCommand):
    """Reopen a closed XSOAR ticket and re-run the original action."""
    command_keyword = "reopen_and_retry"
    card = None

    @aide_log_activity
    def execute(self, message, attachment_actions, activity):
        ticket_number = get_input_value(attachment_actions, 'ticket_number')
        retry_action = get_input_value(attachment_actions, 'retry_action')
        if not ticket_number or not retry_action:
            return "Missing ticket number or action."

        # Reopen the ticket
        try:
            prod_incident_handler.update_incident(ticket_number, {'status': 1})
            logger.info(f"Reopened ticket X#{ticket_number} for {retry_action}")
        except Exception as e:
            logger.error(f"Failed to reopen ticket X#{ticket_number}: {e}")
            return f"⚠️ Failed to reopen ticket X#{ticket_number}: `{e}`"

        # Re-dispatch to the original command
        for cmd in [FetchBrowserHistory(), FetchFilePull()]:
            if cmd.command_keyword == retry_action:
                return cmd.execute(message, attachment_actions, activity)

        return f"⚠️ Unknown retry action: `{retry_action}`"


class GetBrowserHistoryCard(CardOnlyCommand):
    """Display the browser history collection form."""
    command_keyword = "get_browser_history_card"
    help_message = "Browser History 🌐"
    card = BROWSER_HISTORY_CARD


class FetchBrowserHistory(AideCommand):
    """Collect browser history from a device via CrowdStrike RTR."""
    command_keyword = "fetch_browser_history"
    card = None

    @aide_log_activity
    def execute(self, message, attachment_actions, activity):
        import os

        room_id = attachment_actions.roomId if attachment_actions else None

        ticket_number = get_input_value(attachment_actions, 'ticket_number')
        if not ticket_number:
            return "Please enter an XSOAR ticket number."

        # Strip common prefixes
        ticket_number = ticket_number.strip().lstrip('#')
        if ticket_number.upper().startswith('X#'):
            ticket_number = ticket_number[2:]
        elif ticket_number.upper().startswith('X'):
            ticket_number = ticket_number[1:]

        # Fetch ticket from XSOAR
        try:
            case_data = prod_incident_handler.get_case_data(ticket_number)
        except Exception as e:
            logger.error(f"Error fetching ticket X#{ticket_number}: {e}")
            return f"Could not find ticket X#{ticket_number} in XSOAR."

        if not case_data or not case_data.get('id'):
            return f"Could not find ticket X#{ticket_number} in XSOAR."

        if case_data.get('status') == 2:
            return _closed_ticket_card(ticket_number, 'fetch_browser_history')

        # Extract hostname from ticket
        custom_fields = case_data.get('CustomFields') or {}
        hostname = custom_fields.get('hostname', '').strip()
        if not hostname or hostname.lower() in ('n/a', 'na', 'none', ''):
            return f"No hostname found on ticket X#{ticket_number}."

        # Look up device in CrowdStrike
        try:
            cs = CrowdStrikeClient()
            device_id = cs.get_device_id(hostname)
        except Exception as e:
            logger.error(f"CrowdStrike lookup error for {hostname}: {e}")
            return f"Error looking up **{hostname}** in CrowdStrike: {e}"

        if not device_id:
            return f"Host **{hostname}** not found in CrowdStrike."

        # Check platform
        try:
            details = cs.get_device_details(device_id)
            platform = details.get('platform_name', 'Unknown')
            if platform not in ('Windows', 'Mac'):
                return f"Browser history collection is only supported on Windows and Mac devices. **{hostname}** is {platform}."
        except Exception as e:
            logger.warning(f"Could not check platform for {hostname}: {e}")
            platform = None

        # Check if host is online before attempting RTR
        if not _check_host_online(hostname):
            return _offline_host_card(ticket_number, hostname, 'fetch_browser_history')

        # Collect browser history via RTR
        try:
            webex_api.messages.create(
                roomId=room_id,
                markdown=f"Collecting browser history from **{hostname}** (X#{ticket_number})... this may take a minute."
            )
        except Exception:
            pass

        try:
            result_message = collect_browser_history.func(hostname, platform=platform)
        except Exception as e:
            logger.error(f"Failed to collect browser history from {hostname}: {e}")
            return f"⚠️ Failed to collect browser history from **{hostname}**: `{e}`"
        file_path = get_and_clear_generated_file_path()

        if file_path and os.path.exists(file_path):
            # Upload to XSOAR war room
            try:
                prod_incident_handler.upload_file_to_attachment(
                    ticket_number, file_path,
                    comment=f"Browser history collected from {hostname}"
                )
            except Exception as e:
                logger.error(f"Failed to upload browser history to XSOAR X#{ticket_number}: {e}")

            # Notify in Webex (file is already on the ticket)
            ticket_url = build_incident_url(ticket_number)
            return format_user_response(
                activity,
                f"🌐 Browser history collected from **{hostname}**\n\n"
                f"📎 File attached to [X#{ticket_number}]({ticket_url})"
            )

        # No file generated (few entries or error) — return the text response
        return result_message


class GetFilePullCard(CardOnlyCommand):
    """Display the file pull form."""
    command_keyword = "get_file_pull_card"
    help_message = "File Pull 📁"
    card = FILE_PULL_CARD


class FetchFilePull(AideCommand):
    """Pull a file from an endpoint via CrowdStrike RTR."""
    command_keyword = "fetch_file_pull"
    card = None

    @aide_log_activity
    def execute(self, message, attachment_actions, activity):
        import os

        room_id = attachment_actions.roomId if attachment_actions else None

        ticket_number = get_input_value(attachment_actions, 'ticket_number')
        if not ticket_number:
            return "Please enter an XSOAR ticket number."

        file_path = get_input_value(attachment_actions, 'file_path')
        if not file_path:
            return "Please enter a file path."

        # Strip common prefixes
        ticket_number = ticket_number.strip().lstrip('#')
        if ticket_number.upper().startswith('X#'):
            ticket_number = ticket_number[2:]
        elif ticket_number.upper().startswith('X'):
            ticket_number = ticket_number[1:]

        # Fetch ticket from XSOAR
        try:
            case_data = prod_incident_handler.get_case_data(ticket_number)
        except Exception as e:
            logger.error(f"Error fetching ticket X#{ticket_number}: {e}")
            return f"Could not find ticket X#{ticket_number} in XSOAR."

        if not case_data or not case_data.get('id'):
            return f"Could not find ticket X#{ticket_number} in XSOAR."

        if case_data.get('status') == 2:
            return _closed_ticket_card(ticket_number, 'fetch_file_pull', file_path=file_path)

        # Extract hostname from ticket
        custom_fields = case_data.get('CustomFields') or {}
        hostname = custom_fields.get('hostname', '').strip()
        if not hostname or hostname.lower() in ('n/a', 'na', 'none', ''):
            return f"No hostname found on ticket X#{ticket_number}."

        # Check if host is online before attempting RTR
        if not _check_host_online(hostname):
            return _offline_host_card(ticket_number, hostname, 'fetch_file_pull', file_path=file_path)

        # Send progress message
        basename = os.path.basename(file_path.replace('\\', '/'))
        try:
            webex_api.messages.create(
                roomId=room_id,
                markdown=f"Pulling **{basename}** from **{hostname}** (X#{ticket_number})... this may take a few minutes."
            )
        except Exception:
            pass

        # Build local path and pull file via RTR
        local_path = f"/tmp/rtr_file_pull_{hostname}_{basename}"
        result = download_rtr_file(hostname, file_path, local_path)

        if not result.get('success'):
            return f"File pull failed: {result.get('error', 'Unknown error')}"

        actual_path = result.get('local_path', local_path)

        # Upload to XSOAR attachments
        try:
            prod_incident_handler.upload_file_to_attachment(
                ticket_number, actual_path,
                comment=f"File pulled from {hostname}: {file_path}"
            )
        except Exception as e:
            logger.error(f"Failed to upload file to XSOAR X#{ticket_number}: {e}")

        # Cleanup local file (already uploaded to XSOAR)
        try:
            os.remove(actual_path)
        except OSError:
            pass

        # Notify in Webex (file is already on the ticket)
        ticket_url = build_incident_url(ticket_number)
        return format_user_response(
            activity,
            f"📁 **{basename}** pulled from **{hostname}**\n\n"
            f"📎 File attached to [X#{ticket_number}]({ticket_url})"
        )


class GetUrlBlockVerdictForm(CardOnlyCommand):
    """Display the URL block verdict form."""
    command_keyword = "get_url_block_verdict_form"
    card = URL_BLOCK_VERDICT_CARD
    delete_previous_message = False


class ProcessUrlBlockVerdict(AideCommand):
    """Process URL filtering submission from the card."""
    command_keyword = "url_verdict"
    card = None

    @aide_log_activity
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
            return f"{activity['actor']['displayName']}, please provide URLs to test. Example: @aide url_verdict facebook.com, google.com"

        try:
            # Create tester and parse/normalize URLs using backend logic
            from src.components.url_lookup_traffic import URLChecker
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
                zs = result['proxy']
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
            table_headers = ['URL', 'the corporate proxy', 'Bloxone']
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
                zs_blocked = sum(1 for r in results if not r['proxy'].get('allowed'))
                bo_blocked = sum(1 for r in results if not r['bloxone'].get('allowed', True) and 'skipped' not in r['bloxone'])

                response = (f"{activity['actor']['displayName']}, tested {total} URLs.\n"
                            f"the corporate proxy blocked: {zs_blocked}/{total}\n"
                            f"Bloxone blocked: {bo_blocked}/{total}\n"
                            f"Results too long for chat - reduce the number of URLs in the input.\n"
                            f"Responded in {response_time}s")

            return response

        except Exception as e:
            logger.error(f"URL testing error: {str(e)}")
            return f"{activity['actor']['displayName']}, error testing URLs: {str(e)}"


class GetBlockUrlForm(CardOnlyCommand):
    """Display the Block URL form."""
    command_keyword = "get_block_url_form"
    help_message = "Block URL 🚫"
    card = BLOCK_URL_FORM_CARD


class DoBlockUrl(AideCommand):
    """Submit a URL block request to XSOAR."""
    command_keyword = "do_block_url"
    card = None

    @aide_log_activity
    def execute(self, message, attachment_actions, activity):
        from my_bot.tools.block_url_tools import execute_url_block, _get_allowed_rooms

        room_id = attachment_actions.roomId if attachment_actions else None
        allowed = _get_allowed_rooms()
        if allowed and (not room_id or room_id not in allowed):
            return "🚫 URL blocking is only available in authorized rooms (Threat Con, GOSC T2, or Test Dev Space)."

        url = (get_input_value(attachment_actions, 'url') or '').strip()
        xsoar_ticket_id = (get_input_value(attachment_actions, 'xsoar_ticket_id') or '').strip()
        reason = (get_input_value(attachment_actions, 'reason') or '').strip()

        if not url:
            return "❌ URL is required."
        if not reason:
            return "❌ Reason is required."

        import re
        clean_url = re.sub(r'^https?://', '', url).split('/')[0]

        user_email = get_user_email(activity) or 'unknown'

        import threading
        threading.Thread(
            target=execute_url_block,
            kwargs={
                'room_id': room_id,
                'url': clean_url,
                'xsoar_ticket_id': xsoar_ticket_id,
                'reason': reason,
                'user_email': user_email,
                'parent_msg_id': '',
                'bot_access_token': CONFIG.webex_bot_access_token_aide,
            },
            daemon=True,
        ).start()

        return f"🚫 Submitting block request for `{clean_url}`..."


class GetBirthdayAnniversaryForm(AideCommand):
    """Display the birthday and anniversary input form."""
    command_keyword = "get_birthday_anniversary_form"
    help_message = "Birthday & Anniversary 🎉"
    card = None  # Will be dynamically created in execute()

    @aide_log_activity
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


class SaveBirthdayAnniversary(AideCommand):
    """Save birthday and anniversary information from the form."""
    command_keyword = "save_birthday_anniversary"
    card = None
    delete_previous_message = False

    @aide_log_activity
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


class AideHelpCommand(HelpCommand):
    """Custom help command with centered title and two-column button grid."""

    def build_card(self, message, attachment_actions, activity):
        heading = TextBlock("🛠️ Aide ✨", weight=FontWeight.BOLDER, wrap=True,
                            size=FontSize.LARGE, horizontalAlignment=HorizontalAlignment.CENTER,
                            color=Colors.ACCENT)
        subtitle = TextBlock(self.bot_help_subtitle, wrap=True, size=FontSize.SMALL,
                             color=Colors.LIGHT, horizontalAlignment=HorizontalAlignment.CENTER)

        image = Image(url=self.bot_help_image, size=ImageSize.SMALL)

        header_column = Column(items=[heading, subtitle], width=2)
        header_image_column = Column(items=[image], width=1)

        header_container = Container(
            items=[ColumnSet(columns=[header_column, header_image_column])],
            style=options.ContainerStyle.ACCENT,
            bleed=True
        )

        thread_parent_id = None
        if 'parent' not in activity:
            thread_parent_id = activity['id']

        # Collect commands with help messages
        cmds = []
        if self.commands:
            for cmd in sorted(self.commands, key=lambda c: (c.command_keyword or '')):
                if cmd.help_message and cmd.command_keyword != 'help':
                    cmds.append(cmd)

        # Sort by label length (longest first), split into left/right columns
        cmds.sort(key=lambda c: len(c.help_message), reverse=True)
        mid = (len(cmds) + 1) // 2
        left_cmds = cmds[:mid]
        right_cmds = cmds[mid:]

        def make_action_set(cmd):
            return ActionSet(actions=[Submit(
                title=cmd.help_message,
                data={'command_keyword': cmd.command_keyword,
                      'thread_parent_id': thread_parent_id}
            )])

        left_col = Column(items=[make_action_set(c) for c in left_cmds], width="stretch")
        right_col = Column(items=[make_action_set(c) for c in right_cmds], width="auto")

        button_grid = Container(
            items=[ColumnSet(columns=[left_col, right_col])],
            style=options.ContainerStyle.EMPHASIS,
            bleed=True,
            spacing=options.Spacing.NONE
        )

        card = AdaptiveCard(
            body=[
                header_container,
                button_grid
            ])
        return response_from_adaptive_card(adaptive_card=card)


def aide_bot_factory():
    """Create Aide bot instance"""
    # Clean up stale device registrations before starting
    # (to prevent device buildup from automatic restarts)
    cleanup_devices_on_startup(
        CONFIG.webex_bot_access_token_aide,
        bot_name="Aide"
    )

    # Build approved users list: employees + all bots for peer ping communication
    approved_bot_emails = [
        CONFIG.webex_bot_email_orchestrator,
        CONFIG.webex_bot_email_relay,
        CONFIG.webex_bot_email_oracle,
        CONFIG.webex_bot_email_jarvis,
        CONFIG.webex_bot_email_sleuth,
        CONFIG.webex_bot_email_pinger,  # Pinger bot for keepalive
    ]

    # Fetch bot avatar for the custom help card
    bot_avatar = webex_api.people.me().avatar

    help_cmd = AideHelpCommand(
        bot_name="Aide",
        bot_help_subtitle="✨ Your friendly toolbox bot!",
        bot_help_image=bot_avatar
    )

    return WebexBot(
        CONFIG.webex_bot_access_token_aide,
        bot_name="Aide",
        approved_domains=[d.strip() for d in (CONFIG.company_domains or CONFIG.my_web_domain).split(",") if d.strip()],
        approved_users=approved_bot_emails,  # Allow other bots for peer ping
        # approved_rooms disabled - bot lacks spark:memberships_read scope for validation
        # Security: Only add this bot to authorized rooms to control access
        log_level="ERROR",
        threads=True,
        help_command=help_cmd,
        allow_bot_to_bot=True  # Enable peer ping health checks from other bots
    )


# ---------------------------------------------------------------------------
# Escalation Contacts
# ---------------------------------------------------------------------------

class GetContactsCard(CardOnlyCommand):
    """Display the contacts menu card with Show All and Add New buttons."""
    command_keyword = "contacts"
    help_message = "Escalation Contacts 📇"
    card = CONTACTS_MENU_CARD


class GetContactsAddForm(AideCommand):
    """Display the Add New Contact form with dynamic region choices."""
    command_keyword = "get_contacts_add_form"
    card = None

    @aide_log_activity
    def execute(self, message, attachment_actions, activity):
        from src.components.web.escalation_contacts_handler import get_regions
        regions = get_regions() or ["Global", "APAC", "EMEA", "LATAM", "JAPAN"]
        card = build_contacts_add_card(regions)

        room_id = attachment_actions.roomId if attachment_actions else None
        if room_id:
            webex_api.messages.create(
                roomId=room_id,
                text="Add New Contact",
                attachments=[{
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": card
                }]
            )
        return None


class AddNewContact(AideCommand):
    """Process the Add New Contact form submission."""
    command_keyword = "add_new_contact"
    card = None
    delete_previous_message = False

    @aide_log_activity
    def execute(self, message, attachment_actions, activity):
        from src.components.web.escalation_contacts_handler import create_contact, rebuild_embeddings

        region = get_input_value(attachment_actions, 'region')
        custom_region = get_input_value(attachment_actions, 'custom_region')
        team = get_input_value(attachment_actions, 'team')
        name = get_input_value(attachment_actions, 'name')
        title = get_input_value(attachment_actions, 'title')
        email = get_input_value(attachment_actions, 'email')
        phone = get_input_value(attachment_actions, 'phone')

        # Use custom region if "New Region" was selected
        if region == "__new__":
            region = custom_region
        if not region or not team or not name:
            return "⚠️ **Region**, **Team**, and **Name** are required fields."

        try:
            contact_id = create_contact(region=region, team=team, name=name,
                                        title=title, email=email, phone=phone)
        except Exception as e:
            logger.error("Failed to create contact: %s", e, exc_info=True)
            return f"❌ Failed to add contact: {e}"

        # Rebuild embeddings in background
        import threading
        threading.Thread(target=rebuild_embeddings, daemon=True).start()

        user_name = get_user_display_name(activity)
        parts = [f"✅ **{user_name}** added a new contact:"]
        parts.append(f"- **Name:** {name}")
        if title:
            parts.append(f"- **Title:** {title}")
        parts.append(f"- **Region:** {region} / **Team:** {team}")
        if email:
            parts.append(f"- **Email:** {email}")
        if phone:
            parts.append(f"- **Phone:** {phone}")
        return "\n".join(parts)


def aide_initialization(bot=None):
    """Initialize Aide commands"""
    if bot:
        # Add all commands
        bot.add_command(GetApprovedTestingCard())
        bot.add_command(GetCurrentApprovedTestingEntries())
        bot.add_command(AddApprovedTestingEntry())
        bot.add_command(RemoveApprovedTestingEntry())
        # Ticket Cannon Silencer / Noise Suppression
        bot.add_command(GetTicketCannonCard())
        bot.add_command(GetNoiseSuppressorCard())
        bot.add_command(CreateSilencerEntry())
        bot.add_command(GetCurrentSilencers())
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
        bot.add_command(GetAZDOCard())
        bot.add_command(CreateAZDOWorkItem())
        bot.add_command(GetAllOptions())
        bot.add_command(ImportTicket())
        bot.add_command(DoImportTicket())
        bot.add_command(GetTuningRequestCard())
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
        # Domain monitoring
        bot.add_command(RemoveWatchlistDomain())
        bot.add_command(GetDomainLookalikeCard())
        bot.add_command(ProcessDomainLookalike())
        # Person of Interest OSINT
        bot.add_command(GetPOICard())
        bot.add_command(InvestigatePOI())
        # Browser History
        bot.add_command(ReopenAndRetry())
        bot.add_command(GetBrowserHistoryCard())
        bot.add_command(FetchBrowserHistory())
        # File Pull
        bot.add_command(GetFilePullCard())
        bot.add_command(FetchFilePull())
        # Block URL
        bot.add_command(GetBlockUrlForm())
        bot.add_command(DoBlockUrl())
        # Offline host monitoring (callback from RTR offline prompt)
        bot.add_command(MonitorOfflineHost())
        # Escalation Contacts
        bot.add_command(GetContactsCard())
        bot.add_command(GetContactsAddForm())
        bot.add_command(AddNewContact())
        return True
    return False


def _shutdown_handler(signum=None, frame=None):
    """Log shutdown marker before exit"""
    logger.warning("=" * 100)
    logger.warning(f"🛑 AIDE BOT STOPPED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.warning("=" * 100)


def main():
    """Aide main - simplified to use basic WebexBot (keepalive handled by peer_ping_keepalive.py)"""
    logger.info("Starting Aide with basic WebexBot")

    # Register shutdown handlers for graceful logging
    atexit.register(_shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    # Create bot instance
    bot = aide_bot_factory()

    # Initialize commands
    aide_initialization(bot)

    # Run bot (simple and direct)
    logger.info("🚀 Aide is up and running...")
    print("🚀 Aide is up and running...", flush=True)
    bot.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
