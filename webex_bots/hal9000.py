# -*- coding: utf-8 -*-
"""
Toodles Webex Bot - Main Application File
"""

import logging
from datetime import datetime, timedelta
from urllib.parse import quote

import pandas
import webexpythonsdk.models.cards.inputs as INPUTS
import webexpythonsdk.models.cards.options as OPTIONS
from pytz import timezone
from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot
from webexpythonsdk import WebexAPI
from webexpythonsdk.models.cards import (
    ActionSet, ActionStyle, AdaptiveCard, Colors, Column, ColumnSet,
    FontWeight, HorizontalAlignment, TextBlock, Choice, ShowCard
)
from webexpythonsdk.models.cards.actions import Submit

# --- Local Imports ---
# Ensure these paths are correct relative to your project structure
import src.components.oncall as oncall
from config import get_config
from data.transient.data_maps import azdo_area_paths, azdo_orgs, azdo_projects
from services import azdo, xsoar
from services.crowdstrike import CrowdStrikeClient
from services.xsoar import IncidentHandler, ListHandler
from src.helper_methods import log_moneyball_activity

# --- Configuration and Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Constants ---
APPROVED_TESTING_LIST_NAME: str = "METCIRT_Approved_Testing"
APPROVED_TESTING_MASTER_LIST_NAME: str = "METCIRT_Approved_Testing_MASTER"
REVIEW_LIST_NAME: str = "review"
URL_LIST_NAME: str = "METCIRT URLs"
WEBEX_CONFIG_LIST_NAME: str = "METCIRT Webex"
DEFAULT_TIMEZONE: str = "US/Eastern"
DEFAULT_EXPIRY_TIME_DESC: str = "5 PM ET"
DEFAULT_BOT_NAME: str = "Toodles"
DEFAULT_APPROVED_DOMAINS: list[str] = ['company.com']

# --- Load Configuration ---
try:
    CONFIG = get_config()
except Exception as e:
    logger.critical(f"CRITICAL: Failed to load configuration: {e}", exc_info=True)
    # Exit if essential configuration is missing
    exit(1)

# --- Validate Essential Configuration ---
# Using getattr for safer access in case attributes are missing
if not getattr(CONFIG, 'webex_bot_access_token_toodles', None):
    logger.critical("CRITICAL: Webex Bot Access Token (toodles) is missing in the configuration.")
    exit(1)
if not getattr(CONFIG, 'xsoar_prod_auth_key', None) or not getattr(CONFIG, 'xsoar_prod_auth_id', None):
    logger.warning("XSOAR Prod credentials missing. Prod functionality will be affected.")
if not getattr(CONFIG, 'xsoar_dev_auth_key', None) or not getattr(CONFIG, 'xsoar_dev_auth_id', None):
    logger.warning("XSOAR Dev credentials missing. Dev functionality will be affected.")
if not getattr(CONFIG, 'webex_room_id_gosc_t2', None):
    logger.warning("Webex Room ID for GOSC T2 announcements (webex_room_id_gosc_t2) is missing.")
if not getattr(CONFIG, 'webex_room_id_automation_engineering', None):
    logger.warning("Webex Room ID for Automation Engineering announcements (webex_room_id_automation_engineering) is missing.")
if not getattr(CONFIG, 'xsoar_prod_ui_base_url', None):
    logger.warning("XSOAR Prod UI Base URL (xsoar_prod_ui_base_url) is missing.")
# Add checks for other essential URLs or keys as needed

# --- Initialize APIs and Services ---
try:
    webex_api = WebexAPI(CONFIG.webex_bot_access_token_toodles)
    # Verify token validity early
    try:
        webex_api.people.me()
        logger.info("Webex API connection successful.")
    except Exception as webex_auth_e:
        logger.critical(f"CRITICAL: Webex Bot Token is invalid or API is unreachable: {webex_auth_e}")
        exit(1)

    crowdstrike = CrowdStrikeClient()  # Consider adding error handling/validation if init can fail
    incident_handler = IncidentHandler()  # Consider adding error handling/validation
    list_handler = ListHandler()  # Consider adding error handling/validation

except Exception as init_e:
    logger.critical(f"CRITICAL: Failed to initialize required services: {init_e}", exc_info=True)
    exit(1)

# --- Adaptive Card Definitions ---

# Card for creating a new XSOAR ticket
NEW_TICKET_CARD = AdaptiveCard(
    body=[
        TextBlock(
            text="New XSOAR Ticket",
            color=Colors.ACCENT,
            weight=FontWeight.BOLDER,
            size=OPTIONS.FontSize.MEDIUM,
            horizontalAlignment=HorizontalAlignment.CENTER
        ),
        ColumnSet(columns=[
            Column(
                width=1,
                items=[
                    TextBlock(
                        text="Title",
                        wrap=True,
                        horizontalAlignment=HorizontalAlignment.RIGHT
                    )
                ]
            ),
            Column(
                width=6,
                items=[
                    INPUTS.Text(
                        id="title",
                        placeholder="Enter ticket title",
                        isRequired=True,
                        errorMessage="Title is required"
                    )
                ]
            )
        ]),
        ColumnSet(columns=[
            Column(
                width=1,
                items=[
                    TextBlock(
                        text="Details",
                        wrap=True,
                        horizontalAlignment=HorizontalAlignment.RIGHT
                    )
                ]
            ),
            Column(
                width=6,
                items=[
                    INPUTS.Text(
                        id="details",
                        placeholder="Enter ticket details",
                        isMultiline=True,
                        isRequired=True,
                        errorMessage="Details are required"
                    )
                ]
            )
        ], spacing=OPTIONS.Spacing.NONE)
    ]
)

# Card for submitting an IOC Hunt
IOC_HUNT = AdaptiveCard(
    body=[
        TextBlock(
            text="New IOC Hunt",
            color=Colors.ACCENT,
            weight=FontWeight.BOLDER,
            size=OPTIONS.FontSize.MEDIUM,
            horizontalAlignment=HorizontalAlignment.CENTER
        ),
        ColumnSet(columns=[
            Column(
                width=1,
                items=[
                    TextBlock(
                        text="Title:",
                        wrap=True,
                        horizontalAlignment=HorizontalAlignment.RIGHT
                    )
                ]
            ),
            Column(
                width=6,
                items=[
                    INPUTS.Text(
                        id="ioc_hunt_title",
                        placeholder="Enter hunt title",
                        isRequired=True,
                        errorMessage="Title is required"
                    )
                ]
            )
        ]),
        ColumnSet(columns=[
            Column(
                width=1,
                items=[
                    TextBlock(
                        text="IOCs:",
                        wrap=True,
                        horizontalAlignment=HorizontalAlignment.RIGHT
                    )
                ]
            ),
            Column(
                width=6,
                items=[
                    INPUTS.Text(
                        id="ioc_hunt_iocs",
                        placeholder="Domains, Emails, Hashes, IPs (comma or newline separated)",
                        isMultiline=True,
                        isRequired=True,
                        errorMessage="IOCs are required"
                    )
                ]
            )
        ]),
        ActionSet(
            actions=[
                Submit(
                    title="Submit Hunt",
                    data={"callback_keyword": "ioc_hunt"},
                    style=ActionStyle.POSITIVE
                )
            ]
        )
    ]
)

# Card for submitting a Threat Hunt
THREAT_HUNT = {
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "version": "1.3",
    "type": "AdaptiveCard",
    "body": [
        TextBlock(text="New Threat Hunt Request", color=Colors.ACCENT, weight=FontWeight.BOLDER, size=OPTIONS.FontSize.MEDIUM, horizontalAlignment=HorizontalAlignment.CENTER).to_dict(),
        TextBlock(text="Hunt Title:", wrap=True).to_dict(),
        INPUTS.Text(id="threat_hunt_title", isRequired=True, errorMessage="Title is required").to_dict(),
        TextBlock(text="Hunt Description / Hypothesis:", wrap=True).to_dict(),
        INPUTS.Text(id="threat_hunt_desc", isMultiline=True, isRequired=True, errorMessage="Description is required").to_dict(),
        ActionSet(
            spacing=OPTIONS.Spacing.DEFAULT,  # Use default spacing
            actions=[Submit(title="Submit Request", data={"callback_keyword": "threat_hunt"}, style=ActionStyle.POSITIVE)],
        ).to_dict()
    ]
}

# Card for creating an AZDO Work Item
AZDO_CARD = AdaptiveCard(
    body=[
        TextBlock(
            text="New Azure DevOps Work Item",
            color=Colors.ACCENT,
            weight=FontWeight.BOLDER,
            size=OPTIONS.FontSize.MEDIUM,
            horizontalAlignment=HorizontalAlignment.CENTER
        ),
        TextBlock(
            text="Title",
            color=Colors.DEFAULT
        ),
        INPUTS.Text(
            id="wit_title",
            isRequired=True,
            errorMessage="Title is required"
        ),
        TextBlock(
            text="Description",
            color=Colors.DEFAULT
        ),
        INPUTS.Text(
            id="wit_description",
            isMultiline=True,
            isRequired=True,
            errorMessage="Description is required"
        ),
        ColumnSet(
            columns=[
                Column(
                    items=[
                        TextBlock(
                            text="Type",
                            color=Colors.DEFAULT
                        ),
                        INPUTS.ChoiceSet(
                            wrap=True,
                            id="wit_type",
                            value="User%20Story",
                            choices=[
                                Choice(title="User Story", value="User%20Story"),
                                Choice(title="Bug", value="Bug"),
                                Choice(title="Task", value="Task")
                            ],
                            isRequired=True,
                            errorMessage="Type is required"
                        )
                    ]
                )
            ]
        )
    ]
)

RED_TEAM_TESTING_CARD = AdaptiveCard(
    body=[
        TextBlock(
            text="Red Team Testing",
            horizontalAlignment=HorizontalAlignment.CENTER,
            weight=FontWeight.BOLDER,
            size=OPTIONS.FontSize.MEDIUM,
            color=Colors.ACCENT
        ),
        ColumnSet(
            columns=[
                Column(
                    width=1,
                    items=[
                        TextBlock(
                            text="Username(s)",
                            horizontalAlignment=HorizontalAlignment.RIGHT
                        )
                    ],
                    verticalContentAlignment=OPTIONS.VerticalContentAlignment.CENTER
                ),
                Column(
                    width=3,
                    items=[
                        INPUTS.Text(
                            id="usernames",
                            placeholder="comma separated"
                        )
                    ]
                )
            ]
        ),
        ColumnSet(
            columns=[
                Column(
                    width=1,
                    items=[
                        TextBlock(
                            text="Hostname(s)",
                            horizontalAlignment=HorizontalAlignment.RIGHT
                        )
                    ],
                    verticalContentAlignment=OPTIONS.VerticalContentAlignment.CENTER
                ),
                Column(
                    width=3,
                    items=[
                        INPUTS.Text(
                            id="host_names",
                            placeholder="comma separated"
                        )
                    ]
                )
            ]
        )
    ]
)

# Card for importing a Prod ticket to Dev
TICKET_IMPORT_CARD = AdaptiveCard(
    body=[
        TextBlock(
            text="Import Prod Ticket to Dev", wrap=True, horizontalAlignment=HorizontalAlignment.CENTER,
            weight=FontWeight.BOLDER, color=Colors.ACCENT, size=OPTIONS.FontSize.MEDIUM
        ),
        ColumnSet(columns=[
            Column(
                items=[TextBlock(text="Prod ticket#", horizontalAlignment=HorizontalAlignment.RIGHT)],
                width="auto", verticalContentAlignment=OPTIONS.VerticalContentAlignment.CENTER
            ),
            Column(
                items=[INPUTS.Text(id="prod_ticket_number", placeholder="Enter prod ticket number (e.g., 12345)", isRequired=True, errorMessage='Prod ticket number is required')],
                width="stretch", verticalContentAlignment=OPTIONS.VerticalContentAlignment.CENTER
            )
        ]),
        ActionSet(actions=[Submit(title="Import Ticket", style=ActionStyle.POSITIVE, data={"callback_keyword": "import"})])  # Changed title
    ]
)

# Card for creating a Tuning Request
TUNING_REQUEST_CARD = AdaptiveCard(
    body=[
        TextBlock(
            text="New Tuning Request", wrap=True, horizontalAlignment=HorizontalAlignment.CENTER,
            weight=FontWeight.BOLDER, color=Colors.ACCENT, size=OPTIONS.FontSize.MEDIUM
        ),
        INPUTS.Text(id="title", label="Rule/Detection Title", isRequired=True, errorMessage="Title is required"),  # Updated label
        INPUTS.Text(id="description", label="Reason for Tuning / False Positive Details", isMultiline=True, isRequired=True, errorMessage="Description is required"),  # Updated label
        INPUTS.Text(id="tickets", placeholder="Comma-separated (e.g., 123, 456)", label="Recent Example XSOAR Ticket(s)", isRequired=True, errorMessage="At least one ticket number is required"),
        # Updated placeholder/label
        INPUTS.Text(id="ticket_volume", placeholder="Example: ~5 tickets/day", label="Approx. Ticket Volume", isRequired=True, errorMessage="Volume estimate is required"),  # Updated placeholder
        ActionSet(actions=[Submit(title="Submit Tuning Request", style=ActionStyle.POSITIVE, data={"callback_keyword": "tuning_request"})])  # Changed title
    ]
)

# --- All Options Card (Consolidated Actions) ---
# This card uses Action.ShowCard to present other cards as sub-menus
all_options_card = AdaptiveCard(
    body=[
        TextBlock(
            text=f"{DEFAULT_BOT_NAME} Options",
            weight=FontWeight.BOLDER,
            size=OPTIONS.FontSize.MEDIUM,
            horizontalAlignment=HorizontalAlignment.CENTER,
            color=Colors.ACCENT
        )
    ],
    actions=[
        ShowCard(
            title="Approved Testing",
            card=RED_TEAM_TESTING_CARD
        ),
        ShowCard(
            title="On Call",
            card=AdaptiveCard(
                body=[
                    TextBlock(
                        text="Get On-Call Information",
                        weight=FontWeight.BOLDER,
                        horizontalAlignment=HorizontalAlignment.CENTER
                    ),
                    ActionSet(
                        spacing=OPTIONS.Spacing.DEFAULT,
                        actions=[
                            Submit(title="Who is On Call?", data={"callback_keyword": "who"}),
                            Submit(title="Show Rotation", data={"callback_keyword": "rotation"})
                        ]
                    )
                ]
            )
        )
    ]
)


# --- Helper Functions ---

def get_url_card() -> dict:
    """Generates the Adaptive Card for Favorite URLs dynamically."""
    logger.debug(f"Attempting to retrieve XSOAR list: {URL_LIST_NAME}")
    try:
        metcirt_urls = list_handler.get_list_data_by_name(URL_LIST_NAME)
        # Ensure metcirt_urls is a list, even if empty
        if not isinstance(metcirt_urls, list):
            logger.error(f"Data retrieved for '{URL_LIST_NAME}' is not a list: {type(metcirt_urls)}. Treating as empty.")
            metcirt_urls = []

    except Exception as e:
        logger.error(f"Failed to retrieve XSOAR list '{URL_LIST_NAME}': {e}", exc_info=True)
        return AdaptiveCard(body=[TextBlock(text=f"Error retrieving favorite URLs: {e}", wrap=True, color=Colors.ATTENTION)]).to_dict()

    actions = []
    body_items = [TextBlock(text="Favorite URLs & Contacts", weight=FontWeight.BOLDER, horizontalAlignment=HorizontalAlignment.CENTER)]

    for item in metcirt_urls:
        if not isinstance(item, dict):
            logger.warning(f"Skipping non-dictionary item in '{URL_LIST_NAME}' list: {item}")
            continue

        name = item.get('name')
        url = item.get('url')
        phone = item.get('phone_number')

        if name and url:
            # Use Action.OpenUrl for URLs
            actions.append({"type": "Action.OpenUrl", "title": name, "url": url, "style": "default"})  # Use default style

        elif name and phone:
            # Display phone numbers as simple text blocks in the body
            body_items.append(TextBlock(text=f"**{name}:** {phone}", wrap=True, spacing=OPTIONS.Spacing.SMALL))

        else:
            logger.warning(f"Skipping item with missing name/url/phone in '{URL_LIST_NAME}' list: {item}")

    logger.debug(f"Generated URL card with {len(body_items)} body items and {len(actions)} actions.")
    return AdaptiveCard(body=body_items).to_dict()


# Generate the URL card once at startup
URL_CARD = get_url_card()


def announce_webex(room_id: str, markdown_message: str, fallback_text: str, card_payload: dict = None) -> None:
    """Sends a message (and optionally a card) to a specific Webex room."""
    if not room_id:
        logger.warning(f"Cannot send announcement: Room ID is missing. Fallback text: {fallback_text}")
        return
    if not CONFIG.webex_bot_access_token_toodles:
        logger.error("Cannot send announcement: Webex Bot Token is missing.")
        return

    try:
        attachments = []
        if card_payload:
            attachments.append({"contentType": "application/vnd.microsoft.card.adaptive", "content": card_payload})

        webex_api.messages.create(
            roomId=room_id,
            markdown=markdown_message,
            text=fallback_text,  # Fallback for clients that don't render markdown/cards
            attachments=attachments if attachments else None
        )
        logger.info(f"Sent announcement to room ID {room_id}: {fallback_text}")
    except Exception as e:
        logger.error(f"Failed to send announcement to room ID {room_id}: {e}", exc_info=True)


def announce_new_approved_testing_entry(new_item: dict) -> None:
    """Sends an Adaptive Card notification about a new approved testing entry."""
    room_id = getattr(CONFIG, 'webex_room_id_gosc_t2', None)
    if not room_id:
        logger.warning("Cannot announce new approved testing: webex_room_id_gosc_t2 not configured.")
        return

    # Format values for display, handling None or empty strings
    submitter = new_item.get('submitter', 'N/A')
    description = new_item.get('description', 'N/A')
    usernames = new_item.get('usernames') or "_None_"
    host_names = new_item.get('host_names') or "_None_"
    ip_addresses = new_item.get('ip_addresses') or "_None_"
    scope = new_item.get('scope', 'N/A')
    expiry_date = new_item.get('expiry_date', 'N/A')

    card_payload = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.3",
        "body": [
            TextBlock(
                text="New Approved Testing Entry", size=OPTIONS.FontSize.MEDIUM, weight=OPTIONS.FontWeight.BOLDER,
                color=Colors.ATTENTION, horizontalAlignment=HorizontalAlignment.CENTER
            ).to_dict(),
            {  # Using FactSet for structured display
                "type": "FactSet",
                "facts": [
                    {"title": "Submitter:", "value": submitter},
                    {"title": "Description:", "wrap": True, "value": description},
                    {"title": "Username(s):", "wrap": True, "value": usernames},
                    {"title": "Hostname(s):", "wrap": True, "value": host_names},
                    {"title": "IP address(es):", "wrap": True, "value": ip_addresses},
                    {"title": "Scope:", "wrap": True, "value": scope},
                    {"title": "Expires:", "value": f"{expiry_date} at {DEFAULT_EXPIRY_TIME_DESC}"}
                ],
                "spacing": OPTIONS.Spacing.DEFAULT  # Added spacing
            },
            ActionSet(
                spacing=OPTIONS.Spacing.DEFAULT,
                actions=[Submit(title="Get Current List", data={"callback_keyword": "current_approved_testing"})],
            ).to_dict()
        ]
    }

    fallback_text = f"New Approved Testing entry added by {submitter} (Expires: {expiry_date})."
    markdown_message = f"**New Approved Testing Entry Added**\n**Submitter:** {submitter}\n**Expires:** {expiry_date} at {DEFAULT_EXPIRY_TIME_DESC}"

    announce_webex(room_id, markdown_message, fallback_text, card_payload)


def add_entry_to_reviews(review_list: list, ticket_id: str, person: str, date_str: str, message: str):
    """Appends a review entry dictionary to the provided list."""
    if not all([ticket_id, person, date_str, message]):
        logger.warning("Attempted to add incomplete review entry.")
        return  # Avoid adding incomplete data
    review_list.append({"ticket_id": ticket_id, "by": person, "date": date_str, "message": message})
    logger.info(f"Review entry prepared for ticket {ticket_id} by {person}")


def announce_new_threat_hunt(ticket_no: str, ticket_title: str, incident_url: str, person_id: str):
    """Announces a new threat hunt ticket in the designated Webex room."""
    logger.debug(f"Attempting to announce new threat hunt: Ticket {ticket_no}")
    try:
        webex_config = list_handler.get_list_data_by_name(WEBEX_CONFIG_LIST_NAME)
        if not isinstance(webex_config, dict):
            logger.error(f"Invalid format for '{WEBEX_CONFIG_LIST_NAME}' list data: {webex_config}")
            return

        threat_hunt_room_id = webex_config.get("channels", {}).get("threat_hunt")

        if not threat_hunt_room_id:
            logger.warning(f"Cannot announce threat hunt: Threat hunt channel ID not found in '{WEBEX_CONFIG_LIST_NAME}' list under channels.threat_hunt.")
            return

        markdown_message = (
            f"<@personId:{person_id}> created a new Threat Hunt in XSOAR Prod: "
            f"**[#{ticket_no}]({incident_url})** - {ticket_title}"
        )
        fallback_text = f"New Threat Hunt created by user {person_id}: Ticket #{ticket_no} - {ticket_title}"

        announce_webex(threat_hunt_room_id, markdown_message, fallback_text)
        logger.info(f"Announced new threat hunt {ticket_no} created by personId {person_id}")

    except Exception as e:
        logger.error(f"Error retrieving Webex config or announcing threat hunt {ticket_no}: {e}", exc_info=True)


# --- Command Classes ---

class URLs(Command):
    """Displays a card with favorite URLs and contact numbers."""

    def __init__(self):
        super().__init__(
            command_keyword="urls",
            help_message="Show favorite URLs and contacts",
            card=URL_CARD,  # Use pre-generated card
        )

    @log_moneyball_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        """Executes the URLs command."""
        # Card is displayed automatically by the framework.
        logger.debug(f"Executing URLs command for user {activity.get('actor', {}).get('emailAddress')}")
        pass  # Card display is handled by the bot framework


class GetNewXTicketForm(Command):
    """Displays the card to create a new XSOAR ticket."""

    def __init__(self):
        super().__init__(
            card=NEW_TICKET_CARD,
            command_keyword="newticket",  # Simple keyword
            help_message="Open form to create a new XSOAR ticket",
        )

    @log_moneyball_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        """Executes the GetNewXTicketForm command."""
        logger.debug(f"Executing GetNewXTicketForm command for user {activity.get('actor', {}).get('emailAddress')}")
        pass  # Card display is handled by the bot framework


class CreateXSOARTicket(Command):
    """Handles the submission of the new XSOAR ticket form."""

    def __init__(self):
        super().__init__(
            command_keyword="create_x_ticket",  # Matches callback_keyword in card
            card=None,  # This command only processes the submission
            help_message="Processes the new XSOAR ticket form submission (internal).",
        )

    @log_moneyball_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        """Executes the CreateXSOARTicket command."""
        if not attachment_actions or not hasattr(attachment_actions, 'inputs'):
            logger.warning("CreateXSOARTicket executed without attachment actions or inputs.")
            return "Error: Could not process ticket creation due to missing form data."

        try:
            inputs = attachment_actions.inputs
            title = inputs.get('title', '').strip()
            details = inputs.get('details', '').strip()
            detection_source = inputs.get('detection_source')  # Required field in card

            if not title or not details or not detection_source:
                missing = [field for field, value in [("Title", title), ("Details", details), ("Detection Source", detection_source)] if not value]
                logger.warning(f"CreateXSOARTicket submission missing fields: {missing}")
                return f"Error: Please fill in the required fields: {', '.join(missing)}."

            submitter_email = activity.get('actor', {}).get('emailAddress', 'Unknown User')
            incident_payload = {
                'name': title,
                'details': f"{details}\n\nSubmitted via Webex Bot by: {submitter_email}",
                'CustomFields': {
                    'detectionsource': detection_source,
                    'isusercontacted': False,  # Default value
                    'securitycategory': 'CAT-5: Scans/Probes/Attempted Access'  # Default value
                },
                'type': 'Incident'  # Explicitly set type
            }

            logger.info(f"Attempting to create XSOAR ticket: '{title}' by {submitter_email}")
            result = incident_handler.create(incident_payload)  # Assuming create returns a dict or raises error

            new_incident_id = result.get('id')
            if not new_incident_id:
                logger.error(f"Failed to create XSOAR ticket. API Response: {result}")
                return "Error: Failed to create the ticket in XSOAR. The response did not contain an ID."

            # Construct URL safely
            base_url = getattr(CONFIG, 'xsoar_prod_ui_base_url', '').rstrip('/')
            if not base_url:
                logger.error("XSOAR Prod UI Base URL is not configured. Cannot generate ticket link.")
                incident_url_md = f"XSOAR Prod Ticket #{new_incident_id}"  # No link possible
            else:
                incident_url = f"{base_url}/Custom/caseinfoid/{new_incident_id}"
                incident_url_md = f"[#{new_incident_id}]({incident_url})"  # Markdown link

            logger.info(f"Successfully created XSOAR ticket #{new_incident_id}")
            return f"Ticket {incident_url_md} created successfully in XSOAR Prod."

        except KeyError as e:
            logger.error(f"Missing expected input field in CreateXSOARTicket submission: {e}", exc_info=True)
            return f"Error: Missing required form field '{e}'. Please try again."
        except Exception as e:
            logger.error(f"Error creating XSOAR ticket: {e}", exc_info=True)
            return f"An unexpected error occurred while creating the ticket: {e}"


class IOC(Command):
    """Displays the card for submitting an IOC Hunt."""

    def __init__(self):
        super().__init__(
            command_keyword="ioc",
            help_message="Open form to submit an IOC Hunt",
            card=IOC_HUNT,
        )

    @log_moneyball_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        """Executes the IOC command."""
        logger.debug(f"Executing IOC command for user {activity.get('actor', {}).get('emailAddress')}")
        pass  # Card display is handled by the bot framework


class IOCHunt(Command):
    """Handles the submission of the IOC Hunt form."""

    def __init__(self):
        super().__init__(
            command_keyword="ioc_hunt",  # Matches callback_keyword
            card=None,
            help_message="Processes the IOC Hunt form submission (internal)."
        )

    @log_moneyball_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        """Executes the IOCHunt command."""
        if not attachment_actions or not hasattr(attachment_actions, 'inputs'):
            logger.warning("IOCHunt executed without attachment actions or inputs.")
            return "Error: Could not process IOC Hunt creation due to missing form data."

        try:
            inputs = attachment_actions.inputs
            title = inputs.get('ioc_hunt_title', '').strip()
            iocs = inputs.get('ioc_hunt_iocs', '').strip()
            submitter_email = activity.get('actor', {}).get('emailAddress', 'Unknown User')

            if not title or not iocs:
                missing = [field for field, value in [("Title", title), ("IOCs", iocs)] if not value]
                logger.warning(f"IOCHunt submission missing fields: {missing}")
                return f"Error: Please fill in the required fields: {', '.join(missing)}."

            incident_payload = {
                'name': f"IOC Hunt: {title}",  # Prefix title for clarity
                'details': f"{iocs}\n\nSubmitted via Webex Bot by: {submitter_email}",
                'type': "METCIRT IOC Hunt"  # Specific type
            }

            logger.info(f"Attempting to create IOC Hunt ticket: '{title}' by {submitter_email}")
            # Assuming create returns a list with one dict, or raises error
            result = incident_handler.create(incident_payload)

            if not isinstance(result, list) or not result:
                logger.error(f"Failed to create IOC Hunt ticket. Unexpected API response format: {result}")
                return "Error: Failed to create IOC Hunt ticket. Unexpected response from XSOAR."

            ticket_info = result[0]
            if not isinstance(ticket_info, dict):
                logger.error(f"Failed to create IOC Hunt ticket. Unexpected item format in API response list: {ticket_info}")
                return "Error: Failed to create IOC Hunt ticket. Invalid item format in response."

            ticket_no = ticket_info.get('id')
            if not ticket_no:
                logger.error(f"Failed to create IOC Hunt ticket. API Response item missing ID: {ticket_info}")
                return "Error: Failed to create the IOC Hunt ticket. Response item did not contain an ID."

            # Construct URL safely
            base_url = getattr(CONFIG, 'xsoar_prod_ui_base_url', '').rstrip('/')
            if not base_url:
                logger.error("XSOAR Prod UI Base URL is not configured. Cannot generate ticket link.")
                incident_url_md = f"XSOAR Prod Ticket #{ticket_no}"  # No link possible
            else:
                # Assuming direct ID works for the URL path for IOC Hunts
                incident_url = f"{base_url}/{ticket_no}"
                incident_url_md = f"[#{ticket_no}]({incident_url})"  # Markdown link

            logger.info(f"Successfully created IOC Hunt ticket #{ticket_no}")
            return f"IOC Hunt ticket {incident_url_md} created successfully in XSOAR Prod."

        except (KeyError, IndexError) as e:
            logger.error(f"Missing expected input/data or index error in IOCHunt: {e}", exc_info=True)
            return f"Error: Missing required form field or invalid response structure ('{e}'). Please try again."
        except Exception as e:
            logger.error(f"Error creating IOC Hunt ticket: {e}", exc_info=True)
            return f"An unexpected error occurred while creating the IOC Hunt ticket: {e}"


class ThreatHuntCard(Command):
    """Displays the card for submitting a Threat Hunt."""

    def __init__(self):
        super().__init__(
            command_keyword="threat",
            help_message="Open form to submit a Threat Hunt request",
            card=THREAT_HUNT,
        )

    @log_moneyball_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        """Executes the ThreatHuntCard command."""
        logger.debug(f"Executing ThreatHuntCard command for user {activity.get('actor', {}).get('emailAddress')}")
        pass  # Card display is handled by the bot framework


class ThreatHunt(Command):
    """Handles the submission of the Threat Hunt form."""

    def __init__(self):
        super().__init__(
            command_keyword="threat_hunt",  # Matches callback_keyword
            card=None,
            help_message="Processes the Threat Hunt form submission (internal)."
        )

    @log_moneyball_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        """Executes the CreateThreatHunt command."""
        if not attachment_actions or not hasattr(attachment_actions, 'inputs') or not hasattr(attachment_actions, 'personId'):
            logger.warning("CreateThreatHunt executed without attachment actions, inputs, or personId.")
            return "Error: Could not process Threat Hunt creation due to missing form data or submitter ID."

        try:
            inputs = attachment_actions.inputs
            title = inputs.get('threat_hunt_title', '').strip()
            description = inputs.get('threat_hunt_desc', '').strip()
            submitter_email = activity.get('actor', {}).get('emailAddress', 'Unknown User')
            person_id = attachment_actions.personId  # Used for announcement

            if not title or not description:
                missing = [field for field, value in [("Title", title), ("Description", description)] if not value]
                logger.warning(f"CreateThreatHunt submission missing fields: {missing}")
                return f"Error: Please fill in the required fields: {', '.join(missing)}."

            incident_payload = {
                'name': f"Threat Hunt: {title}",  # Prefix title
                'details': f"{description}\n\nSubmitted via Webex Bot by: {submitter_email}",
                'type': "Threat Hunt"  # Specific type
            }

            logger.info(f"Attempting to create Threat Hunt ticket: '{title}' by {submitter_email}")
            # Assuming create returns a list with one dict, or raises error
            result = incident_handler.create(incident_payload)

            if not isinstance(result, list) or not result:
                logger.error(f"Failed to create Threat Hunt ticket. Unexpected API response format: {result}")
                return "Error: Failed to create Threat Hunt ticket. Unexpected response from XSOAR."

            ticket_info = result[0]
            if not isinstance(ticket_info, dict):
                logger.error(f"Failed to create Threat Hunt ticket. Unexpected item format in API response list: {ticket_info}")
                return "Error: Failed to create Threat Hunt ticket. Invalid item format in response."

            ticket_no = ticket_info.get('id')
            if not ticket_no:
                logger.error(f"Failed to create Threat Hunt ticket. API Response item missing ID: {ticket_info}")
                return "Error: Failed to create the Threat Hunt ticket. Response item did not contain an ID."

            # Construct URL safely
            base_url = getattr(CONFIG, 'xsoar_prod_ui_base_url', '').rstrip('/')
            if not base_url:
                logger.error("XSOAR Prod UI Base URL is not configured. Cannot generate ticket link.")
                incident_url = None  # No link possible
                incident_url_md = f"XSOAR Prod Ticket #{ticket_no}"
            else:
                # Assuming direct ID works for the URL path for Threat Hunts
                incident_url = f"{base_url}/{ticket_no}"
                incident_url_md = f"[#{ticket_no}]({incident_url})"  # Markdown link

            logger.info(f"Successfully created Threat Hunt ticket #{ticket_no}")

            # Announce the new ticket (only if URL could be constructed)
            if incident_url:
                announce_new_threat_hunt(ticket_no, title, incident_url, person_id)
            else:
                logger.warning(f"Skipped announcement for Threat Hunt {ticket_no} due to missing base URL config.")

            # Return confirmation to the user who submitted
            return f"Threat Hunt ticket {incident_url_md} created successfully."

        except (KeyError, IndexError) as e:
            logger.error(f"Missing expected input/data or index error in CreateThreatHunt: {e}", exc_info=True)
            return f"Error: Missing required form field or invalid response structure ('{e}'). Please try again."
        except Exception as e:
            logger.error(f"Error creating Threat Hunt ticket: {e}", exc_info=True)
            return f"An unexpected error occurred while creating the Threat Hunt ticket: {e}"


class CreateAZDOWorkItem(Command):
    """Handles the submission of the AZDO Work Item form."""

    def __init__(self):
        super().__init__(
            command_keyword="azdo",  # Simplified keyword
            help_message="Create an Azure DevOps Work Item",
            card=AZDO_CARD,  # Show card on direct command
        )

    @log_moneyball_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        """Executes the CreateAZDOWorkItem command."""
        # If attachment_actions is None, user typed command -> show card (handled by framework)
        if attachment_actions is None:
            logger.debug(f"Executing CreateAZDOWorkItem command (showing card) for user {activity.get('actor', {}).get('emailAddress')}")
            return None

        # If attachment_actions is not None, user submitted the card -> process it
        logger.debug(f"Processing CreateAZDOWorkItem card submission by user {activity.get('actor', {}).get('emailAddress')}")
        try:
            inputs = attachment_actions.inputs
            wit_title = inputs.get('wit_title', '').strip()
            wit_type_encoded = inputs.get('wit_type')  # e.g., "User%20Story"
            wit_description = inputs.get('wit_description', '').strip()
            project_key = inputs.get('project')  # e.g., "platforms", "re"
            submitter_display_name = activity.get('actor', {}).get('displayName', 'Unknown User')

            # --- Input Validation ---
            if not all([wit_title, wit_type_encoded, wit_description, project_key]):
                missing = [field for field, value in [("Title", wit_title), ("Type", wit_type_encoded), ("Description", wit_description), ("Project", project_key)] if not value]
                logger.warning(f"CreateAZDOWorkItem submission missing fields: {missing}")
                return f"Error: Please fill in the required fields: {', '.join(missing)}."

            # --- Determine Project Specifics ---
            assignee = None
            parent_url = None
            area_path = None
            azdo_org = azdo_orgs.get(project_key)
            azdo_project_name = azdo_projects.get(project_key)  # Name for URL

            if not azdo_org or not azdo_project_name:
                logger.error(f"AZDO config missing for project key '{project_key}'. Check data_maps (azdo_orgs, azdo_projects).")
                return f"Error: Configuration missing for project '{project_key}'. Cannot create work item."

            # Project specific logic (Assignee, Parent Link, Area Path)
            if project_key == 'platforms':
                assignee = getattr(CONFIG, 'my_email_address', None)  # Ensure this is configured
                parent_url = getattr(CONFIG, 'azdo_platforms_parent_url', None)  # Ensure this is configured
                area_path = azdo_area_paths.get('platforms')  # Check if platforms has a specific area path
                if not assignee: logger.warning("Assignee (my_email_address) not configured for 'platforms' project.")
                if not parent_url: logger.warning("Parent URL (azdo_platforms_parent_url) not configured for 'platforms' project.")
            elif project_key == 're':
                area_path = azdo_area_paths.get('re')
            elif project_key == 'de':
                area_path = azdo_area_paths.get('de')
            elif project_key == 'gdr':
                area_path = azdo_area_paths.get('gdr')
            # Add more project-specific logic as needed

            if not area_path and project_key not in ['platforms']:  # Platforms might not require area path if using parent link
                logger.warning(f"Area path not found for project key '{project_key}' in data_maps (azdo_area_paths).")
                # Decide if this is critical - maybe proceed without it? For now, warn.

            wit_type_display = wit_type_encoded.replace('%20', ' ')  # For logging/display
            logger.info(f"Attempting to create AZDO {wit_type_display} '{wit_title}' in {project_key} by {submitter_display_name}")

            # --- Create Work Item ---
            wit_id = azdo.create_wit(
                title=wit_title,
                description=wit_description,
                item_type=wit_type_encoded,  # Pass the encoded type
                project=project_key,  # Pass the key
                submitter=submitter_display_name,
                assignee=assignee,
                parent_url=parent_url,
                area_path=area_path
            )

            if not wit_id:  # Check if creation failed
                logger.error(f"azdo.create_wit failed for title '{wit_title}' in project {project_key}.")
                return "Error: Failed to create the work item in Azure DevOps. Check service logs."

            # --- Format Response ---
            # Use quote() on the project name for the URL
            azdo_wit_url = f'https://dev.azure.com/{azdo_org}/{quote(azdo_project_name)}/_workitems/edit/{wit_id}'
            return_message = f'AZDO {wit_type_display} created: [{wit_id}]({azdo_wit_url}) - {wit_title}'  # Markdown link

            logger.info(f"Successfully created AZDO work item {wit_id}")

            # --- Announce (Optional) ---
            announce_room_id = getattr(CONFIG, 'webex_room_id_automation_engineering', None)
            if announce_room_id:
                announce_md = f"{submitter_display_name} created a new AZDO {wit_type_display}: [{wit_id}]({azdo_wit_url}) - {wit_title}"  # Markdown link
                announce_fallback = f"New AZDO {wit_type_display} created by {submitter_display_name}: WIT {wit_id} - {wit_title}"
                announce_webex(announce_room_id, announce_md, announce_fallback)
            else:
                logger.warning("Cannot announce AZDO WIT: webex_room_id_automation_engineering not configured.")

            return return_message

        except KeyError as e:
            logger.error(f"Missing expected input field in CreateAZDOWorkItem submission: {e}", exc_info=True)
            return f"Error: Missing required form field '{e}'. Please try again."
        except Exception as e:
            logger.error(f"Error creating AZDO work item: {e}", exc_info=True)
            return f"An unexpected error occurred while creating the AZDO work item: {e}"


class Review(Command):
    """Adds a ticket number and comments to the 'review' list in XSOAR."""

    def __init__(self):
        super().__init__(
            command_keyword="review",  # Keyword used in card callbacks
            card=None,  # This command processes data from another card's context
            help_message="Adds a ticket to the review list (requires context from another card)."
        )

    @log_moneyball_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        """Executes the Review command."""
        # This command depends on context from another card providing "review_notes" and "incident_id".
        if attachment_actions is None or not hasattr(attachment_actions, 'inputs'):
            logger.warning("Review command executed without attachment actions or inputs.")
            return "This command requires input from a card submission (e.g., from a ticket details card)."

        inputs = attachment_actions.inputs
        review_notes = inputs.get("review_notes", "").strip()
        ticket_no = inputs.get("incident_id", "").strip()
        submitter_email = activity.get('actor', {}).get('emailAddress', 'Unknown User')

        try:

            if not review_notes:
                logger.warning(f"Review submission failed for ticket {ticket_no} by {submitter_email}: No review notes provided.")
                return "Error: Please add review notes before submitting."
            if not ticket_no:
                logger.warning(f"Review submission failed by {submitter_email}: Incident ID is missing.")
                return "Error: Incident ID is missing. Cannot add to review list."

            # Use ISO format for date consistency
            curr_date_str = datetime.now().strftime("%Y-%m-%d")

            logger.info(f"Attempting to add ticket {ticket_no} to review list '{REVIEW_LIST_NAME}' by {submitter_email}")

            # --- Get and Update List ---
            try:
                # Fetch the current list data. Assume it returns {'Tickets': [...]} or raises error
                list_data = list_handler.get_list_data_by_name(REVIEW_LIST_NAME)

                # Ensure the structure is {'Tickets': list}
                if not isinstance(list_data, dict) or 'Tickets' not in list_data:
                    logger.warning(f"Unexpected format for '{REVIEW_LIST_NAME}' list data: {list_data}. Initializing.")
                    review_list = []
                    list_data = {'Tickets': review_list}
                else:
                    review_list = list_data['Tickets']
                    if not isinstance(review_list, list):
                        logger.error(f"'Tickets' key in '{REVIEW_LIST_NAME}' is not a list: {type(review_list)}. Resetting.")
                        review_list = []
                        list_data['Tickets'] = review_list

            except Exception as get_e:
                logger.error(f"Failed to get XSOAR list '{REVIEW_LIST_NAME}': {get_e}", exc_info=True)
                # If list doesn't exist, maybe create it? For now, error out.
                return f"Error: Could not retrieve the '{REVIEW_LIST_NAME}' list from XSOAR: {get_e}"

            # Add the new entry using the helper function
            add_entry_to_reviews(review_list, ticket_no, submitter_email, curr_date_str, review_notes)

            # Save the updated list data (pass the whole structure back)
            try:
                list_handler.save(REVIEW_LIST_NAME, list_data)  # Pass name and updated data object
                logger.info(f"Successfully added ticket {ticket_no} to '{REVIEW_LIST_NAME}' list.")
                return f"Ticket {ticket_no} has been added to the review list."
            except Exception as save_e:
                logger.error(f"Failed to save updated '{REVIEW_LIST_NAME}' list: {save_e}", exc_info=True)
                return f"Error: Failed to save the updated review list to XSOAR: {save_e}"

        except KeyError as e:
            logger.error(f"Missing expected input field in Review command submission: {e}", exc_info=True)
            return f"Error: Missing required field '{e}' in submission."
        except Exception as e:
            logger.error(f"Error processing review submission for ticket {ticket_no}: {e}", exc_info=True)
            return f"An unexpected error occurred while adding the ticket to the review list: {e}"


class GetApprovedTestingCard(Command):
    """Displays the card for managing Approved Testing entries."""

    def __init__(self):
        super().__init__(
            command_keyword="testing",
            help_message="Red Team Testing",
            card=RED_TEAM_TESTING_CARD,
        )

    @log_moneyball_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        """Executes the GetApprovedTestingCard command."""
        logger.debug(f"Executing GetApprovedTestingCard command for user {activity.get('actor', {}).get('emailAddress')}")
        pass  # Card display is handled by the bot framework


class GetCurrentApprovedTestingEntries(Command):
    """Retrieves and displays the current approved testing entries."""

    def __init__(self):
        super().__init__(
            command_keyword="current_approved_testing",  # Matches callback_keyword
            card=None,
            help_message="Shows the current approved testing entries (internal)."
        )

    @log_moneyball_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        """Executes the GetCurrentApprovedTestingEntries command."""
        submitter_name = activity.get('actor', {}).get('displayName', 'User')
        logger.info(f"Retrieving current approved testing entries for {submitter_name}")
        try:
            approved_test_items = list_handler.get_list_data_by_name(APPROVED_TESTING_LIST_NAME)

            # Validate structure
            expected_keys = ["USERNAMES", "ENDPOINTS", "IP_ADDRESSES"]
            if not isinstance(approved_test_items, dict) or not all(k in approved_test_items for k in expected_keys):
                logger.error(f"Invalid format for '{APPROVED_TESTING_LIST_NAME}' list data: {approved_test_items}")
                return f"Error: The approved testing list ('{APPROVED_TESTING_LIST_NAME}') has an unexpected format or is missing required keys ({', '.join(expected_keys)})."

            response_data = {"USERNAMES": [], "ENDPOINTS": [], "IP_ADDRESSES": []}
            has_entries = False

            # Helper to format date safely for Markdown
            def reformat_date_md(date_str):
                if not date_str: return "No Date"
                try:
                    # Assuming stored format is YYYY-MM-DD
                    return datetime.strptime(date_str, "%Y-%m-%d").strftime("%m/%d/%Y")
                except (ValueError, TypeError):
                    logger.warning(f"Could not parse date in GetCurrentApprovedTestingEntries: {date_str}")
                    return date_str  # Return original if parsing fails

            # Populate response_data safely
            for category, items in approved_test_items.items():
                if category in response_data and isinstance(items, list):
                    for item in items:
                        if isinstance(item, dict):
                            data = item.get('data', '').strip()
                            expiry_date_str = reformat_date_md(item.get('expiry_date'))
                            if data:  # Only add if data exists
                                response_data[category].append(f"{data} (Expires: {expiry_date_str})")
                                has_entries = True
                        else:
                            logger.warning(f"Skipping non-dict item in category {category} of '{APPROVED_TESTING_LIST_NAME}': {item}")
                # Allow extra keys, but log if expected keys have wrong type
                elif category in expected_keys and not isinstance(items, list):
                    logger.warning(f"Expected key '{category}' in '{APPROVED_TESTING_LIST_NAME}' is not a list: {type(items)}")
                elif category not in expected_keys:
                    logger.debug(f"Ignoring unexpected category '{category}' in '{APPROVED_TESTING_LIST_NAME}'.")

            if not has_entries:
                logger.info(f"No active approved testing entries found for {submitter_name}.")
                return f"{submitter_name}, there are currently no active Approved Security Testing entries."

            # --- Build Markdown Table ---
            # Calculate max widths safely, handling empty lists
            un_list = response_data.get('USERNAMES', [])
            ep_list = response_data.get('ENDPOINTS', [])
            ip_list = response_data.get('IP_ADDRESSES', [])

            # Add column titles to lists before calculating max width to ensure title fits
            username_col_width = max(len(item) for item in un_list + ['USERNAMES']) if un_list else len('USERNAMES')
            endpoint_col_width = max(len(item) for item in ep_list + ['HOSTNAMES']) if ep_list else len('HOSTNAMES')
            ip_col_width = max(len(item) for item in ip_list + ['IP ADDRESSES']) if ip_list else len('IP ADDRESSES')

            # Header
            header = f"| {'USERNAMES'.ljust(username_col_width)} | {'HOSTNAMES'.ljust(endpoint_col_width)} | {'IP ADDRESSES'.ljust(ip_col_width)} |"
            separator = f"|{'-' * (username_col_width + 2)}|{'-' * (endpoint_col_width + 2)}|{'-' * (ip_col_width + 2)}|"

            table_rows = [header, separator]

            # Find max number of rows needed
            max_rows = max(len(un_list), len(ep_list), len(ip_list))

            # Build rows
            for i in range(max_rows):
                user = un_list[i].ljust(username_col_width) if i < len(un_list) else " " * username_col_width
                host = ep_list[i].ljust(endpoint_col_width) if i < len(ep_list) else " " * endpoint_col_width
                ip = ip_list[i].ljust(ip_col_width) if i < len(ip_list) else " " * ip_col_width
                table_rows.append(f"| {user} | {host} | {ip} |")

            # Footer and final message
            footer = f"*Entries expire at {DEFAULT_EXPIRY_TIME_DESC} on the date shown."
            # Combine message parts with Markdown code block for table
            full_message = (
                f"{submitter_name}, here are the current Approved Security Testing entries:\n"
                f"```\n{table_rows}\n{footer}\n```"
            )

            logger.info(f"Successfully retrieved and formatted {max_rows} approved testing entries for {submitter_name}.")
            return full_message

        except Exception as e:
            logger.error(f"Error getting current approved testing entries: {e}", exc_info=True)
            return f"An unexpected error occurred while retrieving the approved testing entries: {e}"


class AddApprovedTestingEntry(Command):
    """Handles adding new entries to the approved testing lists."""

    def __init__(self):
        super().__init__(
            command_keyword="add_approved_testing",  # Matches callback_keyword
            card=None,
            help_message="Adds entries to the approved testing list (internal)."
        )

    @log_moneyball_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        """Executes the AddApprovedTestingEntry command."""
        if not attachment_actions or not hasattr(attachment_actions, 'inputs'):
            logger.warning("AddApprovedTestingEntry executed without attachment actions or inputs.")
            return "Error: Could not process adding entry due to missing form data."

        try:
            inputs = attachment_actions.inputs
            usernames_raw = inputs.get('usernames', '').strip()
            host_names_raw = inputs.get('host_names', '').strip()
            ip_addresses_raw = inputs.get('ip_addresses', '').strip()
            description = inputs.get('description', '').strip()
            scope = inputs.get('scope', '').strip()
            expiry_date_input = inputs.get('expiry_date', '').strip()  # YYYY-MM-DD from card
            submitter_email = activity.get('actor', {}).get('emailAddress', 'Unknown User')
            submitter_name = activity.get('actor', {}).get('displayName', 'Unknown User')  # For return message

            # --- Validation ---
            if not any([usernames_raw, host_names_raw, ip_addresses_raw]):
                logger.warning(f"AddApprovedTestingEntry submission failed by {submitter_email}: No identifiers provided.")
                return "Error: At least one of Username(s), Hostname(s), or IP(s) must be provided."
            if not description:
                logger.warning(f"AddApprovedTestingEntry submission failed by {submitter_email}: Description missing.")
                return "Error: Description is required."
            if not scope:
                logger.warning(f"AddApprovedTestingEntry submission failed by {submitter_email}: Scope missing.")
                return "Error: Scope is required."

            # --- Process Expiry Date ---
            try:
                if expiry_date_input:
                    # Validate date format YYYY-MM-DD
                    expiry_dt = datetime.strptime(expiry_date_input, "%Y-%m-%d")
                    expiry_date_str = expiry_dt.strftime("%Y-%m-%d")  # Ensure consistent format
                else:
                    # Default to tomorrow if not provided
                    expiry_dt = datetime.now(timezone(DEFAULT_TIMEZONE)) + timedelta(days=1)
                    expiry_date_str = expiry_dt.strftime("%Y-%m-%d")
                    logger.info(f"Expiry date not provided by {submitter_email}, defaulting to {expiry_date_str}")
            except ValueError:
                logger.warning(f"Invalid date format '{expiry_date_input}' provided by {submitter_email}.")
                return f"Error: Invalid date format for 'Keep until'. Please use YYYY-MM-DD (e.g., {datetime.now().strftime('%Y-%m-%d')})."

            # --- Process Input Lists (Handle commas/newlines, filter empty strings) ---
            def split_and_strip(raw_input):
                if not raw_input: return []
                # Split by comma or newline, strip whitespace, filter empty results
                return [item.strip() for item in raw_input.replace('\n', ',').split(',') if item.strip()]

            usernames_list = split_and_strip(usernames_raw)
            host_names_list = split_and_strip(host_names_raw)
            ip_addresses_list = split_and_strip(ip_addresses_raw)

            if not any([usernames_list, host_names_list, ip_addresses_list]):
                logger.warning(f"AddApprovedTestingEntry submission by {submitter_email} resulted in empty lists after processing inputs.")
                return "Error: No valid Usernames, Hostnames, or IPs were provided after processing."  # Should be caught earlier, but safety check

            logger.info(f"Processing AddApprovedTestingEntry by {submitter_email}: "
                        f"Users={usernames_list}, Hosts={host_names_list}, IPs={ip_addresses_list}, "
                        f"Desc='{description[:50]}...', Scope='{scope}', Expires={expiry_date_str}")

            # --- Get Current Lists ---
            try:
                current_entries = list_handler.get_list_data_by_name(APPROVED_TESTING_LIST_NAME)
                # Basic validation of structure
                expected_keys = ["USERNAMES", "ENDPOINTS", "IP_ADDRESSES"]
                if not isinstance(current_entries, dict) or not all(k in current_entries for k in expected_keys):
                    logger.warning(f"Invalid format for '{APPROVED_TESTING_LIST_NAME}'. Reinitializing.")
                    current_entries = {"USERNAMES": [], "ENDPOINTS": [], "IP_ADDRESSES": []}
                # Ensure values are lists
                for key in expected_keys:
                    if not isinstance(current_entries.get(key), list):
                        logger.warning(f"Key '{key}' in '{APPROVED_TESTING_LIST_NAME}' is not a list ({type(current_entries.get(key))}). Resetting.")
                        current_entries[key] = []

                master_entries = list_handler.get_list_data_by_name(APPROVED_TESTING_MASTER_LIST_NAME)
                if not isinstance(master_entries, list):  # Master list should be a list of dicts
                    logger.warning(f"Invalid format for '{APPROVED_TESTING_MASTER_LIST_NAME}'. Reinitializing.")
                    master_entries = []

            except Exception as get_e:
                logger.error(f"Failed to get XSOAR lists for approved testing: {get_e}", exc_info=True)
                return f"Error: Could not retrieve existing approved testing lists from XSOAR: {get_e}"

            # --- Add Entries ---
            submit_date_str = datetime.now().strftime("%Y-%m-%d")  # Use consistent format
            added_count = 0
            new_master_entries_to_add = []

            # Helper to create master entry dict
            def create_master_entry(key, value):
                return {
                    key: value, "description": description, "scope": scope,
                    "submitter": submitter_email, "submit_date": submit_date_str,
                    "expiry_date": expiry_date_str
                }

            # Add to current list and prepare master entries
            if usernames_list:
                for username in usernames_list:
                    current_entries["USERNAMES"].append({"data": username, "expiry_date": expiry_date_str, "submitter": submitter_email})
                    new_master_entries_to_add.append(create_master_entry("username", username))
                    added_count += 1
            if host_names_list:
                for host_name in host_names_list:
                    current_entries["ENDPOINTS"].append({"data": host_name, "expiry_date": expiry_date_str, "submitter": submitter_email})
                    new_master_entries_to_add.append(create_master_entry("host_name", host_name))
                    added_count += 1
            if ip_addresses_list:
                for ip_address in ip_addresses_list:
                    current_entries["IP_ADDRESSES"].append({"data": ip_address, "expiry_date": expiry_date_str, "submitter": submitter_email})
                    new_master_entries_to_add.append(create_master_entry("ip_address", ip_address))
                    added_count += 1

            # Append all new master entries at once
            master_entries.extend(new_master_entries_to_add)

            # --- Save Lists ---
            try:
                logger.debug(
                    f"Saving updated '{APPROVED_TESTING_LIST_NAME}' with {len(current_entries.get('USERNAMES', []))} users, {len(current_entries.get('ENDPOINTS', []))} endpoints, {len(current_entries.get('IP_ADDRESSES', []))} IPs.")
                list_handler.save(APPROVED_TESTING_LIST_NAME, current_entries)

                logger.debug(f"Saving updated '{APPROVED_TESTING_MASTER_LIST_NAME}' with {len(master_entries)} total entries.")
                list_handler.save(APPROVED_TESTING_MASTER_LIST_NAME, master_entries)

                logger.info(f"Successfully saved updates to approved testing lists. Added {added_count} items for {submitter_email}.")
            except Exception as save_e:
                logger.error(f"Failed to save approved testing lists: {save_e}", exc_info=True)
                # Consider attempting to revert changes or notify admin? Difficult state.
                return f"Error: Failed to save the updated approved testing lists to XSOAR: {save_e}"

            # --- Announce ---
            announce_item = {
                "description": description, "scope": scope, "submitter": submitter_email,
                "submit_date": submit_date_str, "expiry_date": expiry_date_str,
                "usernames": ', '.join(usernames_list) or None,  # Use None if empty for cleaner card
                "host_names": ', '.join(host_names_list) or None,
                "ip_addresses": ', '.join(ip_addresses_list) or None
            }
            announce_new_approved_testing_entry(announce_item)

            # Format expiry date for user message (MM/DD/YYYY)
            expiry_display_date = expiry_dt.strftime("%m/%d/%Y")
            return f"{submitter_name}, your {added_count} entry/entries have been added to the Approved Testing list (expires {expiry_display_date})."

        except KeyError as e:
            logger.error(f"Missing expected input field in AddApprovedTestingEntry submission: {e}", exc_info=True)
            return f"Error: Missing required form field '{e}'. Please try again."
        except Exception as e:
            logger.error(f"Error adding approved testing entry: {e}", exc_info=True)
            return f"An unexpected error occurred while adding the approved testing entry: {e}"


class RemoveApprovedTestingEntry(Command):
    """Handles removing entries from the approved testing list (Not Implemented)."""

    def __init__(self):
        super().__init__(
            command_keyword="remove_approved_testing",  # Matches callback_keyword
            card=None,
            help_message="Removes entries from the approved testing list (internal - NOT IMPLEMENTED)."
        )

    @log_moneyball_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        """Executes the RemoveApprovedTestingEntry command."""
        submitter_email = activity.get('actor', {}).get('emailAddress', 'Unknown User')
        logger.warning(f"RemoveApprovedTestingEntry command executed by {submitter_email}, but is not implemented.")

        # --- Implementation Needed ---
        # See previous detailed comment in the full file response about the complexities here.
        # Requires card redesign or a different approach to identify items for removal.
        # --- Placeholder Response ---
        return "Sorry, the 'Remove' functionality for approved testing entries is not yet implemented."


class Who(Command):
    """Return who the on-call person is."""

    def __init__(self):
        super().__init__(
            command_keyword="who",
            help_message="Show who is currently on call",
            card=None,
        )

    @log_moneyball_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        """Executes the Who command."""
        submitter_email = activity.get('actor', {}).get('emailAddress', 'Unknown User')
        logger.info(f"Getting current on-call person, requested by {submitter_email}.")
        try:
            on_call_person = oncall.get_on_call_person()
            if on_call_person:
                logger.info(f"On-call person determined: {on_call_person}")
                return f"The current on-call person is: **{on_call_person}**"
            else:
                logger.warning("oncall.get_on_call_person() returned empty.")
                return "Could not determine the current on-call person. The schedule might be empty or unavailable."
        except Exception as e:
            logger.error(f"Error getting on-call person: {e}", exc_info=True)
            return f"Sorry, an error occurred while retrieving the on-call person: {e}"


class Rotation(Command):
    """Return the on-call rotation schedule."""

    def __init__(self):
        super().__init__(
            command_keyword="rotation",
            help_message="Show the on-call rotation schedule",
            card=None,
        )

    @log_moneyball_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        """Executes the Rotation command."""
        submitter_email = activity.get('actor', {}).get('emailAddress', 'Unknown User')
        logger.info(f"Getting on-call rotation, requested by {submitter_email}.")
        try:
            rotation_data = oncall.get_rotation()

            if not rotation_data:
                logger.warning("oncall.get_rotation() returned empty.")
                return "Could not retrieve the on-call rotation schedule. It might be empty or unavailable."

            # Expecting list of lists/tuples like [[date, name], [date, name]]
            if not isinstance(rotation_data, list) or not all(isinstance(item, (list, tuple)) and len(item) == 2 for item in rotation_data):
                logger.error(f"Unexpected format for rotation data received from oncall.get_rotation(): {rotation_data}")
                return "Error: Received unexpected data format for the rotation schedule."

            # Convert to DataFrame for easy formatting
            try:
                df = pandas.DataFrame(rotation_data, columns=["Date", "Analyst"])
                # Optional: Format date column if needed (e.g., to remove time)
                # df['Date'] = pandas.to_datetime(df['Date']).dt.strftime('%Y-%m-%d')
            except Exception as df_e:
                logger.error(f"Error creating DataFrame from rotation data: {df_e}", exc_info=True)
                return f"Error formatting the rotation schedule data: {df_e}"

            # Convert DataFrame to Markdown table
            markdown_table = df.to_markdown(index=False)

            if not markdown_table:
                logger.error("Failed to convert rotation DataFrame to markdown.")
                return "Error: Could not format the rotation schedule for display."

            logger.info(f"Successfully retrieved and formatted rotation schedule for {submitter_email}.")
            # Return formatted table in a code block for monospace alignment
            return f"**On-Call Rotation Schedule:**\n{markdown_table}"

        except Exception as e:
            logger.error(f"Error getting on-call rotation: {e}", exc_info=True)
            return f"Sorry, an error occurred while retrieving the on-call rotation: {e}"


class ContainmentStatusCS(Command):
    """Checks and returns the CrowdStrike network containment status of a host."""

    def __init__(self):
        super().__init__(
            command_keyword="status",
            help_message="Check CrowdStrike containment status (use: status <hostname>)",
            card=None,  # Processes message or card input
        )

    @log_moneyball_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        """Executes the ContainmentStatusCS command."""
        host_name_cs = ""
        submitter_email = activity.get('actor', {}).get('emailAddress', 'Unknown User')

        # Prioritize input from the card submission if available
        if attachment_actions and hasattr(attachment_actions, 'inputs'):
            host_name_cs = attachment_actions.inputs.get('host_name_cs', '').strip()
            logger.debug(f"Received hostname '{host_name_cs}' from card submission by {submitter_email}.")

        # If not from card, try parsing from the direct message
        if not host_name_cs and message:
            cleaned_message = message.strip()
            # Use configured bot name or default
            bot_mention = f"@{getattr(CONFIG, 'bot_name', DEFAULT_BOT_NAME)}"

            # Try removing mention + command: "@Bot status hostname"
            if cleaned_message.lower().startswith(f"{bot_mention.lower()} {self.command_keyword}"):
                host_name_cs = cleaned_message[len(bot_mention) + len(self.command_keyword) + 1:].strip()
            # Try removing command only: "status hostname"
            elif cleaned_message.lower().startswith(self.command_keyword):
                host_name_cs = cleaned_message[len(self.command_keyword):].strip()
            # Fallback: Assume the entire message (after cleaning) is the hostname
            else:
                host_name_cs = cleaned_message
                logger.debug(f"Assuming message '{cleaned_message}' is the hostname for status check by {submitter_email}.")

            logger.debug(f"Parsed hostname '{host_name_cs}' from direct message by {submitter_email}.")

        if not host_name_cs:
            logger.warning(f"ContainmentStatusCS failed for {submitter_email}: No hostname provided.")
            return "Please provide a hostname, either via the card or by typing `status <hostname>`."

        logger.info(f"Checking CS containment status for host: '{host_name_cs}', requested by {submitter_email}")
        try:
            # Assuming the service client handles potential API errors and returns status or raises Exception
            status = crowdstrike.get_device_containment_status(host_name_cs)

            if status is not None:  # Check for None explicitly
                logger.info(f"Status for '{host_name_cs}': {status}")
                # Use backticks for hostname, bold for status
                return f'The network containment status of `{host_name_cs}` in CrowdStrike is **{status}**.'
            else:
                # Handle cases where the API might return None (e.g., host not found)
                logger.warning(f"CrowdStrike API returned no status for '{host_name_cs}'. Host likely not found.")
                return f'Could not retrieve containment status for `{host_name_cs}`. The host may not exist in CrowdStrike or the API response was empty.'

        except Exception as e:
            # Catch specific exceptions from the client if possible (e.g., HostNotFound, APIError)
            logger.error(f"Error getting CS containment status for '{host_name_cs}': {e}", exc_info=True)
            # Provide a more informative error message
            error_message = f"Error checking status for `{host_name_cs}`: {e}. "
            error_message += "Please ensure the hostname is correct and exists in CrowdStrike."
            return error_message


class GetAllOptions(Command):
    """Displays the main options card with ShowCard actions."""

    def __init__(self):
        super().__init__(
            command_keyword="options",
            help_message="Show all available bot command categories",
            card=all_options_card,
        )

    @log_moneyball_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        """Executes the GetAllOptions command."""
        logger.debug(f"Executing GetAllOptions command for user {activity.get('actor', {}).get('emailAddress')}")
        pass  # Card display is handled by the bot framework


class ImportTicket(Command):
    """Imports a ticket from XSOAR Prod to Dev."""

    def __init__(self):
        super().__init__(
            command_keyword="import",  # Matches callback_keyword
            help_message="Import an XSOAR Prod ticket to Dev environment",
            card=TICKET_IMPORT_CARD.to_dict(),  # Show card on direct command
        )

    @log_moneyball_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        """Executes the ImportTicket command."""
        if attachment_actions is None:
            logger.debug(f"Executing ImportTicket command (showing card) for user {activity.get('actor', {}).get('emailAddress')}")
            return None

        logger.debug(f"Processing ImportTicket card submission by user {activity.get('actor', {}).get('emailAddress')}")

        prod_ticket_number = attachment_actions.inputs.get('prod_ticket_number', '').strip()
        submitter_name = activity.get('actor', {}).get('displayName', 'User')

        try:

            if not prod_ticket_number:
                logger.warning(f"ImportTicket failed for {submitter_name}: Production ticket number missing.")
                return "Error: Production ticket number is required."

            # Basic validation - check if it looks like a number
            if not prod_ticket_number.isdigit():
                logger.warning(f"ImportTicket failed for {submitter_name}: Invalid ticket number '{prod_ticket_number}'.")
                return f"Error: Invalid production ticket number '{prod_ticket_number}'. Please enter digits only."

            logger.info(f"Attempting to import Prod ticket {prod_ticket_number} to Dev, requested by {submitter_name}.")

            # Call the service function
            # Assuming it returns (dev_ticket_id, dev_ticket_url) or raises error
            destination_ticket_number, destination_ticket_link = xsoar.import_ticket(prod_ticket_number)

            if destination_ticket_number and destination_ticket_link:
                logger.info(f"Successfully imported Prod ticket {prod_ticket_number} to Dev ticket {destination_ticket_number}")
                # Format response with link
                # Use the link provided by the service function
                return (f"Prod ticket `{prod_ticket_number}` imported to Dev: "
                        f"X#{destination_ticket_number}")
            elif destination_ticket_number:  # Handle case where link might be missing but ID is returned
                logger.warning(f"Imported Prod ticket {prod_ticket_number} to Dev ticket {destination_ticket_number}, but link was not returned.")
                return f"Prod ticket `{prod_ticket_number}` imported to Dev: X#{destination_ticket_number} (Link unavailable)."
            else:
                # Handle case where import function might return None, None without erroring
                logger.error(f"xsoar.import_ticket({prod_ticket_number}) failed or returned no ticket ID.")
                return f"Failed to import ticket `{prod_ticket_number}`. The ticket might not exist in Prod, may already be imported, or an error occurred during import."

        except KeyError as e:
            logger.error(f"Missing expected input field 'prod_ticket_number' in ImportTicket submission: {e}", exc_info=True)
            return "Error: Missing required form field 'prod_ticket_number'. Please try again."
        except Exception as e:
            logger.error(f"Error importing ticket {prod_ticket_number}: {e}", exc_info=True)
            return f"An error occurred while importing ticket `{prod_ticket_number}`: {e}"


class CreateTuningRequest(Command):
    """Creates an AZDO work item for a tuning request."""

    def __init__(self):
        super().__init__(
            help_message="Create an AZDO Tuning Request (User Story)",
            command_keyword="tuning",  # Simplified keyword for user
            card=TUNING_REQUEST_CARD.to_dict(),  # Show card on direct command
        )

    # Internal callback keyword matches card definition's data
    _callback_keyword = "tuning_request"

    @log_moneyball_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        """Executes the CreateTuningRequest command."""
        # Check if this execution is from the card submission based on callback keyword
        is_card_submission = (attachment_actions is not None and
                              hasattr(attachment_actions, 'inputs') and
                              # Check the actual callback keyword from the card data
                              attachment_actions.inputs.get('callback_keyword') == self._callback_keyword)

        if not is_card_submission:
            # If not a card submission for *this* command, assume user typed "tuning" -> show card
            logger.debug(f"Executing CreateTuningRequest command (showing card) for user {activity.get('actor', {}).get('emailAddress')}")
            return None

        # Process the card submission
        logger.debug(f"Processing CreateTuningRequest card submission by user {activity.get('actor', {}).get('emailAddress')}")
        try:
            inputs = attachment_actions.inputs
            title = inputs.get('title', '').strip()
            description = inputs.get('description', '').strip()
            tickets = inputs.get('tickets', '').strip()  # Comma-separated list
            ticket_volume = inputs.get('ticket_volume', '').strip()
            submitter_display_name = activity.get('actor', {}).get('displayName', 'Unknown User')

            # --- Validation ---
            required_fields = {
                "Rule/Detection Title": title,
                "Reason for Tuning": description,
                "Recent Example Ticket(s)": tickets,
                "Approx. Ticket Volume": ticket_volume
            }
            missing = [name for name, value in required_fields.items() if not value]
            if missing:
                logger.warning(f"CreateTuningRequest submission missing fields: {missing}")
                return f"Error: Please fill in the required fields: {', '.join(missing)}."

            # --- Prepare AZDO Data ---
            # Combine description parts using HTML breaks for AZDO formatting
            full_description = (
                f'{description}<br><br>'
                f'<b>Example tickets:</b> {tickets}<br>'
                f'<b>Approx. ticket volume:</b> {ticket_volume}'
            )
            project_key = 'de'  # Tuning requests go to Detection Engineering project
            item_type = 'User Story'  # Standard type for tuning requests
            area_path_key = 'tuning_request'  # Specific area path key from data_maps

            area_path = azdo_area_paths.get(area_path_key)
            azdo_org = azdo_orgs.get(project_key)
            azdo_project_name = azdo_projects.get(project_key)

            # Validate AZDO config lookup
            if not area_path:
                logger.error(f"AZDO area path key '{area_path_key}' not found in data_maps (azdo_area_paths).")
                return "Error: Configuration error - Tuning request area path is missing."
            if not azdo_org or not azdo_project_name:
                logger.error(f"AZDO org/project config missing for project key '{project_key}'. Check data_maps (azdo_orgs, azdo_projects).")
                return f"Error: Configuration missing for project '{project_key}'. Cannot create tuning request."

            logger.info(f"Attempting to create AZDO Tuning Request '{title}' in {project_key} by {submitter_display_name}")

            # --- Create Work Item ---
            tuning_request_id = azdo.create_wit(
                title=f"Tuning Request: {title}",  # Prefix title
                description=full_description,
                item_type=item_type,
                project=project_key,  # Pass key
                area_path=area_path,
                submitter=submitter_display_name
                # Add assignee, parent_url if needed for tuning requests
            )

            if not tuning_request_id:
                logger.error(f"azdo.create_wit failed for tuning request '{title}' in project {project_key}.")
                return "Error: Failed to create the tuning request in Azure DevOps. Check service logs."

            # --- Format Response ---
            tuning_request_url = f'https://dev.azure.com/{azdo_org}/{quote(azdo_project_name)}/_workitems/edit/{tuning_request_id}'
            # Provide the URL directly in the response message
            return_message = f"Tuning request submitted successfully!\n[{tuning_request_id}]({tuning_request_url}) - {title}"

            logger.info(f"Successfully created AZDO tuning request {tuning_request_id}")

            # --- Announce (Optional) ---
            announce_room_id = getattr(CONFIG, 'webex_room_id_automation_engineering', None)
            if announce_room_id:
                # Use the URL in the announcement too
                announce_md = f"{submitter_display_name} submitted a new Tuning Request: {tuning_request_id} - {title}"
                announce_fallback = f"New Tuning Request submitted by {submitter_display_name}: WIT {tuning_request_id} - {title}"
                announce_webex(announce_room_id, announce_md, announce_fallback)
            else:
                logger.warning("Cannot announce Tuning Request: webex_room_id_automation_engineering not configured.")

            return return_message

        except KeyError as e:
            logger.error(f"Missing expected input field in CreateTuningRequest submission: {e}", exc_info=True)
            return f"Error: Missing required form field '{e}'. Please try again."
        except Exception as e:
            logger.error(f"Error creating AZDO tuning request: {e}", exc_info=True)
            return f"An unexpected error occurred while creating the tuning request: {e}"


# --- Main Bot Execution ---

def main():
    """Initializes and runs the Webex Bot."""
    # Use configured bot name or a default
    bot_name = getattr(CONFIG, 'bot_name', DEFAULT_BOT_NAME)
    logger.info(f"Initializing bot: {bot_name}")

    # Approved domains from config or default
    approved_domains = getattr(CONFIG, 'approved_domains', DEFAULT_APPROVED_DOMAINS)
    logger.info(f"Approved domains: {approved_domains}")

    # --- Initialize Bot ---
    # Token presence already checked at top level
    bot = WebexBot(
        CONFIG.webex_bot_access_token_hal9000,
        bot_name=bot_name,
        approved_domains=approved_domains,
        include_demo_commands=False  # Disable default demo commands
    )

    # --- Add Commands ---
    logger.info("Adding commands to bot...")
    # Approved Testing
    bot.add_command(GetApprovedTestingCard())
    bot.add_command(GetCurrentApprovedTestingEntries())
    bot.add_command(AddApprovedTestingEntry())
    bot.add_command(RemoveApprovedTestingEntry())  # Still needs implementation

    # On Call
    bot.add_command(Who())
    bot.add_command(Rotation())

    # CrowdStrike
    bot.add_command(ContainmentStatusCS())
    # Add Contain/Uncontain commands here if they exist
    # bot.add_command(ContainHostCS())
    # bot.add_command(UncontainHostCS())

    # XSOAR
    bot.add_command(GetNewXTicketForm())
    bot.add_command(CreateXSOARTicket())
    bot.add_command(IOC())
    bot.add_command(IOCHunt())
    bot.add_command(ThreatHuntCard())
    bot.add_command(ThreatHunt())
    bot.add_command(ImportTicket())
    bot.add_command(Review())  # Check context dependency

    # AZDO
    bot.add_command(CreateAZDOWorkItem())
    bot.add_command(CreateTuningRequest())

    # Misc / General
    bot.add_command(URLs())
    bot.add_command(GetAllOptions())  # Main menu/entry point

    logger.info(f"Starting bot {bot}...")
    try:
        # Run the bot's main loop
        bot.run()
    except KeyboardInterrupt:
        logger.info(f"Bot {bot} stopped by user (KeyboardInterrupt).")
    except Exception as run_e:
        logger.critical(f"Bot {bot} run failed unexpectedly: {run_e}", exc_info=True)
    finally:
        logger.info(f"Bot {bot} has stopped.")


if __name__ == '__main__':  # Standard check for script execution
    main()
