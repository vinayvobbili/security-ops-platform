import ipaddress
from datetime import datetime, timedelta
from urllib.parse import quote
import threading
import time

import pandas
import requests
import webexpythonsdk.models.cards.inputs as INPUTS
import webexpythonsdk.models.cards.options as OPTIONS
from pytz import timezone
from tabulate import tabulate
from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot
from webexpythonsdk import WebexAPI
from webexpythonsdk.models.cards import (
    Colors, TextBlock, FontWeight, Column, AdaptiveCard, ColumnSet, HorizontalAlignment, ActionSet, ActionStyle
)
from webexpythonsdk.models.cards.actions import Submit

import src.components.oncall as oncall
from config import get_config
from data.data_maps import azdo_projects, azdo_orgs, azdo_area_paths
from services import xsoar, azdo
from services.crowdstrike import CrowdStrikeClient
from services.xsoar import ListHandler, TicketHandler
from src.helper_methods import log_toodles_activity
from services.approved_testing_utils import add_approved_testing_entry

CONFIG = get_config()
webex_api = WebexAPI(CONFIG.webex_bot_access_token_toodles)

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

incident_handler = TicketHandler()
list_handler = ListHandler()

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
                            }
                        ]
                    }
                ]
            }
        }
    ]
}


def get_url_card():
    metcirt_urls = list_handler.get_list_data_by_name('METCIRT URLs')
    actions = []

    # Iterate through the list of URLs and create button actions
    for item in metcirt_urls:
        if "url" in item:  # Handle URL buttons with Action.OpenUrl
            actions.append({
                "type": "Action.OpenUrl",
                "title": item['name'],
                "url": item['url'],
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
                "actions": actions
            }
        ]
    }

    return card


URL_CARD = get_url_card()


class URLs(Command):
    def __init__(self):
        super().__init__(
            command_keyword="urls",
            card=URL_CARD,
            delete_previous_message=True
        )

    @log_toodles_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        pass


class GetNewXTicketForm(Command):
    def __init__(self):
        super().__init__(
            card=NEW_TICKET_CARD,
            command_keyword="get_x_ticket_form",
            help_message="Create X Ticket",
            delete_previous_message=True
        )

    @log_toodles_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        pass


class CreateXSOARTicket(Command):
    def __init__(self):
        super().__init__(
            command_keyword="create_x_ticket",
            card=None,
            delete_previous_message=True
        )

    @log_toodles_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        if attachment_actions.inputs['title'].strip() == "" or attachment_actions.inputs['details'].strip() == "":
            return "Please fill in both fields to create a new ticket."

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
        result = incident_handler.create(incident)
        new_incident_id = result.get('id')
        incident_url = CONFIG.xsoar_prod_ui_base_url + '/Custom/caseinfoid/' + new_incident_id

        return f"{activity['actor']['displayName']}, Ticket [#{new_incident_id}]({incident_url}) has been created in XSOAR Prod."


class IOC(Command):
    def __init__(self):
        super().__init__(
            command_keyword="ioc",
            card=IOC_HUNT,
            delete_previous_message=True
        )

    @log_toodles_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        pass


class IOCHunt(Command):
    def __init__(self):
        super().__init__(
            command_keyword="ioc_hunt",
            card=None,
            delete_previous_message=True
        )

    @log_toodles_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
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
        result = incident_handler.create(incident)
        ticket_no = result.get('id')
        incident_url = CONFIG.xsoar_prod_ui_base_url + '/Custom/caseinfoid/' + ticket_no

        return f"{activity['actor']['displayName']}, A New IOC Hunt has been created in XSOAR. Ticket: [#{ticket_no}]({incident_url})"


class ThreatHuntCard(Command):
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

    @log_toodles_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
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
        result = incident_handler.create(incident)
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
            help_message="Create AZDO Work Item",
            card=AZDO_CARD,
            delete_previous_message=True
        )

    @log_toodles_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):

        try:
            parent_url = None
            assignee = None
            area_path = None
            inputs = attachment_actions.inputs
            wit_title = inputs['wit_title']
            wit_type = inputs['wit_type']
            submitter_display_name = activity['actor']['displayName']
            wit_description = inputs['wit_description']
            project = inputs['project']

            if project == 'platforms':
                assignee = CONFIG.my_email_address
                parent_url = CONFIG.azdo_platforms_parent_url
            elif project == 'rea':
                assignee = CONFIG.resp_eng_auto_lead
                area_path = azdo_area_paths['re']
                parent_url = CONFIG.azdo_rea_parent_url
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
                area_path=area_path
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

    @log_toodles_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        if attachment_actions.inputs["review_notes"] == "":
            return "Please add a comment to submit this ticket for review."

        curr_date = datetime.now()
        ticket_no = attachment_actions.inputs["incident_id"]

        list_dict = list_handler.get_list_data_by_name("review").get('Tickets')
        add_entry_to_reviews(list_dict, ticket_no, activity['actor']['emailAddress'], curr_date.strftime("%x"),
                             attachment_actions.inputs["review_notes"])
        reformat = {"Tickets": list_dict}
        list_handler.save(reformat, "review")

        return f"Ticket {ticket_no} has been added to Reviews."


class GetApprovedTestingCard(Command):
    def __init__(self):
        super().__init__(
            command_keyword="testing",
            help_message="Submit Approved Testing",
            card=APPROVED_TESTING_CARD,
            delete_previous_message=True
        )

    @log_toodles_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        pass


# Helper function to convert date format from YYYY-MM-DD to MM/DD/YYYY
def reformat_date(date_str):
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").strftime("%m/%d/%Y")
    except ValueError:
        return date_str  # If there's an issue with the date format, return it as-is


def get_approved_testing_entries_table():
    approved_test_items = list_handler.get_list_data_by_name(approved_testing_list_name)

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

    @log_toodles_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
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
        if len(result) > max_length:
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

    @log_toodles_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        usernames = attachment_actions.inputs['usernames'].strip()
        items_of_tester = attachment_actions.inputs['ip_addresses_and_host_names_of_tester'].strip()
        items_to_be_tested = attachment_actions.inputs['ip_addresses_and_host_names_to_be_tested'].strip()
        description = attachment_actions.inputs['description'].strip()
        scope = attachment_actions.inputs['scope'].strip()
        submitter = activity['actor']['emailAddress']
        expiry_date = attachment_actions.inputs['expiry_date']
        if attachment_actions.inputs['callback_keyword'] == 'add_approved_testing' and expiry_date == "":
            expiry_date = (datetime.now(timezone('US/Eastern')) + timedelta(days=1)).strftime("%Y-%m-%d")
        submit_date = datetime.now().strftime("%m/%d/%Y")
        try:
            add_approved_testing_entry(
                list_handler,
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
    webex_data = list_handler.get_list_data_by_name('METCIRT Webex')
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f"Bearer {CONFIG.webex_bot_access_token_toodles}"
    }
    payload_json = {
        'roomId': webex_data.get("channels").get("threat_hunt"),
        'markdown': f"<@personId:{person_id}> created a new Threat Hunt in XSOAR. Ticket: [#{ticket_no}]({incident_url}) - {ticket_title}"
    }
    requests.post(webex_data.get('api_url'), headers=headers, json=payload_json)


def keepalive_ping():
    while True:
        try:
            # Lightweight API call to keep the connection alive
            webex_api.people.me()
        except Exception as e:
            print(f"Keepalive ping failed: {e}")
        time.sleep(240)  # 4 minutes


class Who(Command):
    """Return who the on-call person is"""

    def __init__(self):
        super().__init__(
            command_keyword="who",
            help_message="On-Call",
            card=None,
            delete_previous_message=True
        )

    @log_toodles_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        return f"{activity['actor']['displayName']}, the DnR On-call person is {oncall.get_on_call_person()}"


class Rotation(Command):
    """Return who the on-call person is"""

    def __init__(self):
        super().__init__(
            command_keyword="rotation",
            card=None,
            delete_previous_message=True
        )

    @log_toodles_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
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

    @log_toodles_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):

        if message.strip() != "":
            host_name_cs = message.strip()
        else:
            host_name_cs = attachment_actions.inputs['host_name_cs'].strip()

        host_name_cs = host_name_cs.replace("METCIRT_Bot status", "").strip()
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
            delete_previous_message=True
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

    @log_toodles_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
    def execute(self, message, attachment_actions, activity):
        prod_ticket_number = attachment_actions.inputs['prod_ticket_number']
        destination_ticket_number, destination_ticket_link = xsoar.import_ticket(prod_ticket_number)
        return f'{activity['actor']['displayName']}, the Prod ticket has been copied to Dev [X#{destination_ticket_number}]({destination_ticket_link})'


class CreateTuningRequest(Command):
    def __init__(self):
        super().__init__(
            help_message="Create Tuning Request",
            command_keyword="tuning_request",
            card=TUNING_REQUEST_CARD.to_dict(),
            delete_previous_message=True
        )

    @log_toodles_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
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
            help_message="Search X",
            command_keyword="get_search_xsoar_card",
            card=SEARCH_X_CARD.to_dict(),
            delete_previous_message=True
        )

    @log_toodles_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles)
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

        ticket_handler = TicketHandler()
        tickets = ticket_handler.get_tickets(query=query)
        if tickets:
            for ticket in tickets:
                message = f"[X#{ticket.get('id')}]({CONFIG.xsoar_prod_ui_base_url}/Custom/caseinfoid/{ticket.get('id')}) - {ticket.get('name')}\n"
        else:
            message = 'None Found'
        return message


def main():
    # Start keepalive thread
    threading.Thread(target=keepalive_ping, daemon=True).start()

    bot = WebexBot(
        CONFIG.webex_bot_access_token_toodles,
        bot_name="Hello from Toodles!",
        approved_rooms=[CONFIG.webex_room_id_vinay_test_space, CONFIG.webex_room_id_gosc_t2, CONFIG.webex_room_id_threatcon_collab],
        log_level="ERROR",
        threads=True,
        bot_help_subtitle="Pick a tool!"
    )

    bot.add_command(GetApprovedTestingCard())
    bot.add_command(GetCurrentApprovedTestingEntries())
    bot.add_command(AddApprovedTestingEntry())
    bot.add_command(RemoveApprovedTestingEntry())
    bot.add_command(Who())
    bot.add_command(Rotation())
    bot.add_command(ContainmentStatusCS())
    bot.add_command(Review())
    bot.add_command(GetNewXTicketForm())
    bot.add_command(CreateXSOARTicket())
    bot.add_command(IOC())
    bot.add_command(IOCHunt())
    bot.add_command(URLs())
    bot.add_command(ThreatHuntCard())
    bot.add_command(CreateThreatHunt())
    bot.add_command(CreateAZDOWorkItem())
    bot.add_command(GetAllOptions())
    bot.add_command(ImportTicket())
    bot.add_command(CreateTuningRequest())
    bot.add_command(GetSearchXSOARCard())
    bot.add_command(FetchXSOARTickets())

    print("Toodles is up and running...")
    bot.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
