import base64
import json
import time
from datetime import date, datetime, timedelta
from urllib.parse import quote

import pandas
import requests
import schedule
from pytz import timezone
from webex_bot.models.command import Command
from webex_bot.webex_bot import WebexBot
from webexpythonsdk import WebexAPI

from config import get_config
from services.xsoar import ListHandler, IncidentHandler

approved_testing_list_name: str = "METCIRT_Approved_Testing"
approved_testing_master_list_name: str = "METCIRT_Approved_Testing_MASTER"

CONFIG = get_config()
webex_api = WebexAPI(CONFIG.webex_bot_access_token_toodles)

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

incident_handler = IncidentHandler()
list_handler = ListHandler()

NEW_TICKET_CARD = {
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "type": "AdaptiveCard",
    "version": "1.3",
    "body": [
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
                    "width": 3,
                    "items": [
                        {
                            "type": "Input.Text",
                            "id": "title",
                            "placeholder": "New Incident"
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
                    "width": 3,
                    "items": [
                        {
                            "type": "Input.Text",
                            "id": "details",
                            "placeholder": "Something happened here",
                            "isMultiline": True
                        }
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
                                    "title": "Response Engineering",
                                    "value": "re"
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
            "size": "medium"
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
                            "text": "Username",
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
                            "id": "username"
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
                    "width": "1",
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "Host Name",
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
                            "id": "host_name"
                        }
                    ]
                }
            ],
            "spacing": "small"
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
                            "text": "IP Address",
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
                            "id": "ip_address"
                        }
                    ]
                }
            ],
            "spacing": "small"
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
                            "text": "Description",
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
                            "id": "description",
                            "isMultiline": True
                        }
                    ]
                }
            ],
            "spacing": "small"
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
                            "text": "Scope",
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
                            "id": "scope"
                        }
                    ]
                }
            ],
            "spacing": "small"
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
                            "text": "Keep until:",
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
                            "type": "Input.Date",
                            "id": "expiry_date",
                            "placeholder": "Enter a date"
                        }
                    ]
                }
            ],
            "spacing": "small"
        },
        {
            "type": "Input.Toggle",
            "id": "should_create_snow_ticket",
            "title": "Create a SNOW Ticket for this activity?",
            "valueOn": "true",
            "valueOff": "false"
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
                                "type": "Action.Submit",
                                "title": "Show Metrics",
                                "data": {
                                    "callback_keyword": "metrics"
                                }
                            },
                            {
                                "type": "Action.ShowCard",
                                "title": "IOC Hunt",
                                "card": IOC_HUNT
                            },
                            {
                                "type": "Action.ShowCard",
                                "title": "Threat Hunt",
                                "card": THREAT_HUNT
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
    metcirt_urls = list_handler.get_list_by_name('METCIRT URLs')
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
        )

    def execute(self, message, attachment_actions, activity):
        pass


class GetNewXTicketForm(Command):
    def __init__(self):
        super().__init__(
            card=NEW_TICKET_CARD,
            command_keyword="get_x_ticket_form",
            help_message="Create X Ticket",
        )

    def execute(self, message, attachment_actions, activity):
        pass


class CreateXSOARTicket(Command):
    def __init__(self):
        super().__init__(
            command_keyword="create_x_ticket",
            card=None,
        )

    def execute(self, message, attachment_actions, activity):
        if attachment_actions.inputs['title'].strip() == "" or attachment_actions.inputs['details'].strip() == "":
            return "Please fill in both fields to create a new ticket."

        incident = {
            'name': attachment_actions.inputs['title'].strip(),
            'details': attachment_actions.inputs['details'].strip() + f"\nSubmitted by: {activity['actor']['emailAddress']}"
        }
        new_ticket = [incident]
        result = incident_handler.create(new_ticket)
        new_incident_id = result[0].get('id')
        incident_url = CONFIG.xsoar_prod_ui_base_url + new_incident_id

        return f"Ticket [#{new_incident_id}]({incident_url}) has been created in XSOAR."


class IOC(Command):
    def __init__(self):
        super().__init__(
            command_keyword="ioc",
            card=IOC_HUNT,
        )

    def execute(self, message, attachment_actions, activity):
        pass


class IOCHunt(Command):
    def __init__(self):
        super().__init__(
            command_keyword="ioc_hunt",
            card=None,
        )

    def execute(self, message, attachment_actions, activity):
        if attachment_actions.inputs['ioc_hunt_title'].strip() == "" or attachment_actions.inputs['ioc_hunt_iocs'].strip() == "":
            return "Please fill in both fields to create a new ticket."

        incident = {
            'name': attachment_actions.inputs['ioc_hunt_title'].strip(),
            'details': attachment_actions.inputs['ioc_hunt_iocs'].strip(),
            'type': "METCIRT IOC Hunt"
        }
        new_ticket = [incident]
        result = incident_handler.create(new_ticket)
        ticket_no = result[0].get('id')
        incident_url = CONFIG.xsoar_prod_ui_base_url + ticket_no

        return f"A New IOC Hunt has been created in XSOAR. Ticket: [#{ticket_no}]({incident_url})"


class ThreatHuntCard(Command):
    def __init__(self):
        super().__init__(
            command_keyword="threat",
            card=THREAT_HUNT,
        )

    def execute(self, message, attachment_actions, activity):
        pass


class ThreatHunt(Command):
    def __init__(self):
        super().__init__(
            command_keyword="threat_hunt",
            card=None,
        )

    def execute(self, message, attachment_actions, activity):
        if attachment_actions.inputs['threat_hunt_title'].strip() == "" or attachment_actions.inputs['threat_hunt_desc'].strip() == "":
            return "Please fill in both fields to create a new ticket."

        incident = {
            'name': attachment_actions.inputs['threat_hunt_title'].strip(),
            'details': attachment_actions.inputs['threat_hunt_desc'].strip() + f"\nSubmitted by: {activity['actor']['emailAddress']}",
            'type': "Threat Hunt"
        }
        new_ticket = [incident]
        result = incident_handler.create(new_ticket)
        ticket_no = result[0].get('id')
        ticket_title = attachment_actions.inputs['threat_hunt_title'].strip()
        incident_url = CONFIG.xsoar_prod_ui_base_url + ticket_no
        person_id = attachment_actions.personId

        announce_new_threat_hunt(ticket_no, ticket_title, incident_url, person_id)


class AZDOWorkItem(Command):
    def __init__(self):
        super().__init__(
            command_keyword="azdo_wit",
            help_message="Create AZDO Work Item",
            card=AZDO_CARD,
        )

    def execute(self, message, attachment_actions, activity):
        azdo_projects = {
            'platforms': 'Acme-Cyber-Platforms',
            're': 'Acme-Cyber-Security',
            'de': 'Detection-Engineering',
            'gdr': 'Global Detection and Response Shared'
        }
        azdo_orgs = {
            'platforms': 'Acme-US',
            're': 'Acme-US',
            'de': 'Acme-US',
            'gdr': 'Acme-US-2'
        }
        try:
            inputs = attachment_actions.inputs
            wit_title = inputs['wit_title']
            wit_type = inputs['wit_type']
            submitter_display_name = activity['actor']['displayName']
            wit_description = inputs['wit_description'] + f'<br><br>Submitted by <strong>{submitter_display_name}</strong>'
            project = inputs['project']

            org = azdo_orgs[project]
            project_name = azdo_projects.get(project)
            url = f"https://dev.azure.com/{org}/{project_name}/_apis/wit/workitems/${wit_type}?api-version=7.0"

            payload = [
                {
                    "op": "add",
                    "path": "/fields/System.Title",
                    "value": wit_title
                },
                {
                    "op": "add",
                    "path": "/fields/Microsoft.VSTS.TCM.ReproSteps" if wit_type == 'Bug' else "/fields/System.Description",
                    "value": wit_description
                }
            ]

            if project == 'platforms':
                payload.append({
                    "op": "add",
                    "path": "/fields/System.AssignedTo",
                    "value": "Vinay Vobbilichetty"
                })
                payload.append({
                    "op": "add",
                    "path": "/relations/-",
                    "value": {
                        "rel": "System.LinkTypes.Hierarchy-Reverse",
                        "url": "https://dev.azure.com/Acme-US/Acme-Cyber-Platforms/_workitems/edit/203352"
                    }
                })
            elif project == 're':
                payload.append({
                    "op": "add",
                    "path": "/fields/System.AreaPath",
                    "value": "Acme-Cyber-Security\METCIRT\METCIRT Tier III"
                })
                payload.append({
                    "op": "add",
                    "path": "/fields/Microsoft.VSTS.Common.StackRank",
                    "value": "1"
                })

            metcirt_xsoar = list_handler.get_list_by_name('METCIRT XSOAR')
            api_token = metcirt_xsoar['AZDO_PAT']['us-2' if project == 'gdr' else 'us']
            api_key = base64.b64encode(b':' + api_token.encode('utf-8')).decode('utf-8')

            headers = {
                'Content-Type': 'application/json-patch+json',
                'Authorization': f'Basic {api_key}'
            }

            response = requests.request("POST", url, headers=headers, json=payload)
            wit_id = json.loads(response.text).get('id')
            azdo_wit_url = f'https://dev.azure.com/{azdo_orgs.get(project)}/{quote(azdo_projects.get(project))}/_workitems/edit/{wit_id}'
            wit_type = wit_type.replace('%20', ' ')
            return_message = f'A new AZDO {wit_type} has been created \n [{wit_id}]({azdo_wit_url}) - {wit_title}'

            webex_data = list_handler.get_list_by_name('METCIRT Webex')
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f"Bearer {CONFIG.webex_bot_access_token_toodles}"
            }
            payload_json = {
                'roomId': webex_data.get("channels").get("metcirt_automation" if project == 'platforms' else "response_engineering"),
                'markdown': f"{submitter_display_name} has created a new AZDO {wit_type} \n [{wit_id}]({azdo_wit_url}) - {wit_title}"
            }
            requests.post(webex_data.get('api_url'), headers=headers, json=payload_json)

            return return_message
        except Exception as e:
            return str(e)


class Review(Command):
    def __init__(self):
        super().__init__(
            command_keyword="review",
            card=None,
        )

    def execute(self, message, attachment_actions, activity):
        if attachment_actions.inputs["review_notes"] == "":
            return "Please add a comment to submit this ticket for review."

        curr_date = datetime.now()
        ticket_no = attachment_actions.inputs["incident_id"]

        list_dict = list_handler.get_list_by_name("review").get('Tickets')
        add_entry_to_reviews(list_dict, ticket_no, activity['actor']['emailAddress'], curr_date.strftime("%x"), attachment_actions.inputs["review_notes"])
        reformat = {"Tickets": list_dict}
        list_handler.save(reformat, "review")

        return f"Ticket {ticket_no} has been added to Reviews."


class GetApprovedTestingCard(Command):
    def __init__(self):
        super().__init__(
            command_keyword="testing",
            help_message="Submit Approved Testing",
            card=APPROVED_TESTING_CARD,
        )

    def execute(self, message, attachment_actions, activity):
        pass


class GetCurrentApprovedTestingEntries(Command):
    def __init__(self):
        super().__init__(
            command_keyword="current_approved_testing",
            card=None,
        )

    def execute(self, message, attachment_actions, activity):
        approved_test_items = list_handler.get_list_by_name(approved_testing_list_name)
        response_text = {
            "USERNAMES": [],
            "ENDPOINTS": [],
            "IP_ADDRESSES": []
        }

        # Helper function to convert date format from YYYY-MM-DD to MM/DD/YYYY
        def reformat_date(date_str):
            try:
                return datetime.strptime(date_str, "%Y-%m-%d").strftime("%m/%d/%Y")
            except ValueError:
                return date_str  # If there's an issue with the date format, return it as-is

        # Populate response_text with data and reformat the expiry date
        for category in approved_test_items:
            for item in approved_test_items.get(category):
                expiry_date = reformat_date(item.get('expiry_date'))
                response_text.get(category).append(f"{item.get('data')} ({expiry_date})")

        # Dynamically calculate the max column width based on the longest item in each category
        username_col_width = max(len(item) for item in response_text['USERNAMES'] + ['USERNAMES'])
        endpoint_col_width = max(len(item) for item in response_text['ENDPOINTS'] + ['HOST NAMES'])
        ip_col_width = max(len(item) for item in response_text['IP_ADDRESSES'] + ['IP ADDRESSES'])

        # Create the header with dynamically calculated widths
        table = (
            f"{activity['actor']['displayName']}, here are the current Approved Security Testing entries\n"
            "```\n"
            f"|{'-' * (username_col_width + 2)}|{'-' * (endpoint_col_width + 2)}|{'-' * (ip_col_width + 2)}|\n"
            f"| {'USERNAMES'.ljust(username_col_width)} | {'HOST NAMES'.ljust(endpoint_col_width)} | {'IP ADDRESSES'.ljust(ip_col_width)} |\n"
            f"|{'-' * (username_col_width + 2)}|{'-' * (endpoint_col_width + 2)}|{'-' * (ip_col_width + 2)}|\n"
        )

        # Find the maximum number of items in any category
        max_items = max(len(response_text.get('USERNAMES')), len(response_text.get('ENDPOINTS')), len(response_text.get('IP_ADDRESSES')))

        # Pad each category list to the same length
        for category in response_text:
            response_text[category].extend([""] * (max_items - len(response_text[category])))

        # Construct table rows with dynamically calculated column widths
        for i in range(max_items):
            table += f"| {response_text['USERNAMES'][i].ljust(username_col_width)} | {response_text['ENDPOINTS'][i].ljust(endpoint_col_width)} | {response_text['IP_ADDRESSES'][i].ljust(ip_col_width)} |\n"

        table += f"|{'-' * (username_col_width + 2)}-{'-' * (endpoint_col_width + 2)}-{'-' * (ip_col_width + 2)}|\n"
        table += "\n*Entries expire at 5 PM ET on the date shown"

        return table


class AddApprovedTestingEntry(Command):
    def __init__(self):
        super().__init__(
            command_keyword="add_approved_testing",
            card=None,
        )

    def execute(self, message, attachment_actions, activity):
        username = attachment_actions.inputs['username'].strip()
        host_name = attachment_actions.inputs['host_name'].strip()
        ip_address = attachment_actions.inputs['ip_address'].strip()

        if username == "" and host_name == "" and ip_address == "":
            return "One of username, host name, or IP address needs to be filled in. Please try again"

        description = attachment_actions.inputs['description'].strip()
        scope = attachment_actions.inputs['scope'].strip()
        should_create_snow_ticket = attachment_actions.inputs['should_create_snow_ticket']
        submitter = activity['actor']['emailAddress']
        expiry_date = attachment_actions.inputs['expiry_date']
        if attachment_actions.inputs['callback_keyword'] == 'add_approved_testing' and expiry_date == "":
            expiry_date = (datetime.now(timezone('US/Eastern')) + timedelta(days=1)).strftime("%Y-%m-%d")

        approved_testing_entries = list_handler.get_list_by_name(approved_testing_list_name)

        if username:
            approved_testing_entries.get("USERNAMES").append({"data": username, "expiry_date": expiry_date, "submitter": submitter})
        if host_name:
            approved_testing_entries.get("ENDPOINTS").append({"data": host_name, "expiry_date": expiry_date, "submitter": submitter})
        if ip_address:
            approved_testing_entries.get("IP_ADDRESSES").append({"data": ip_address, "expiry_date": expiry_date, "submitter": submitter})

        list_handler.save(approved_testing_list_name, approved_testing_entries)

        approved_testing_master_list_entries = list_handler.get_list_by_name(approved_testing_master_list_name)
        new_testing_entry = {
            "username": username,
            "host_name": host_name,
            "ip_address": ip_address,
            "description": description,
            "scope": scope,
            "should_create_snow_ticket": should_create_snow_ticket,
            "submitter": submitter,
            "submit_date": datetime.now().strftime("%m/%d/%Y"),
            "expiry_date": expiry_date
        }
        approved_testing_master_list_entries.append(new_testing_entry)
        list_handler.save(approved_testing_master_list_name, approved_testing_master_list_entries)

        announce_new_approved_testing_entry({
            "description": description,
            "scope": scope,
            "should_create_snow_ticket": should_create_snow_ticket,
            "submitter": submitter,
            "submit_date": datetime.now().strftime("%m/%d/%Y"),
            "expiry_date": expiry_date,
            "username": username,
            "ip_address": ip_address,
            "host_name": host_name
        })

        return f"{activity['actor']['displayName']}, your entry has been added to the Approved Testing list."


class RemoveApprovedTestingEntry(Command):
    def __init__(self):
        super().__init__(
            command_keyword="remove_approved_testing",
            card=None,
        )

    def execute(self, message, attachment_actions, activity):
        pass


def add_entry_to_reviews(dict_full, ticket_id, person, date, message):
    """
    adds the ticket to the list for further review
    """
    dict_full.append({"ticket_id": ticket_id, "by": person, "date": date, "message": message})


def announce_new_threat_hunt(ticket_no, ticket_title, incident_url, person_id):
    webex_data = list_handler.get_list_by_name('METCIRT Webex')
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f"Bearer {CONFIG.webex_bot_access_token_toodles}"
    }
    payload_json = {
        'roomId': webex_data.get("channels").get("threat_hunt"),
        'markdown': f"<@personId:{person_id}> created a new Threat Hunt in XSOAR. Ticket: [#{ticket_no}]({incident_url}) - {ticket_title}"
    }
    requests.post(webex_data.get('api_url'), headers=headers, json=payload_json)


def announce_new_approved_testing_entry(new_item) -> None:
    payload = json.dumps({
        'roomId': CONFIG.webex_room_id_gosc_t2,
        "text": "New approved testing item submitted",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "type": "AdaptiveCard",
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "version": "1.3",
                "body": [
                    {
                        "type": "TextBlock",
                        "text": "New Approved Testing",
                        "style": "heading",
                        "size": "Large",
                        "weight": "Bolder",
                        "color": "Attention"
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
                                "title": "Username",
                                "wrap": True,
                                "value": new_item.get('username')
                            },
                            {
                                "title": "Hostname",
                                "wrap": True,
                                "value": new_item.get('host_name')
                            },
                            {
                                "title": "IP address",
                                "wrap": True,
                                "value": new_item.get('ip_address')
                            },
                            {
                                "title": "Scope",
                                "wrap": True,
                                "value": new_item.get('scope')
                            },
                            {
                                "title": "Keep until",
                                "value": new_item.get('expiry_date')
                            },
                            {
                                "title": "SNOW ticket",
                                "value": new_item.get('should_create_snow_ticket', 'No')
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
        }]
    })
    webex_api.messages.create(
        roomId=CONFIG.webex_room_id_gosc_t2,
        text="Previous Shift Performance!",
        attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": payload}]
    )


def get_on_call_person():
    """get on-call from XSOAR lists"""
    today = datetime.now(timezone('EST'))
    last_monday = today - timedelta(days=today.weekday())
    return get_on_call_email_by_monday_date(last_monday.strftime('%Y-%m-%d'))


def get_on_call_email_by_monday_date(monday_date):
    """takes the Monday_date as arg"""
    analysts, rotation = get_on_call_details()
    on_call_name = list(
        filter(
            lambda x: x['Monday_date'] == str(monday_date),
            rotation
        )
    )[0]['analyst_name']
    on_call_email_address = list(
        filter(
            lambda x: x['name'] == on_call_name,
            analysts
        )
    )[0]['email_address']

    return on_call_email_address


def get_on_call_details():
    t3_on_call_list = list_handler.get_list_by_name('Spear_OnCall')
    return t3_on_call_list['analysts'], t3_on_call_list['rotation']


def announce_oncall_change():
    """announce shift change """

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {WEBEX_BOT_API_TOKEN}'
    }
    payload_json = {
        'roomId': ON_CALL_ANNOUNCE_ROOM_ID,
        'markdown': f'On-call person now is <@personEmail:{get_on_call_person()}>'
    }
    requests.post(WEBEX_API_URL, headers=headers, json=payload_json)


def alert_oncall_change():
    """alert shift change """

    today = date.today()
    coming_monday = today + timedelta(days=-today.weekday(), weeks=1)

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {WEBEX_BOT_API_TOKEN}'
    }
    payload_json = {
        'roomId': ALERT_ROOM_ID,
        'markdown': f'Next week\'s On-call person is <@personEmail:{get_on_call_email_by_monday_date(coming_monday)}>'
    }
    requests.post(WEBEX_API_URL, headers=headers, json=payload_json)


def get_rotation():
    """get on-call rotation"""
    rotation = get_on_call_details()[1]  # 0 index item is analysts
    now = datetime.now()
    last_to_last_monday = now - timedelta(days=now.weekday() + 7)
    weeks_after_last_to_last_monday = list(
        filter(
            lambda week: datetime.strptime(week['Monday_date'], '%Y-%m-%d') > last_to_last_monday,
            rotation
        )
    )
    return weeks_after_last_to_last_monday


def schedule_messages():
    """schedule"""
    schedule.every().friday.at("14:00", "America/New_York").do(alert_oncall_change)
    schedule.every().monday.at("08:00", "America/New_York").do(announce_oncall_change)
    # schedule.every(1).minutes.do(alert_shift_change)
    while True:
        # Check whether a scheduled task is pending to run or not
        schedule.run_pending()
        time.sleep(60)


def get_access_token():
    """get CS access token"""
    url = 'https://api.us-2.crowdstrike.com/oauth2/token'
    body = {
        'client_id': cs_client_id,
        'client_secret': cs_client_secret
    }
    response = requests.post(url, data=body)
    json_data = response.json()
    return json_data['access_token']


def get_device_id(host_name):
    """get CS asset ID"""
    url = 'https://api.us-2.crowdstrike.com/devices/queries/devices/v1?filter=hostname:' + '\'' + host_name + '\''
    headers = {
        'Authorization': f'Bearer {get_access_token()}'
    }
    response = requests.get(url, headers=headers)
    json_data = response.json()
    return json_data['resources'][0]


def get_device_status(host_name):
    """get device containment status"""
    url = 'https://api.us-2.crowdstrike.com/devices/entities/devices/v1'
    headers = {
        'content-type': 'application/json',
        'Authorization': f'Bearer {get_access_token()}'
    }
    params = {
        "ids": get_device_id(host_name)
    }
    response = requests.get(url, headers=headers, params=params)
    json_data = response.json()
    return json_data['resources'][0]['status']


class Who(Command):
    """Return who the on-call person is"""

    def __init__(self):
        super().__init__(
            command_keyword="who",
            help_message="On-Call",
            card=None,
        )

    def execute(self, message, attachment_actions, activity):
        return f"On-call person is <@personEmail:{get_on_call_person()}>"


class Rotation(Command):
    """Return who the on-call person is"""

    def __init__(self):
        super().__init__(
            command_keyword="rotation",
            card=None,
        )

    def execute(self, message, attachment_actions, activity):
        rotation = get_rotation()

        data_frame = pandas.DataFrame(rotation, columns=["Monday_date", "analyst_name"])
        data_frame.columns = ['Monday', 'Analyst']

        return data_frame.to_string(index=False)


class ContainmentStatusCS(Command):
    """Return the containment status of a host"""

    def __init__(self):
        super().__init__(
            command_keyword="status",
            card=None,
        )

    def execute(self, message, attachment_actions, activity):

        if message.strip() != "":
            host_name_cs = message.strip()
        else:
            host_name_cs = attachment_actions.inputs['host_name_cs'].strip()

        host_name_cs = host_name_cs.replace("METCIRT_Bot status", "").strip()
        if host_name_cs is None or host_name_cs == "":
            return "Please enter a host name and try again"

        try:
            return f'The containment status of {host_name_cs} in CS is {get_device_status(host_name_cs)}'
        except Exception as e:
            return f'There seems to be an issue with finding the host you entered. Please make sure the host is valid. Error: {str(e)}'


class GetAllOptions(Command):
    def __init__(self):
        super().__init__(
            command_keyword="options",
            help_message="More Commands",
            card=all_options_card,
        )

    def execute(self, message, attachment_actions, activity):
        pass


def main():
    bot = WebexBot(
        CONFIG.webex_bot_access_token_toodles,
        bot_name="Hello from Toodles!",
        approved_domains=['company.com']
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
    bot.add_command(ThreatHunt())
    bot.add_command(AZDOWorkItem())
    bot.add_command(GetAllOptions())

    bot.run()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
