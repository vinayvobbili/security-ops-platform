"""Navigation and options cards for Toodles bot."""

from .ticket_cards import IOC_HUNT, THREAT_HUNT
from .testing_cards import APPROVED_TESTING_CARD
from .import_cards import TICKET_IMPORT_CARD


def get_all_options_card():
    """Build the all_options_card with references to other cards.

    This is a function because it needs to reference other card definitions
    and we want to ensure imports are resolved correctly.
    """
    return {
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
                                },
                                {
                                    "type": "Action.Submit",
                                    "title": "Birthday & Anniversary",
                                    "data": {
                                        "callback_keyword": "get_birthday_anniversary_form"
                                    }
                                }
                            ]
                        }
                    ]
                }
            }
        ]
    }


# For backwards compatibility, create the card at module load time
all_options_card = get_all_options_card()
