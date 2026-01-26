"""Adaptive cards for XSOAR ticket and hunt creation."""

NEW_TICKET_CARD = {
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "type": "AdaptiveCard",
    "version": "1.3",
    "body": [
        {
            "type": "TextBlock",
            "text": "🎫 New X Ticket",
            "color": "Accent",
            "weight": "Bolder",
            "size": "Large",
            "horizontalAlignment": "Center"
        },
        {
            "type": "Container",
            "style": "emphasis",
            "spacing": "Medium",
            "items": [
                {
                    "type": "ColumnSet",
                    "columns": [
                        {
                            "type": "Column",
                            "width": 2,
                            "items": [
                                {
                                    "type": "TextBlock",
                                    "text": "📝 Title",
                                    "wrap": True,
                                    "horizontalAlignment": "Right",
                                    "weight": "Bolder",
                                    "color": "Accent"
                                }
                            ],
                            "verticalContentAlignment": "Center"
                        },
                        {
                            "type": "Column",
                            "width": 5,
                            "items": [
                                {
                                    "type": "Input.Text",
                                    "id": "title",
                                    "placeholder": "Enter ticket title"
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
                            "width": 2,
                            "items": [
                                {
                                    "type": "TextBlock",
                                    "text": "📋 Details",
                                    "wrap": True,
                                    "horizontalAlignment": "Right",
                                    "weight": "Bolder",
                                    "color": "Accent"
                                }
                            ],
                            "verticalContentAlignment": "Center"
                        },
                        {
                            "type": "Column",
                            "width": 5,
                            "items": [
                                {
                                    "type": "Input.Text",
                                    "id": "details",
                                    "placeholder": "Describe the issue",
                                    "isMultiline": True
                                }
                            ]
                        }
                    ],
                    "spacing": "Small"
                },
                {
                    "type": "ColumnSet",
                    "columns": [
                        {
                            "type": "Column",
                            "width": 2,
                            "items": [
                                {
                                    "type": "TextBlock",
                                    "text": "🔍 Detection Source",
                                    "wrap": True,
                                    "horizontalAlignment": "Right",
                                    "weight": "Bolder",
                                    "color": "Accent"
                                }
                            ],
                            "verticalContentAlignment": "Center"
                        },
                        {
                            "type": "Column",
                            "width": 3,
                            "items": [
                                {
                                    "type": "Input.ChoiceSet",
                                    "id": "detection_source",
                                    "choices": [
                                        {"title": "Threat Hunt", "value": "Threat Hunt"},
                                        {"title": "CrowdStrike Falcon", "value": "CrowdStrike Falcon"},
                                        {"title": "Employee Reported", "value": "Employee Reported"},
                                        {"title": "Recorded Future", "value": "Recorded Future"},
                                        {"title": "Third Party", "value": "Third Party"},
                                        {"title": "Abnormal Security", "value": "Abnormal Security"},
                                        {"title": "Akamai", "value": "Akamai"},
                                        {"title": "AppDynamics", "value": "AppDynamics"},
                                        {"title": "Area1", "value": "Area1"},
                                        {"title": "Cisco AMP", "value": "Cisco AMP"},
                                        {"title": "CrowdStrike Falcon IDP", "value": "CrowdStrike Falcon IDP"},
                                        {"title": "Customer Reported", "value": "Customer Reported"},
                                        {"title": "Cyberbit", "value": "Cyberbit"},
                                        {"title": "Flashpoint", "value": "Flashpoint"},
                                        {"title": "ForcePoint", "value": "ForcePoint"},
                                        {"title": "Illusive", "value": "Illusive"},
                                        {"title": "Infoblox", "value": "Infoblox"},
                                        {"title": "Intel471", "value": "Intel471"},
                                        {"title": "IronPort", "value": "IronPort"},
                                        {"title": "Lumen", "value": "Lumen"},
                                        {"title": "PaloAlto", "value": "PaloAlto"},
                                        {"title": "Prisma Cloud", "value": "Prisma Cloud"},
                                        {"title": "Rubrik", "value": "Rubrik"},
                                        {"title": "Tanium", "value": "Tanium"},
                                        {"title": "Vectra MDR", "value": "Vectra MDR"},
                                        {"title": "ZeroFox", "value": "ZeroFox"},
                                        {"title": "ZScaler", "value": "ZScaler"},
                                        {"title": "Other", "value": "Other"}
                                    ],
                                    "placeholder": "Select source",
                                    "isRequired": True,
                                    "errorMessage": "Required"
                                }
                            ]
                        }
                    ],
                    "spacing": "Small"
                }
            ]
        },
        {
            "type": "ActionSet",
            "spacing": "Medium",
            "actions": [
                {
                    "type": "Action.Submit",
                    "title": "🚀 Submit",
                    "data": {
                        "callback_keyword": "create_x_ticket"
                    },
                    "style": "positive"
                }
            ],
            "horizontalAlignment": "Right"
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
            "text": "🎯 IOC Hunt",
            "wrap": True,
            "horizontalAlignment": "Center",
            "weight": "Bolder",
            "size": "Large",
            "color": "Accent"
        },
        {
            "type": "TextBlock",
            "text": "🔎 Search for Indicators of Compromise across your environment",
            "wrap": True,
            "horizontalAlignment": "Center",
            "isSubtle": True,
            "spacing": "Small"
        },
        {
            "type": "Container",
            "style": "emphasis",
            "spacing": "Medium",
            "items": [
                {
                    "type": "TextBlock",
                    "text": "📝 Hunt Title",
                    "wrap": True,
                    "weight": "Bolder",
                    "color": "Accent"
                },
                {
                    "type": "Input.Text",
                    "id": "ioc_hunt_title",
                    "placeholder": "Enter a descriptive title"
                },
                {
                    "type": "TextBlock",
                    "text": "🚨 IOCs",
                    "wrap": True,
                    "weight": "Bolder",
                    "color": "Accent",
                    "spacing": "Medium"
                },
                {
                    "type": "Input.Text",
                    "id": "ioc_hunt_iocs",
                    "placeholder": "Domains / Email Addresses / Files (one per line)",
                    "isMultiline": True
                }
            ]
        },
        {
            "type": "ActionSet",
            "spacing": "Medium",
            "actions": [
                {
                    "type": "Action.Submit",
                    "title": "🚀 Start Hunt",
                    "data": {
                        "callback_keyword": "ioc_hunt"
                    },
                    "style": "positive"
                }
            ],
            "horizontalAlignment": "Right"
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
            "text": "🕵️ Threat Hunt",
            "wrap": True,
            "horizontalAlignment": "Center",
            "weight": "Bolder",
            "size": "Large",
            "color": "Attention"
        },
        {
            "type": "TextBlock",
            "text": "🔬 Proactively search for threats in your environment",
            "wrap": True,
            "horizontalAlignment": "Center",
            "isSubtle": True,
            "spacing": "Small"
        },
        {
            "type": "Container",
            "style": "emphasis",
            "spacing": "Medium",
            "items": [
                {
                    "type": "TextBlock",
                    "text": "📝 Hunt Title",
                    "wrap": True,
                    "weight": "Bolder",
                    "color": "Accent"
                },
                {
                    "type": "Input.Text",
                    "id": "threat_hunt_title",
                    "placeholder": "Enter hunt title"
                },
                {
                    "type": "TextBlock",
                    "text": "📋 Hunt Description",
                    "wrap": True,
                    "weight": "Bolder",
                    "color": "Accent",
                    "spacing": "Medium"
                },
                {
                    "type": "Input.Text",
                    "id": "threat_hunt_desc",
                    "placeholder": "Describe the threat hypothesis and hunt methodology",
                    "isMultiline": True
                }
            ]
        },
        {
            "type": "ActionSet",
            "spacing": "Medium",
            "actions": [
                {
                    "type": "Action.Submit",
                    "title": "🎯 Start Hunt",
                    "data": {
                        "callback_keyword": "threat_hunt"
                    },
                    "style": "positive"
                }
            ],
            "horizontalAlignment": "Right"
        }
    ]
}
