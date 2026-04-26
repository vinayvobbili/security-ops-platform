"""Adaptive cards for approved testing management."""

APPROVED_TESTING_CARD = {
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "type": "AdaptiveCard",
    "version": "1.3",
    "body": [
        {
            "type": "TextBlock",
            "text": "🧪 Approved Testing",
            "horizontalAlignment": "Center",
            "weight": "Bolder",
            "size": "Large",
            "color": "Accent"
        },
        {
            "type": "TextBlock",
            "text": "🛡️ Register security testing activities to prevent false positives",
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
                    "type": "ColumnSet",
                    "columns": [
                        {
                            "type": "Column",
                            "width": 2,
                            "items": [
                                {
                                    "type": "TextBlock",
                                    "text": "👤 Username(s)",
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
                                    "type": "Input.Text",
                                    "id": "usernames",
                                    "placeholder": "Use comma as separator",
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
                            "width": 2,
                            "items": [
                                {
                                    "type": "TextBlock",
                                    "text": "💻 Tester IPs/Hosts",
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
                                    "type": "Input.Text",
                                    "id": "ip_addresses_and_host_names_of_tester",
                                    "placeholder": "Use comma as separator",
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
                                    "text": "🎯 Target IPs/Hosts",
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
                                    "type": "Input.Text",
                                    "id": "ip_addresses_and_host_names_to_be_tested",
                                    "placeholder": "Use comma as separator",
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
                                    "text": "📋 Description",
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
                                    "type": "Input.Text",
                                    "id": "description",
                                    "isMultiline": True,
                                    "placeholder": "Describe the testing activity"
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
                                    "text": "📝 Notes/Scope",
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
                                    "type": "Input.Text",
                                    "id": "scope",
                                    "placeholder": "Testing scope details",
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
                                    "text": "⚔️ MITRE ATT&CK TTPs",
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
                                    "type": "Input.Text",
                                    "id": "ttps",
                                    "placeholder": "e.g. T1059, T1078, T1566.001",
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
                                    "text": "⏰ Keep until (5 PM ET)",
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
                                    "type": "Input.Date",
                                    "id": "expiry_date",
                                    "placeholder": "Select expiry date"
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
                    "title": "📋 View List",
                    "data": {
                        "callback_keyword": "current_approved_testing"
                    }
                },
                {
                    "type": "Action.Submit",
                    "title": "➖ Remove",
                    "data": {
                        "callback_keyword": "remove_approved_testing"
                    },
                    "style": "positive"
                },
                {
                    "type": "Action.Submit",
                    "title": "➕ Add",
                    "data": {
                        "callback_keyword": "add_approved_testing"
                    },
                    "style": "destructive"
                }
            ],
            "horizontalAlignment": "Right"
        }
    ]
}
