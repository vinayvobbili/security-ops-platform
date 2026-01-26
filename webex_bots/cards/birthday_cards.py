"""Adaptive cards for birthday and work anniversary management."""

BIRTHDAY_ANNIVERSARY_CARD = {
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "type": "AdaptiveCard",
    "version": "1.3",
    "body": [
        {
            "type": "TextBlock",
            "text": "🎊 Birthday & Work Anniversary 🎊",
            "wrap": True,
            "horizontalAlignment": "Center",
            "weight": "Bolder",
            "size": "Large",
            "color": "Accent"
        },
        {
            "type": "TextBlock",
            "text": "✨ Help us celebrate your special days! Share your birthday and work anniversary so we can wish you well. ✨",
            "wrap": True,
            "spacing": "Medium",
            "horizontalAlignment": "Center",
            "color": "Good"
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
                                    "text": "👶 Birthday",
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
                                    "id": "birthday",
                                    "placeholder": "Select your birthday"
                                },
                                {
                                    "type": "TextBlock",
                                    "text": "*Year doesn't matter",
                                    "size": "Small",
                                    "isSubtle": True,
                                    "wrap": True,
                                    "spacing": "None"
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
                                    "text": "👔 Start Date",
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
                                    "id": "anniversary",
                                    "placeholder": "Select your start date"
                                }
                            ]
                        }
                    ],
                    "spacing": "Medium"
                }
            ]
        },
        {
            "type": "TextBlock",
            "text": "💡 *You can fill in one or both fields.*\\n*Leave blank if you prefer not to share.*",
            "size": "Small",
            "isSubtle": True,
            "wrap": True,
            "spacing": "Medium",
            "horizontalAlignment": "Center"
        },
        {
            "type": "ActionSet",
            "spacing": "Medium",
            "actions": [
                {
                    "type": "Action.Submit",
                    "title": "💾 Save",
                    "data": {
                        "callback_keyword": "save_birthday_anniversary"
                    },
                    "style": "positive"
                }
            ],
            "horizontalAlignment": "Right"
        }
    ]
}
