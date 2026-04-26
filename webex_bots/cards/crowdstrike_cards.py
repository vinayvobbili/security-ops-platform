"""Adaptive cards for CrowdStrike operations."""

FILE_PULL_CARD = {
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "type": "AdaptiveCard",
    "version": "1.3",
    "body": [
        {
            "type": "TextBlock",
            "text": "📁 File Pull",
            "horizontalAlignment": "Center",
            "weight": "Bolder",
            "size": "Large",
            "color": "Good"
        },
        {
            "type": "TextBlock",
            "text": "Pull a file from an endpoint via CrowdStrike RTR",
            "horizontalAlignment": "Center",
            "size": "Small",
            "color": "Light",
            "spacing": "None",
            "wrap": True
        },
        {
            "type": "Input.Text",
            "id": "ticket_number",
            "label": "🎫 XSOAR Ticket #",
            "placeholder": "e.g. 929947",
            "isRequired": True,
            "errorMessage": "Please enter a ticket number"
        },
        {
            "type": "Input.Text",
            "id": "file_path",
            "label": "📂 File Path on Endpoint",
            "placeholder": r"C:\Users\jsmith\Documents\file.xlsx",
            "isRequired": True,
            "errorMessage": "Please enter a file path"
        },
        {
            "type": "ActionSet",
            "spacing": "Medium",
            "actions": [
                {
                    "type": "Action.Submit",
                    "title": "📥 Pull File",
                    "style": "positive",
                    "data": {
                        "callback_keyword": "fetch_file_pull"
                    }
                }
            ]
        }
    ]
}

BROWSER_HISTORY_CARD = {
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "type": "AdaptiveCard",
    "version": "1.3",
    "body": [
        {
            "type": "TextBlock",
            "text": "🌐 Browser History",
            "horizontalAlignment": "Center",
            "weight": "Bolder",
            "size": "Large",
            "color": "Good"
        },
        {
            "type": "TextBlock",
            "text": "Collect Chrome, Edge & Firefox history from a Windows endpoint via CrowdStrike RTR",
            "horizontalAlignment": "Center",
            "size": "Small",
            "color": "Light",
            "spacing": "None",
            "wrap": True
        },
        {
            "type": "Input.Text",
            "id": "ticket_number",
            "label": "🎫 XSOAR Ticket #",
            "placeholder": "e.g. 929947",
            "isRequired": True,
            "errorMessage": "Please enter a ticket number"
        },
        {
            "type": "ActionSet",
            "spacing": "Medium",
            "actions": [
                {
                    "type": "Action.Submit",
                    "title": "🔍 Collect",
                    "style": "positive",
                    "data": {
                        "callback_keyword": "fetch_browser_history"
                    }
                }
            ]
        }
    ]
}
