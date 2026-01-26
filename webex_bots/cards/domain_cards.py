"""Adaptive cards for domain lookalike scanning."""

DOMAIN_LOOKALIKE_CARD = {
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "type": "AdaptiveCard",
    "version": "1.3",
    "body": [
        {
            "type": "TextBlock",
            "text": "🔍 Domain Lookalike Scanner",
            "horizontalAlignment": "Center",
            "weight": "Bolder",
            "size": "Large",
            "color": "Accent"
        },
        {
            "type": "TextBlock",
            "text": "🛡️ Detect typosquatting and homograph attacks",
            "wrap": True,
            "spacing": "Small",
            "isSubtle": True,
            "horizontalAlignment": "Center"
        },
        {
            "type": "Container",
            "style": "emphasis",
            "spacing": "Medium",
            "items": [
                {
                    "type": "TextBlock",
                    "text": "🌐 Domain to Scan",
                    "weight": "Bolder",
                    "color": "Accent"
                },
                {
                    "type": "Input.Text",
                    "id": "domain",
                    "placeholder": "example.com",
                    "isRequired": True,
                    "errorMessage": "Please enter a valid domain"
                },
                {
                    "type": "Input.Toggle",
                    "id": "registered_only",
                    "title": "🔎 Perform DNS resolution to find registered domains",
                    "value": "false",
                    "wrap": True
                },
                {
                    "type": "TextBlock",
                    "text": "⚡ **OFF:** Fast scan - generates lookalike variations\n🐢 **ON:** Slow scan - checks DNS for real threats",
                    "size": "Small",
                    "isSubtle": True,
                    "wrap": True,
                    "spacing": "Small"
                }
            ]
        },
        {
            "type": "ActionSet",
            "spacing": "Medium",
            "horizontalAlignment": "Right",
            "actions": [
                {
                    "type": "Action.Submit",
                    "title": "🚀 Start Scan",
                    "style": "positive",
                    "data": {
                        "callback_keyword": "domain_lookalike_scan"
                    }
                }
            ]
        }
    ]
}
