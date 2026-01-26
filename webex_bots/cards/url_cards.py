"""Adaptive cards for URL block verdict checking."""

URL_BLOCK_VERDICT_CARD = {
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "type": "AdaptiveCard",
    "version": "1.3",
    "body": [
        {
            "type": "TextBlock",
            "text": "🔗 Check URL Block Verdict",
            "wrap": True,
            "horizontalAlignment": "Center",
            "weight": "Bolder",
            "size": "Large",
            "color": "Accent"
        },
        {
            "type": "TextBlock",
            "text": "🛡️ Verify if URLs are blocked by security policies",
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
                    "text": "🌐 URLs to Check",
                    "weight": "Bolder",
                    "color": "Accent"
                },
                {
                    "type": "Input.Text",
                    "id": "urls_to_check",
                    "placeholder": "Enter URLs (comma-separated)",
                    "isRequired": True,
                    "errorMessage": "Required",
                    "isMultiline": True
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
                    "title": "🔍 Check Verdict",
                    "style": "positive",
                    "data": {
                        "callback_keyword": "url_verdict"
                    }
                }
            ]
        }
    ]
}
