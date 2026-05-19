"""Adaptive cards for Person-of-Interest OSINT investigations."""

POI_INVESTIGATE_CARD = {
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "type": "AdaptiveCard",
    "version": "1.3",
    "body": [
        {
            "type": "TextBlock",
            "text": "🕵️ Person of Interest — OSINT",
            "horizontalAlignment": "Center",
            "weight": "Bolder",
            "size": "Large",
            "color": "Accent",
        },
        {
            "type": "TextBlock",
            "text": "Breach data · username footprint · email account checks",
            "wrap": True,
            "spacing": "Small",
            "isSubtle": True,
            "horizontalAlignment": "Center",
        },
        {
            "type": "Container",
            "style": "emphasis",
            "spacing": "Medium",
            "items": [
                {
                    "type": "TextBlock",
                    "text": "Fill in at least one identifier. More = better.",
                    "size": "Small",
                    "isSubtle": True,
                    "wrap": True,
                },
                {"type": "TextBlock", "text": "👤 Full Name", "weight": "Bolder", "color": "Accent", "spacing": "Medium"},
                {"type": "Input.Text", "id": "poi_name", "placeholder": "Jane Doe"},
                {"type": "TextBlock", "text": "🆔 Username / Handle", "weight": "Bolder", "color": "Accent", "spacing": "Medium"},
                {"type": "Input.Text", "id": "poi_username", "placeholder": "janedoe42"},
                {"type": "TextBlock", "text": "📧 Email", "weight": "Bolder", "color": "Accent", "spacing": "Medium"},
                {"type": "Input.Text", "id": "poi_email", "placeholder": "jane@example.com", "style": "Email"},
                {"type": "TextBlock", "text": "📝 Reason for investigation", "weight": "Bolder", "color": "Accent", "spacing": "Medium"},
                {"type": "Input.Text", "id": "poi_reason", "placeholder": "e.g. insider threat triage on X#12345", "isMultiline": True},
            ],
        },
        {
            "type": "ActionSet",
            "spacing": "Medium",
            "horizontalAlignment": "Right",
            "actions": [
                {
                    "type": "Action.Submit",
                    "title": "🔎 Investigate",
                    "style": "destructive",
                    "data": {"callback_keyword": "poi_investigate"},
                }
            ],
        },
    ],
}
