"""Adaptive card for URL block confirmation."""


BLOCK_URL_FORM_CARD = {
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "type": "AdaptiveCard",
    "version": "1.3",
    "body": [
        {
            "type": "TextBlock",
            "text": "🚫 Block URL",
            "wrap": True,
            "horizontalAlignment": "Center",
            "weight": "Bolder",
            "size": "Large",
            "color": "Attention"
        },
        {
            "type": "TextBlock",
            "text": "Route a URL/domain block through XSOAR",
            "horizontalAlignment": "Center",
            "size": "Small",
            "color": "Light",
            "spacing": "None",
            "wrap": True
        },
        {
            "type": "Input.Text",
            "id": "url",
            "label": "🌐 URL or Domain",
            "placeholder": "e.g. evil-domain.com",
            "isRequired": True,
            "errorMessage": "URL is required"
        },
        {
            "type": "Input.Text",
            "id": "xsoar_ticket_id",
            "label": "🎫 XSOAR Ticket # (optional)",
            "placeholder": "Leave blank to create a new ticket"
        },
        {
            "type": "Input.Text",
            "id": "reason",
            "label": "📝 Reason",
            "placeholder": "Why is this URL being blocked?",
            "isRequired": True,
            "errorMessage": "Reason is required",
            "isMultiline": True
        },
        {
            "type": "ActionSet",
            "spacing": "Medium",
            "horizontalAlignment": "Right",
            "actions": [
                {
                    "type": "Action.Submit",
                    "title": "🚫 Block URL",
                    "style": "destructive",
                    "data": {
                        "callback_keyword": "do_block_url"
                    }
                }
            ]
        }
    ]
}


def build_block_url_card(url: str) -> dict:
    """Build an Adaptive Card for confirming a URL block request.

    Args:
        url: The URL/domain to be blocked

    Returns:
        Adaptive Card JSON dict
    """
    return {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.3",
        "body": [
            {
                "type": "TextBlock",
                "text": "🚫 URL Block Request",
                "wrap": True,
                "horizontalAlignment": "Center",
                "weight": "Bolder",
                "size": "Large",
                "color": "Attention"
            },
            {
                "type": "Container",
                "style": "emphasis",
                "spacing": "Medium",
                "items": [
                    {
                        "type": "TextBlock",
                        "text": "URL to Block",
                        "weight": "Bolder",
                        "color": "Accent"
                    },
                    {
                        "type": "TextBlock",
                        "text": url,
                        "wrap": True,
                        "weight": "Bolder",
                        "size": "Medium",
                        "fontType": "Monospace"
                    }
                ]
            },
            {
                "type": "Container",
                "style": "emphasis",
                "spacing": "Medium",
                "items": [
                    {
                        "type": "TextBlock",
                        "text": "XSOAR Ticket ID (optional)",
                        "weight": "Bolder",
                        "color": "Accent"
                    },
                    {
                        "type": "Input.Text",
                        "id": "xsoar_ticket_id",
                        "placeholder": "Leave blank to create new",
                        "isRequired": False
                    }
                ]
            },
            {
                "type": "Container",
                "style": "emphasis",
                "spacing": "Medium",
                "items": [
                    {
                        "type": "TextBlock",
                        "text": "Reason",
                        "weight": "Bolder",
                        "color": "Accent"
                    },
                    {
                        "type": "Input.Text",
                        "id": "reason",
                        "placeholder": "Why is this URL being blocked?",
                        "isRequired": True,
                        "errorMessage": "Reason is required",
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
                        "title": "🚫 Confirm Block",
                        "style": "destructive",
                        "data": {
                            "callback_keyword": "confirm_block_url",
                            "url": url
                        }
                    }
                ]
            }
        ]
    }
