"""Adaptive cards for Ticket Cannon Silencer & Noise Suppression management."""

from services.ticket_cannon_utils import SILENCER_FIELDS

# Build choices for the field dropdowns
_FIELD_CHOICES = [{"title": label, "value": key} for key, label in SILENCER_FIELDS.items()]

_EXPIRY_CHOICES = [
    {"title": "1 day", "value": "1"},
    {"title": "3 days", "value": "3"},
    {"title": "7 days", "value": "7"},
    {"title": "14 days", "value": "14"},
    {"title": "30 days", "value": "30"},
    {"title": "90 days", "value": "90"},
]


def _build_card(title, subtitle, category_value, create_keyword):
    """Build a silencer/suppressor card with a pre-set category (no dropdown)."""
    return {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.3",
        "body": [
            {
                "type": "TextBlock",
                "text": title,
                "horizontalAlignment": "Center",
                "weight": "Bolder",
                "size": "Large",
                "color": "Accent"
            },
            {
                "type": "TextBlock",
                "text": subtitle,
                "wrap": True,
                "horizontalAlignment": "Center",
                "isSubtle": True,
                "spacing": "Small"
            },
            {
                "type": "ActionSet",
                "spacing": "Small",
                "horizontalAlignment": "Center",
                "actions": [
                    {"type": "Action.OpenUrl", "title": "📋 View Current Entries", "url": "http://gdnr.the-company.com/ticket-cannon"},
                ],
            },
            {
                "type": "Container",
                "style": "emphasis",
                "spacing": "Medium",
                "items": [
                    # Description
                    {
                        "type": "ColumnSet",
                        "columns": [
                            {
                                "type": "Column", "width": 2,
                                "items": [{"type": "TextBlock", "text": "📋 Description", "horizontalAlignment": "Right", "weight": "Bolder", "color": "Accent"}],
                                "verticalContentAlignment": "Center"
                            },
                            {
                                "type": "Column", "width": 3,
                                "items": [{"type": "Input.Text", "id": "description", "placeholder": "e.g. CrowdStrike GitHub blocklist FPs", "isRequired": True}]
                            }
                        ]
                    },
                    # Expiry
                    {
                        "type": "ColumnSet",
                        "spacing": "Small",
                        "columns": [
                            {
                                "type": "Column", "width": 2,
                                "items": [{"type": "TextBlock", "text": "⏰ Expiry", "horizontalAlignment": "Right", "weight": "Bolder", "color": "Accent"}],
                                "verticalContentAlignment": "Center"
                            },
                            {
                                "type": "Column", "width": 3,
                                "items": [{"type": "Input.ChoiceSet", "id": "expiry_days", "value": "1", "choices": _EXPIRY_CHOICES}]
                            }
                        ]
                    },
                    # Separator
                    {"type": "TextBlock", "text": "🎯 Filter Fields (fill at least one pair)", "weight": "Bolder", "color": "Accent", "spacing": "Medium"},
                    # Field 1
                    {
                        "type": "ColumnSet",
                        "spacing": "Small",
                        "columns": [
                            {"type": "Column", "width": 2, "verticalContentAlignment": "Center", "items": [{"type": "Input.ChoiceSet", "id": "field1_key", "placeholder": "Field 1", "choices": _FIELD_CHOICES, "value": ""}]},
                            {"type": "Column", "width": 3, "verticalContentAlignment": "Center", "items": [{"type": "Input.Text", "id": "field1_value", "placeholder": "Exact value (copy from ticket)"}]}
                        ]
                    },
                    # Field 2
                    {
                        "type": "ColumnSet",
                        "spacing": "Small",
                        "columns": [
                            {"type": "Column", "width": 2, "verticalContentAlignment": "Center", "items": [{"type": "Input.ChoiceSet", "id": "field2_key", "placeholder": "Field 2 (optional)", "choices": _FIELD_CHOICES, "value": ""}]},
                            {"type": "Column", "width": 3, "verticalContentAlignment": "Center", "items": [{"type": "Input.Text", "id": "field2_value", "placeholder": "Exact value"}]}
                        ]
                    },
                    # Field 3
                    {
                        "type": "ColumnSet",
                        "spacing": "Small",
                        "columns": [
                            {"type": "Column", "width": 2, "verticalContentAlignment": "Center", "items": [{"type": "Input.ChoiceSet", "id": "field3_key", "placeholder": "Field 3 (optional)", "choices": _FIELD_CHOICES, "value": ""}]},
                            {"type": "Column", "width": 3, "verticalContentAlignment": "Center", "items": [{"type": "Input.Text", "id": "field3_value", "placeholder": "Exact value"}]}
                        ]
                    },
                    # Custom field (free-text key + value)
                    {"type": "TextBlock", "text": "🔧 Custom field (type any XSOAR field name)", "weight": "Bolder", "color": "Accent", "spacing": "Medium", "size": "Small"},
                    {
                        "type": "ColumnSet",
                        "spacing": "Small",
                        "columns": [
                            {"type": "Column", "width": 2, "verticalContentAlignment": "Center", "items": [{"type": "Input.Text", "id": "custom_key", "placeholder": "e.g. ioc_value"}]},
                            {"type": "Column", "width": 3, "verticalContentAlignment": "Center", "items": [{"type": "Input.Text", "id": "custom_value", "placeholder": "Exact value"}]}
                        ]
                    },
                ]
            },
            {
                "type": "ActionSet",
                "spacing": "Medium",
                "actions": [
                    {"type": "Action.Submit", "title": "➕ Create", "data": {"callback_keyword": create_keyword, "category": category_value}, "style": "destructive"},
                ],
                "horizontalAlignment": "Right"
            }
        ]
    }


TICKET_CANNON_CARD = _build_card(
    title="🔇 Ticket Cannon Silencer",
    subtitle="Suppress barrage tickets from noisy rule fires",
    category_value="ticket_cannon",
    create_keyword="create_silencer",
)

NOISE_SUPPRESSOR_CARD = _build_card(
    title="🔕 Noisy Rule Suppressor",
    subtitle="Suppress chronic false positives and benign true positives",
    category_value="noise_suppression",
    create_keyword="create_silencer",
)
