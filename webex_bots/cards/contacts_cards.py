"""Adaptive cards for escalation contacts management."""

CONTACTS_URL = "http://gdnr.the-company.com/escalation-contacts"

CONTACTS_MENU_CARD = {
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "type": "AdaptiveCard",
    "version": "1.3",
    "body": [
        {
            "type": "TextBlock",
            "text": "📇 Escalation Contacts",
            "wrap": True,
            "horizontalAlignment": "Center",
            "weight": "Bolder",
            "size": "Large",
            "color": "Accent"
        },
        {
            "type": "TextBlock",
            "text": "View or manage the team's escalation contact list.",
            "wrap": True,
            "spacing": "Medium",
            "horizontalAlignment": "Center",
            "isSubtle": True
        },
    ],
    "actions": [
        {
            "type": "Action.OpenUrl",
            "title": "📋 Show All",
            "url": CONTACTS_URL,
            "style": "positive"
        },
        {
            "type": "Action.Submit",
            "title": "➕ Add New",
            "data": {"callback_keyword": "get_contacts_add_form"},
            "style": "positive"
        }
    ]
}


def build_contacts_add_card(regions):
    """Build the Add New Contact form card with dynamic region choices."""
    region_choices = [{"title": r, "value": r} for r in regions]
    region_choices.append({"title": "+ New Region...", "value": "__new__"})

    return {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.3",
        "body": [
            {
                "type": "TextBlock",
                "text": "➕ Add New Contact",
                "wrap": True,
                "horizontalAlignment": "Center",
                "weight": "Bolder",
                "size": "Large",
                "color": "Accent"
            },
            {
                "type": "Container",
                "style": "emphasis",
                "spacing": "Medium",
                "items": [
                    # Region
                    {
                        "type": "TextBlock",
                        "text": "Region *",
                        "weight": "Bolder",
                        "spacing": "Small"
                    },
                    {
                        "type": "Input.ChoiceSet",
                        "id": "region",
                        "placeholder": "Select region",
                        "choices": region_choices,
                        "isRequired": True
                    },
                    {
                        "type": "Input.Text",
                        "id": "custom_region",
                        "placeholder": "Enter new region name (only if '+ New Region...' selected)"
                    },
                    # Team
                    {
                        "type": "TextBlock",
                        "text": "Team *",
                        "weight": "Bolder",
                        "spacing": "Small"
                    },
                    {
                        "type": "Input.Text",
                        "id": "team",
                        "placeholder": "e.g. EMEA-CIRT, LATAM POC",
                        "isRequired": True
                    },
                    # Name
                    {
                        "type": "TextBlock",
                        "text": "Name *",
                        "weight": "Bolder",
                        "spacing": "Small"
                    },
                    {
                        "type": "Input.Text",
                        "id": "name",
                        "placeholder": "Contact full name",
                        "isRequired": True
                    },
                    # Title
                    {
                        "type": "TextBlock",
                        "text": "Title",
                        "weight": "Bolder",
                        "spacing": "Small"
                    },
                    {
                        "type": "Input.Text",
                        "id": "title",
                        "placeholder": "Job title / role"
                    },
                    # Email
                    {
                        "type": "TextBlock",
                        "text": "Email",
                        "weight": "Bolder",
                        "spacing": "Small"
                    },
                    {
                        "type": "Input.Text",
                        "id": "email",
                        "placeholder": "Email address",
                        "style": "Email"
                    },
                    # Phone
                    {
                        "type": "TextBlock",
                        "text": "Phone",
                        "weight": "Bolder",
                        "spacing": "Small"
                    },
                    {
                        "type": "Input.Text",
                        "id": "phone",
                        "placeholder": "Phone number",
                        "style": "Tel"
                    },
                ]
            },
        ],
        "actions": [
            {
                "type": "Action.Submit",
                "title": "💾 Save Contact",
                "data": {"callback_keyword": "add_new_contact"},
                "style": "positive"
            }
        ]
    }
