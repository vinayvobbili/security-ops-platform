"""Adaptive cards for Ticket Cannon Silencer & Noise Suppression.

Creation moved to the login-gated web dashboard so every silencer carries an
authenticated owner + audit trail and is RBAC-gated (only SOC analysts /
response engineers can suppress detections). These Toodles cards no longer
collect input — they just deep-link analysts to the web app. The old in-card
create flow (and the `create_silencer` command) was retired.
"""

from my_config import get_config

CONFIG = get_config()

_DASHBOARD_URL = f"https://gdnr.{CONFIG.my_web_domain}/ticket-cannon"


def _build_redirect_card(title, subtitle):
    """A small card that points analysts at the web silencer dashboard."""
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
                "color": "Accent",
            },
            {
                "type": "TextBlock",
                "text": subtitle,
                "wrap": True,
                "horizontalAlignment": "Center",
                "isSubtle": True,
                "spacing": "Small",
            },
            {
                "type": "Container",
                "style": "emphasis",
                "spacing": "Medium",
                "items": [
                    {
                        "type": "TextBlock",
                        "text": (
                            "🔐 Creating and managing entries now lives in the web app "
                            "(login-gated for audit). It has a searchable field picker "
                            "with examples — pick **File Path**, **Command Line**, "
                            "**Parent CMD line**, etc. and paste the value from the "
                            "ticket, no API-key guessing.\n\nOpen the dashboard below to "
                            "add or manage an entry."
                        ),
                        "wrap": True,
                    },
                ],
            },
            {
                "type": "ActionSet",
                "spacing": "Medium",
                "horizontalAlignment": "Center",
                "actions": [
                    {"type": "Action.OpenUrl", "title": "🌐 Open Silencer Dashboard", "url": _DASHBOARD_URL},
                ],
            },
        ],
    }


TICKET_CANNON_CARD = _build_redirect_card(
    title="🔇 Ticket Cannon Silencer",
    subtitle="Suppress barrage tickets from noisy rule fires",
)

NOISE_SUPPRESSOR_CARD = _build_redirect_card(
    title="🔕 Noisy Rule Suppressor",
    subtitle="Suppress chronic false positives and benign true positives",
)
