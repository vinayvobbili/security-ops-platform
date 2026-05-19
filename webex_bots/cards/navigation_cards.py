"""Navigation and options cards for Toodles bot.

Uses Action.Submit buttons instead of Action.ShowCard to keep the card
under Webex's size limit. Each button triggers the corresponding command
keyword, which loads the full card on-demand.
"""


def get_all_options_card():
    """Build a lightweight all-options card using submit buttons."""
    return {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.3",
        "body": [
            {
                "type": "TextBlock",
                "text": "📋 More Commands",
                "weight": "Bolder",
                "size": "Medium",
                "horizontalAlignment": "Center",
                "color": "Accent"
            },
            # --- Testing & Suppression ---
            {
                "type": "TextBlock",
                "text": "🧪 Testing & Suppression",
                "weight": "Bolder",
                "spacing": "Medium",
                "separator": True
            },
            {
                "type": "ActionSet",
                "spacing": "Small",
                "actions": [
                    {"type": "Action.Submit", "title": "🧪 Approved Testing", "data": {"callback_keyword": "testing"}, "style": "positive"},
                    {"type": "Action.Submit", "title": "🔇 Ticket Cannon Silencer", "data": {"callback_keyword": "silencer"}, "style": "positive"},
                    {"type": "Action.Submit", "title": "🔕 Noisy Rule Suppressor", "data": {"callback_keyword": "suppressor"}, "style": "destructive"},
                ]
            },
            # --- On-Call ---
            {
                "type": "TextBlock",
                "text": "📞 On-Call",
                "weight": "Bolder",
                "spacing": "Medium",
                "separator": True
            },
            {
                "type": "ActionSet",
                "spacing": "Small",
                "actions": [
                    {"type": "Action.Submit", "title": "👤 Who's On-Call", "data": {"callback_keyword": "who"}, "style": "positive"},
                    {"type": "Action.Submit", "title": "🔄 Rotation", "data": {"callback_keyword": "rotation"}, "style": "positive"},
                ]
            },
            # --- CrowdStrike ---
            {
                "type": "TextBlock",
                "text": "🦅 CrowdStrike",
                "weight": "Bolder",
                "spacing": "Medium",
                "separator": True
            },
            {
                "type": "ColumnSet",
                "spacing": "Small",
                "columns": [
                    {
                        "type": "Column", "width": "stretch",
                        "items": [{"type": "Input.Text", "id": "host_name_cs", "placeholder": "Hostname for CS actions"}]
                    }
                ]
            },
            {
                "type": "ActionSet",
                "spacing": "Small",
                "actions": [
                    {"type": "Action.Submit", "title": "🔍 Check Status", "data": {"callback_keyword": "status"}, "style": "positive"},
                    {"type": "Action.Submit", "title": "🔓 Uncontain", "data": {"callback_keyword": "uncontain"}, "style": "positive"},
                    {"type": "Action.Submit", "title": "🔒 Contain", "data": {"callback_keyword": "contain"}, "style": "destructive"},
                ]
            },
            {
                "type": "ActionSet",
                "spacing": "Small",
                "actions": [
                    {"type": "Action.Submit", "title": "🌐 Browser History", "data": {"callback_keyword": "get_browser_history_card"}, "style": "positive"},
                    {"type": "Action.Submit", "title": "🚫 Block URL", "data": {"callback_keyword": "get_block_url_form"}, "style": "destructive"},
                ]
            },
            # --- XSOAR ---
            {
                "type": "TextBlock",
                "text": "📋 XSOAR",
                "weight": "Bolder",
                "spacing": "Medium",
                "separator": True
            },
            {
                "type": "ActionSet",
                "spacing": "Small",
                "actions": [
                    {"type": "Action.Submit", "title": "📝 Create Ticket", "data": {"callback_keyword": "get_x_ticket_form"}, "style": "positive"},
                    {"type": "Action.Submit", "title": "🎯 IOC Hunt", "data": {"callback_keyword": "ioc"}, "style": "destructive"},
                    {"type": "Action.Submit", "title": "🕵️ Threat Hunt", "data": {"callback_keyword": "show_threat_hunt_form"}, "style": "destructive"},
                    {"type": "Action.Submit", "title": "📥 Import Ticket", "data": {"callback_keyword": "import"}, "style": "positive"},
                    {"type": "Action.Submit", "title": "🔎 Search X", "data": {"callback_keyword": "get_search_xsoar_card"}, "style": "positive"},
                ]
            },
            # --- Misc ---
            {
                "type": "TextBlock",
                "text": "🔧 Misc",
                "weight": "Bolder",
                "spacing": "Medium",
                "separator": True
            },
            {
                "type": "ActionSet",
                "spacing": "Small",
                "actions": [
                    {"type": "Action.Submit", "title": "🔗 Fav URLs", "data": {"callback_keyword": "urls"}, "style": "positive"},
                    {"type": "Action.Submit", "title": "🏖️ Holidays", "data": {"callback_keyword": "holidays"}, "style": "positive"},
                    {"type": "Action.Submit", "title": "🎂 Birthday & Anniversary", "data": {"callback_keyword": "get_birthday_anniversary_form"}, "style": "positive"},
                    {"type": "Action.Submit", "title": "💼 AZDO Work Item", "data": {"callback_keyword": "azdo"}, "style": "positive"},
                    {"type": "Action.Submit", "title": "🌐 Domain Lookalike", "data": {"callback_keyword": "domain_lookalike"}, "style": "destructive"},
                    {"type": "Action.Submit", "title": "🕵️ Person of Interest", "data": {"callback_keyword": "poi"}, "style": "destructive"},
                    {"type": "Action.Submit", "title": "🚫 URL Block Verdict", "data": {"callback_keyword": "get_url_block_verdict_form"}, "style": "destructive"},
                    {"type": "Action.Submit", "title": "🔧 Tuning Request", "data": {"callback_keyword": "tuning"}, "style": "positive"},
                    {"type": "Action.Submit", "title": "📇 Contacts", "data": {"callback_keyword": "contacts"}, "style": "positive"},
                ]
            },
        ]
    }


# For backwards compatibility, create the card at module load time
all_options_card = get_all_options_card()
