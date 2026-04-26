"""
XSOAR Script: Is From Ticket Cannon

Checks if the current incident matches any active Ticket Cannon Silencer filter.
If a match is found, sets context variables for the playbook to auto-close the ticket
and notify the Approved Testing Webex room.

The silencer list is managed via the IR web app — all edits go through the web UI
so that Webex notifications fire on every change.

List name: METCIRT_Ticket_Cannon_Silencer

Context outputs:
  - TicketCannonSilencer.IsMatch (bool): whether a silencer matched
  - TicketCannonSilencer.CloseNote (str): close note text if matched
  - TicketCannonSilencer.SilencerDescription (str): description of matched silencer
  - TicketCannonSilencer.SilencerId (str): id of matched silencer

Usage in XSOAR playbook:
  1. Add this script as a task after "Playbook Triggered"
  2. Add a conditional: if ${TicketCannonSilencer.IsMatch} == true → close ticket
"""
import json
import requests
from datetime import datetime

LIST_NAME = "METCIRT_Ticket_Cannon_Silencer"

# Fields that live at the top level of the incident (not under CustomFields)
TOP_LEVEL_FIELDS = {"name", "type", "severity"}


def get_incident_field(incident, custom_fields, labels_map, field_name):
    """Get a field value from the incident, checking top-level, CustomFields, then labels."""
    if field_name in TOP_LEVEL_FIELDS:
        val = incident.get(field_name, "")
    elif field_name in custom_fields:
        val = custom_fields.get(field_name, "")
    else:
        # Fall back to labels (stored as [{type, value}, ...])
        val = labels_map.get(field_name, "")

    # Normalize severity from int to string for matching
    if field_name == "severity" and isinstance(val, int):
        severity_map = {0: "Unknown", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
        val = severity_map.get(val, str(val))

    return str(val).strip() if val else ""


def check_silencer_match(silencer, incident, custom_fields, labels_map):
    """Check if all fields in a silencer match the incident (AND logic, exact match)."""
    fields = silencer.get("fields", {})
    if not fields:
        return False

    for field_name, expected_value in fields.items():
        actual_value = get_incident_field(incident, custom_fields, labels_map, field_name)
        if actual_value != expected_value.strip():
            return False

    return True


def get_webex_config():
    """Fetch Webex config from the METCIRT Webex list."""
    try:
        raw = demisto.executeCommand("getList", {"listName": "METCIRT Webex"})[0].get("Contents", "{}")
        return json.loads(raw) if raw else {}
    except Exception:
        return {}


def notify_webex_suppression(incident, silencer):
    """Send an Adaptive Card to the Webex room when a ticket is suppressed."""
    try:
        webex_config = get_webex_config()
        room_id = webex_config.get("channels", {}).get("vinay_test_dev", "")  # TODO: switch to security_testing_notifs for prod
        api_url = webex_config.get("api_url", "")
        bot_token = webex_config.get("METCIRT_Bot_access_token", "")

        if not (room_id and api_url and bot_token):
            return

        ticket_id = incident.get("id", "")
        ticket_name = incident.get("name", "Unknown")
        ticket_url = demisto.demistoUrls().get("investigation", "")
        desc = silencer.get("description", "N/A")
        created_by = silencer.get("created_by", "Unknown")
        match_count = silencer.get("match_count", 0)
        expiry = silencer.get("expiry_date", "N/A")

        # Build field facts for the card
        fields = silencer.get("fields", {})
        field_facts = [{"title": f"🔹 {k}", "value": v} for k, v in fields.items()]

        card = {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.3",
            "body": [
                # Header banner
                {
                    "type": "Container",
                    "style": "emphasis",
                    "bleed": True,
                    "items": [
                        {
                            "type": "ColumnSet",
                            "columns": [
                                {"type": "Column", "width": "auto", "items": [{"type": "TextBlock", "text": "🔇", "size": "ExtraLarge"}]},
                                {
                                    "type": "Column",
                                    "width": "stretch",
                                    "verticalContentAlignment": "Center",
                                    "items": [
                                        {"type": "TextBlock", "text": "🚨 TICKET SUPPRESSED", "size": "Large", "weight": "Bolder", "color": "Warning"},
                                        {"type": "TextBlock", "text": "Ticket Cannon Silencer auto-closed a matching ticket", "size": "Small", "color": "Light", "isSubtle": True, "spacing": "None"},
                                    ],
                                },
                                {"type": "Column", "width": "auto", "items": [{"type": "TextBlock", "text": "💥", "size": "ExtraLarge"}]},
                            ],
                        }
                    ],
                },
                # Ticket info
                {
                    "type": "Container",
                    "style": "accent",
                    "bleed": True,
                    "spacing": "None",
                    "items": [
                        {"type": "TextBlock", "text": f"🎫 #{ticket_id}  —  {ticket_name}", "size": "Large", "weight": "Bolder", "color": "Accent", "wrap": True},
                    ],
                },
                # Silencer details
                {
                    "type": "TextBlock",
                    "text": "🛡️ **Silencer Details**",
                    "separator": True,
                    "spacing": "Medium",
                    "color": "Good",
                    "size": "Medium",
                    "weight": "Bolder",
                },
                {
                    "type": "FactSet",
                    "spacing": "Small",
                    "facts": [
                        {"title": "📝 Description", "value": desc},
                        {"title": "👤 Created by", "value": created_by},
                        {"title": "🎯 Matches so far", "value": f"**{match_count}** ticket{'s' if match_count != 1 else ''}"},
                        {"title": "⏰ Expires", "value": expiry},
                    ],
                },
                # Matched fields
                {
                    "type": "TextBlock",
                    "text": "🔍 **Matched Fields**",
                    "separator": True,
                    "spacing": "Medium",
                    "color": "Attention",
                    "size": "Medium",
                    "weight": "Bolder",
                },
                {
                    "type": "FactSet",
                    "spacing": "Small",
                    "facts": field_facts if field_facts else [{"title": "None", "value": "—"}],
                },
                # Footer
                {
                    "type": "TextBlock",
                    "text": "🌐 [View all silencers on web dashboard](http://gdnr.the company.com/ticket-cannon)",
                    "spacing": "Medium",
                    "separator": True,
                    "size": "Small",
                    "horizontalAlignment": "Center",
                    "isSubtle": True,
                },
                # Open ticket button
                {
                    "type": "ActionSet",
                    "spacing": "Small",
                    "horizontalAlignment": "Right",
                    "actions": [
                        {"type": "Action.OpenUrl", "title": "🔗 Open Ticket in XSOAR", "url": ticket_url, "style": "positive"},
                    ],
                },
            ],
        }

        payload = json.dumps({
            "roomId": room_id,
            "text": f"Ticket Cannon Silencer suppressed #{ticket_id} {ticket_name}",
            "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}],
        })
        headers = {"Authorization": f"Bearer {bot_token}", "Content-Type": "application/json"}
        requests.post(url=api_url, headers=headers, data=payload)
    except Exception:
        pass  # Don't fail the script if notification fails


def main():
    """Check incident against all active, non-expired silencers."""
    # Fetch silencer list
    list_result = demisto.executeCommand("getList", {"listName": LIST_NAME})
    raw = list_result[0].get("Contents", "[]") if list_result else "[]"

    try:
        silencers = json.loads(raw) if raw and raw != "Item not found (8)" else []
    except (json.JSONDecodeError, TypeError):
        silencers = []

    if not silencers:
        return_results({
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": {"is_match": False},
            "HumanReadable": "No ticket cannon silencers configured.",
            "EntryContext": {
                "TicketCannonSilencer": {
                    "IsMatch": False,
                    "CloseNote": "",
                    "SilencerDescription": "",
                    "SilencerId": "",
                }
            },
        })
        return

    # Get incident data
    incident = demisto.incident()
    custom_fields = incident.get("CustomFields", {}) or {}
    # Build labels lookup: {label_type: label_value}
    labels_map = {}
    for label in (incident.get("labels") or []):
        if label.get("type") and label.get("value"):
            labels_map[label["type"]] = label["value"]
    today = datetime.now()

    matched_silencer = None
    matched_index = None

    for i, silencer in enumerate(silencers):
        # Skip inactive silencers
        if not silencer.get("active", False):
            continue

        # Skip expired silencers
        try:
            expiry = datetime.fromisoformat(silencer.get("expiry_date", "2000-01-01"))
            if expiry <= today:
                continue
        except ValueError:
            continue

        # Check if all fields match
        if check_silencer_match(silencer, incident, custom_fields, labels_map):
            matched_silencer = silencer
            matched_index = i
            break

    if matched_silencer:
        # Increment match count and save back
        silencers[matched_index]["match_count"] = silencers[matched_index].get("match_count", 0) + 1
        demisto.executeCommand("setList", {
            "listName": LIST_NAME,
            "listData": json.dumps(silencers, indent=2),
        })

        close_note = (
            f"Auto-closed by Ticket Cannon Silencer: {matched_silencer.get('description', 'N/A')} "
            f"(ID: {matched_silencer.get('id', 'N/A')}, "
            f"created by {matched_silencer.get('created_by', 'Unknown')}). "
            f"See IR web app /ticket-cannon for details."
        )

        # Set close note directly on the incident
        demisto.executeCommand("setIncident", {
            "closeNotes": close_note,
        })

        # Notify Webex room
        notify_webex_suppression(incident, matched_silencer)

        return_results({
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": {"is_match": True, "silencer_id": matched_silencer["id"]},
            "HumanReadable": f"**Ticket Cannon match found!** Silencer: {matched_silencer.get('description', 'N/A')}",
            "EntryContext": {
                "TicketCannonSilencer": {
                    "IsMatch": True,
                    "CloseNote": close_note,
                    "SilencerDescription": matched_silencer.get("description", ""),
                    "SilencerId": matched_silencer.get("id", ""),
                }
            },
        })
    else:
        return_results({
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": {"is_match": False},
            "HumanReadable": "No ticket cannon silencer match.",
            "EntryContext": {
                "TicketCannonSilencer": {
                    "IsMatch": False,
                    "CloseNote": "",
                    "SilencerDescription": "",
                    "SilencerId": "",
                }
            },
        })


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
