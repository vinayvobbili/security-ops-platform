import ipaddress
from datetime import datetime, timedelta

from pytz import timezone
from webexteamssdk import WebexTeamsAPI

from my_config import get_config

CONFIG = get_config()


def add_approved_testing_entry(
        list_handler,
        approved_testing_list_name,
        approved_testing_master_list_name,
        usernames,
        items_of_tester,
        items_to_be_tested,
        description,
        scope,
        submitter,
        expiry_date,
        submitter_ip_address,
        submit_date=None,
        ttps=None,
):
    """
    Adds an approved testing entry to both the current and master lists.
    announce_func: optional function to call with the new item for notifications.
    Returns: (current_entries, master_entries, new_item)
    """
    if not (usernames or items_of_tester or items_to_be_tested):
        raise ValueError("At least one of Usernames, Tester Hosts, or Targets must be filled.")

    if not expiry_date:
        expiry_date = (datetime.now(timezone('US/Eastern')) + timedelta(days=1)).strftime("%Y-%m-%d")
    if not submit_date:
        submit_date = datetime.now().strftime("%m/%d/%Y")

    current_entries = list_handler.get_list_data_by_name(approved_testing_list_name)
    master_entries = list_handler.get_list_data_by_name(approved_testing_master_list_name)

    all_items = (items_of_tester + ', ' + items_to_be_tested).strip(', ')
    usernames_list = [u.strip() for u in usernames.split(',')] if usernames else []
    items_list = [i.strip() for i in all_items.split(',')] if all_items else []

    # Add usernames
    for username in usernames_list:
        if username:
            current_entries.get("USERNAMES").append({
                "data": username, "expiry_date": expiry_date, "submitter": submitter
            })
            master_entries.append({
                "username": username,
                "description": description,
                "scope": scope,
                "ttps": ttps,
                "submitter": submitter,
                "submit_date": submit_date,
                "expiry_date": expiry_date,
                "submitter_ip_address": submitter_ip_address
            })
    # Add IPs/hostnames
    for item in items_list:
        if not item:
            continue
        try:
            ipaddress.ip_address(item)
            is_ip = True
            is_cidr = False
        except ValueError:
            # Check if it's a CIDR block
            try:
                ipaddress.ip_network(item, strict=False)
                is_ip = False
                is_cidr = True
            except ValueError:
                is_ip = False
                is_cidr = False
        if is_ip:
            current_entries.get("IP_ADDRESSES").append(
                {"data": item, "expiry_date": expiry_date, "submitter": submitter})
            master_entries.append({
                "ip_address": item,
                "description": description,
                "scope": scope,
                "ttps": ttps,
                "submitter": submitter,
                "submit_date": submit_date,
                "expiry_date": expiry_date,
                "submitter_ip_address": submitter_ip_address,
            })
        elif is_cidr:
            current_entries.get("CIDR_BLOCKS").append(
                {"data": item, "expiry_date": expiry_date, "submitter": submitter})
            master_entries.append({
                "cidr_block": item,
                "description": description,
                "scope": scope,
                "ttps": ttps,
                "submitter": submitter,
                "submit_date": submit_date,
                "expiry_date": expiry_date,
                "submitter_ip_address": submitter_ip_address,
            })
        else:
            current_entries.get("ENDPOINTS").append(
                {"data": item, "expiry_date": expiry_date, "submitter": submitter})
            master_entries.append({
                "host_name": item,
                "description": description,
                "scope": scope,
                "ttps": ttps,
                "submitter": submitter,
                "submit_date": submit_date,
                "expiry_date": expiry_date,
                "submitter_ip_address": submitter_ip_address,
            })
    list_handler.save(approved_testing_list_name, current_entries)
    list_handler.save(approved_testing_master_list_name, master_entries)

    # Persist TTPs to threat intel dashboard DB for red team visibility
    if ttps:
        try:
            from services.threat_intel_db import insert_approved_testing_ttps
            insert_approved_testing_ttps(ttps, submitter=submitter, description=description, expiry_date=expiry_date)
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Failed to insert approved testing TTPs to DB: {e}")

    new_item = {
        "description": description,
        "scope": scope,
        "ttps": ttps,
        "submitter": submitter,
        "submit_date": submit_date,
        "expiry_date": expiry_date,
        "usernames": ', '.join(usernames_list),
        "items_of_tester": items_of_tester,
        "items_to_be_tested": items_to_be_tested
    }
    announce_new_approved_testing_entry(new_item)


def announce_new_approved_testing_entry(new_item) -> None:
    payload = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.3",
        "body": [
            {
                "type": "Container",
                "style": "emphasis",
                "bleed": True,
                "items": [
                    {
                        "type": "ColumnSet",
                        "columns": [
                            {
                                "type": "Column",
                                "width": "auto",
                                "items": [{"type": "TextBlock", "text": "🛡️", "size": "Medium"}]
                            },
                            {
                                "type": "Column",
                                "width": "stretch",
                                "verticalContentAlignment": "center",
                                "items": [
                                    {
                                        "type": "TextBlock",
                                        "text": "New approved testing",
                                        "size": "Medium",
                                        "weight": "Bolder",
                                        "color": "Light"
                                    },
                                    {
                                        "type": "TextBlock",
                                        "text": "Penetration test authorization recorded",
                                        "size": "Small",
                                        "color": "Light",
                                        "isSubtle": True,
                                        "spacing": "None"
                                    }
                                ]
                            },
                            {
                                "type": "Column",
                                "width": "auto",
                                "items": [{"type": "TextBlock", "text": "✅", "size": "Medium"}]
                            }
                        ]
                    }
                ]
            },
            {
                "type": "TextBlock",
                "text": "📋 **Details**",
                "spacing": "Medium",
                "color": "Accent"
            },
            {
                "type": "FactSet",
                "spacing": "Small",
                "facts": [
                    {"title": "👤 Submitter", "value": new_item.get('submitter', 'n/a')},
                    {"title": "📝 Description", "value": new_item.get('description', 'n/a')},
                    {"title": "🔑 Username(s)", "value": new_item.get('usernames', 'n/a')}
                ]
            },
            {
                "type": "TextBlock",
                "text": "🌐 **Network scope**",
                "separator": True,
                "spacing": "Medium",
                "color": "Accent"
            },
            {
                "type": "Container",
                "style": "accent",
                "bleed": True,
                "spacing": "Small",
                "items": [
                    {
                        "type": "FactSet",
                        "facts": [
                            {"title": "🖥️ IPs/Hostnames/CIDRs of Tester", "value": new_item.get('items_of_tester', 'n/a')},
                            {"title": "🎯 IPs/Hostnames/CIDRs to be tested", "value": new_item.get('items_to_be_tested', 'n/a')}
                        ]
                    }
                ]
            },
            {
                "type": "TextBlock",
                "text": "⚔️ **Attack details**",
                "separator": True,
                "spacing": "Medium",
                "color": "Accent"
            },
            {
                "type": "FactSet",
                "spacing": "Small",
                "facts": [
                    {"title": "🔍 Scope", "value": new_item.get('scope', 'n/a')},
                    {"title": "⚙️ MITRE ATT&CK TTPs", "value": new_item.get('ttps', 'n/a')},
                    {"title": "⏰ Keep until", "value": new_item.get('expiry_date', 'n/a')}
                ]
            },
            {
                "type": "ActionSet",
                "separator": True,
                "spacing": "Medium",
                "actions": [
                    {
                        "type": "Action.Submit",
                        "title": "📄 Get current list",
                        "style": "positive",
                        "data": {"callback_keyword": "current_approved_testing"}
                    }
                ],
                "horizontalAlignment": "center"
            }
        ]
    }
    webex_api = WebexTeamsAPI(access_token=CONFIG.webex_bot_access_token_aide)
    webex_api.messages.create(
        roomId=CONFIG.webex_room_id_gosc_t2,
        text="New Approved Testing!",
        attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": payload}]
    )
