import re
import json
from zoneinfo import ZoneInfo

def sanitize_channel_name(name, incident_id, max_length=50):
    """
    Sanitizes the channel name according to MS Teams naming requirements

    Args:
        name (str): The incident name
        incident_id (str): The incident ID
        max_length (int): Maximum length for channel name

    Returns:
        str: Sanitized channel name
    """
    bad_chars = "~#%&{}*+/:<>?|'"

    # Ensure we have valid inputs
    if not name:
        name = "Unnamed-Incident"
    if not incident_id:
        incident_id = "Unknown"

    # Create and sanitize channel name
    channel_name = f"X{incident_id}-{name}"
    channel_name = re.sub(rf'[{bad_chars}]', '-', channel_name)
    # Trim whitespace and remove duplicate dashes
    channel_name = re.sub(r'-+', '-', channel_name)
    channel_name = channel_name.strip('-')

    # Limit channel name to max_length chars
    return channel_name[:max_length]

def execute_command_with_error_handling(command, args):
    """
    Execute a Demisto command and handle potential errors.

    Args:
        command (str): The command to execute
        args (dict): Command arguments

    Returns:
        list: Command results

    Raises:
        Exception: If command fails
    """
    demisto.info(f"Executing command: {command} with args: {args}")
    results = demisto.executeCommand(command, args)

    # Check if command execution was successful
    if isError(results):
        error_message = f"Error executing {command}: {results[0].get('Contents')}"
        demisto.error(error_message)
        demisto.results({
            "Type": entryTypes["note"],
            "ContentsFormat": formats["text"],
            "Contents": f"❌ {error_message}"
        })
        raise Exception(error_message)

    return results

def main():
    try:
        demisto.info("Starting War Room creation script")

        # Get incident details
        incident = demisto.incident()
        incident_name = incident.get('name')
        incident_id = incident.get('id')
        reason = demisto.args().get("Reason", "No reason provided")

        # Format and sanitize channel name
        channel_name = sanitize_channel_name(incident_name, incident_id)

        # Log creation step
        demisto.results({
            "Type": entryTypes["note"],
            "ContentsFormat": formats["text"],
            "Contents": f"Starting War Room creation for incident X#{incident_id} - {incident_name}"
        })

        # Get war room details
        try:
            war_room_results = execute_command_with_error_handling("getList", {
                "listName": "CIRT_War_Room"
            })
            war_room_details = json.loads(war_room_results[0]['Contents'])
            ms_teams_name = war_room_details["microsoft_team_name"]
        except Exception as e:
            demisto.error(f"Failed to get war room details: {str(e)}")
            raise Exception(f"Failed to get war room details from the CIRT_War_Room list: {str(e)}")

        # Create MS Teams channel
        war_room_starter = demisto.executeCommand("getUsers", args={
            "current": True
        })
        war_room_starter_email_address = war_room_starter[0].get('Contents')[0].get("email")
        war_room_starter_name = war_room_starter[0].get('Contents')[0].get("name")
        try:
            execute_command_with_error_handling("microsoft-teams-create-channel", {
                "channel_name": channel_name,
                "team": ms_teams_name,
                "membership_type": "private",
                "owner_user": war_room_starter_email_address,
                "description": f"War room for XSOAR#{incident_id} - {incident_name}. Reason: {reason}"
            })
            demisto.info(f"Created channel name: {channel_name}")
            demisto.results({
                "Type": entryTypes["note"],
                "ContentsFormat": formats["text"],
                "Contents": f"✅ Created MS Teams channel: {channel_name}"
            })
        except Exception as e:
            error_str = str(e)
            if "channel name already existed" in error_str.lower():
                demisto.info(f"Channel {channel_name} already exists, continuing...")
                demisto.results({
                    "Type": entryTypes["note"],
                    "ContentsFormat": formats["text"],
                    "Contents": f"⚠️ Channel `{channel_name}` already exists, using existing channel."
                })
            else:
                demisto.error(f"Failed to create MS Teams channel: {error_str}")
                raise

        # Promote starter to owner explicitly. Graph adds the app principal
        # (functional account) as owner by default; the starter needs to be
        # promoted so they can invite others even if they're missing from the
        # members list.
        try:
            execute_command_with_error_handling("microsoft-teams-add-user-to-channel", {
                "channel": channel_name,
                "team": ms_teams_name,
                "member": war_room_starter_email_address,
                "owner": "true"
            })
            demisto.results({
                "Type": entryTypes["note"],
                "ContentsFormat": formats["text"],
                "Contents": f"✅ Promoted {war_room_starter_name} to channel owner"
            })
        except Exception as e:
            demisto.error(f"Failed to promote starter to owner: {str(e)}")
            demisto.results({
                "Type": entryTypes["note"],
                "ContentsFormat": formats["text"],
                "Contents": f"⚠️ Could not promote {war_room_starter_name} to owner: {str(e)}"
            })

        # Collect emails from every list-typed top-level key (section groups
        # like Leadership, Response Engineering, ... plus the flat `members`
        # list for anyone not covered by a section). Filter to entries that
        # look like emails so we skip structural lists (e.g. comments.*).
        all_emails = set()
        for key, value in war_room_details.items():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and "@" in item:
                        all_emails.add(item.strip().lower())
        members = sorted(all_emails)
        members_added = 0
        failed_members = []

        for member in members:
            if not member:
                demisto.debug("Skipping empty member")
                continue

            try:
                execute_command_with_error_handling("microsoft-teams-add-user-to-channel", {
                    "channel": channel_name,
                    "member": member,
                    "team": ms_teams_name,
                    "owner": "true"
                })
                members_added += 1
            except Exception as e:
                error_msg = f"Failed to add member {member} to channel: {str(e)}"
                demisto.error(error_msg)
                failed_members.append(member)
                demisto.results({
                    "Type": entryTypes["note"],
                    "ContentsFormat": formats["text"],
                    "Contents": f"❌ {error_msg}"
                })

        demisto.results({
            "Type": entryTypes["note"],
            "ContentsFormat": formats["text"],
            "Contents": f"✅ Added {members_added} members to channel as owners"
        })

        if failed_members:
            demisto.results({
                "Type": entryTypes["note"],
                "ContentsFormat": formats["text"],
                "Contents": f"⚠️ Failed to add these members: {', '.join(failed_members)}"
            })

        # Remove the functional/app account from the channel so it doesn't
        # clutter the owner list. Must run AFTER all other channel-modifying
        # calls — once removed, XSOAR loses its foothold in the channel and
        # further microsoft-teams-* calls targeting it will 403.
        functional_account_email = war_room_details.get("functional_account_email")
        if functional_account_email:
            try:
                execute_command_with_error_handling("microsoft-teams-user-remove-from-channel", {
                    "channel": channel_name,
                    "team": ms_teams_name,
                    "member": functional_account_email
                })
                demisto.results({
                    "Type": entryTypes["note"],
                    "ContentsFormat": formats["text"],
                    "Contents": "✅ Removed functional account from channel"
                })
            except Exception as e:
                demisto.error(f"Failed to remove functional account: {str(e)}")
                demisto.results({
                    "Type": entryTypes["note"],
                    "ContentsFormat": formats["text"],
                    "Contents": f"⚠️ Could not remove functional account: {str(e)}"
                })
        else:
            demisto.debug("No functional_account_email in CIRT_War_Room list, skipping removal")

        # Send Webex notification
        try:
            webex_results = execute_command_with_error_handling("getList", {
                "listName": "CIRT Webex"
            })
            webex_details = json.loads(webex_results[0]['Contents'])
            room_id = webex_details['channels']['threat_con_collab']
            investigation_url = demisto.demistoUrls().get('investigation')

            # Format Teams instructions with team name
            teams_msg = (
                f"🔗 **MS Teams War Room:**  \n"
                f"Channel: `{channel_name}`  \n"
                f"*(Team: {ms_teams_name})*"
            )

            markdown_msg = (
                f"🚨 **WAR ROOM ACTIVATED** 🚨  \n"
                f"**Incident:** [X#{incident_id}]({investigation_url}) - {incident_name}  \n"
                f"**Reason:** {reason}  \n"
                f"**Opened By:** *{war_room_starter_name}*  \n\n"
                f"{teams_msg}"
            )

            execute_command_with_error_handling("cisco-spark-create-message", {
                "roomId": room_id,
                "markdown": markdown_msg
            })

            demisto.results({
                "Type": entryTypes["note"],
                "ContentsFormat": formats["text"],
                "Contents": "✅ Webex notification sent successfully"
            })
        except Exception as e:
            error_msg = f"Failed to send Webex notification: {str(e)}"
            demisto.error(error_msg)
            demisto.results({
                "Type": entryTypes["note"],
                "ContentsFormat": formats["text"],
                "Contents": f"❌ {error_msg}"
            })

        # Write to Action Log
        custom_fields = incident.get("CustomFields", {})
        current_action_summary = custom_fields.get("actionsummary", '')
        eastern = ZoneInfo("America/New_York")
        current_date_time = datetime.now(eastern).strftime("%m/%d/%Y %I:%M:%S %p %Z")

        new_action_summary = f'{current_date_time} - War room has been stood up in Microsoft Teams by {war_room_starter_name}. Reason: {reason}' + \
        '\n' + current_action_summary
        demisto.executeCommand("setIncident", args = {
            'customFields': {
                'actionsummary': new_action_summary
            }
        })

        # Write to war room history
        war_room_history_list_name = "DnR War Room History"
        war_room_history = demisto.executeCommand("getList", {
            "listName": war_room_history_list_name,
        })
        war_room_history = json.loads(war_room_history[0]['Contents'])
        war_room_history.append({
            "incident_id": incident_id,
            "incident_name": incident_name,
            "reason": reason,
            "channel_name": channel_name,
            "war_room_starter_name": war_room_starter_name,
            "current_date_time": current_date_time
        })
        save_results = demisto.executeCommand("setList", {
            "listName": war_room_history_list_name,
            "listData": json.dumps(war_room_history, indent=4)
        })

        # Final success message
        demisto.results({
            "Type": entryTypes["note"],
            "ContentsFormat": formats["text"],
            "Contents": f"✅ War Room creation process completed for incident X#{incident_id}"
        })

    except Exception as e:
        error_message = f"Error in War Room creation script: {str(e)}"
        demisto.error(error_message)
        demisto.results({
            "Type": entryTypes["error"],
            "ContentsFormat": formats["text"],
            "Contents": f"❌ {error_message}"
        })
        return_error(f"Failed to create War Room: {str(e)}")

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
