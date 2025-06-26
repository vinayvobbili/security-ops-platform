import time
import requests
import schedule
import json

from datetime import datetime, timezone


def get_list_by_name(list_name):
    """Fetch a list by name from Demisto's internal lists."""
    try:
        response = demisto.internalHttpRequest('GET', '/lists')
        all_lists = json.loads(response.get("body", "[]"))
        matching_lists = [item for item in all_lists if item.get('id') == list_name]

        if not matching_lists:
            raise ValueError(f"No list found with the name '{list_name}'.")
        if len(matching_lists) > 1:
            raise ValueError(f"Multiple lists found with the name '{list_name}'.")

        return json.loads(matching_lists[0].get('data', '{}'))

    except json.JSONDecodeError:
        demisto.error(f"Error decoding JSON for list: {list_name}")
        raise
    except Exception as e:
        demisto.error(f"Error fetching list '{list_name}': {str(e)}")
        raise


# Load Webex and XSOAR details
webex_details = get_list_by_name('METCIRT Webex')
webex_api_url = webex_details.get('api_url')
room_id = webex_details.get('channels', {}).get('sla_notices')
bot_access_token = webex_details.get('bot_access_token')

xsoar_details = get_list_by_name('METCIRT XSOAR')
xsoar_api_base_url = xsoar_details.get("api_base_url")
xsoar_api_token = xsoar_details.get("api_key")
xsoar_auth_id = xsoar_details.get("auth_id")
xsoar_ui_base_url = xsoar_details.get("ui_base_url")
incident_search = xsoar_details.get("incident_search", {})
incident_search_filter = incident_search.get("metcirtincidentnotificationsla", {})
verify_frequency_mins = incident_search.get("incident_declaration_sla_verify_frequency_in_minutes", 5)

incident_search_url = xsoar_api_base_url + '/incidents/search'
headers = {
    'Authorization': xsoar_api_token,
    'Content-Type': 'application/json',
    'x-xdr-auth-id': xsoar_auth_id
}


def notify(message):
    """Send a notification message to the Webex room."""
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f"Bearer {bot_access_token}"
    }
    payload = {
        'roomId': room_id,
        'markdown': message
    }

    try:
        response = requests.post(webex_api_url, headers=headers, json=payload)
        response.raise_for_status()  # Raises an error for bad HTTP response codes
        demisto.debug(f"Successfully sent notification: {message}")
    except requests.RequestException as e:
        demisto.error(f"Failed to send notification: {str(e)}")


def get_time_remaining(future_timestamp):
    """Return the time remaining until a future timestamp, in seconds."""
    # Remove the microseconds and the 'Z'
    future_timestamp_cleaned = future_timestamp.split('.')[0] + 'Z'

    # Parse the cleaned timestamp without microseconds
    future_time = datetime.strptime(future_timestamp_cleaned[:-1], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)

    # Get the current time in UTC
    now = datetime.now(timezone.utc)

    # Calculate the time difference
    time_difference = future_time - now

    # Get the total seconds from the time difference
    total_seconds = int(time_difference.total_seconds())

    # Calculate hours, minutes, and seconds
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60

    # Format the output to show 'hh:mm:ss'
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def handle_incidents_at_risk_of_breaching_incident_notification_sla():
    """Main handler for incidents at risk of breaching the notification SLA."""
    try:
        response = requests.post(incident_search_url, headers=headers, json=incident_search_filter)
        response.raise_for_status()
        incidents = response.json().get('data', [])

        if not incidents:
            demisto.debug("No incidents at risk found.")
            return

        for incident in incidents:
            owner_email_address = incident.get('owner')
            owner_details = f"<@personEmail:{owner_email_address}>" if owner_email_address else 'No owner'
            incident_id = incident.get('id')
            incident_name = incident.get('name', 'Unknown Incident')
            incident_details_url = xsoar_ui_base_url + f"/Custom/caseinfoid/{incident_id}"

            sla_time_remaining = "Unknown due date"
            due_date = incident.get('CustomFields', {}).get('metcirtincidentnotificationsla', {}).get('dueDate')
            if due_date:
                try:
                    sla_time_remaining = get_time_remaining(due_date)
                except Exception as e:
                    demisto.error(f"Error calculating due date: {str(e)}")

            message = (
                f"{owner_details}, Ticket [X#{incident_id}]({incident_details_url}) - \"{incident_name}\" \n"
                f"is at risk of breaching *METCIRT Incident Notification SLA*. Action required within the next **{sla_time_remaining}**"
            )
            notify(message)

        demisto.debug(f"Processed {len(incidents)} incidents at risk.")

    except requests.RequestException as e:
        error_message = f"Failed to process incidents: {str(e)}"
        demisto.error(error_message)
        notify(error_message)
    except json.JSONDecodeError as e:
        error_message = f"Failed to decode incidents response: {str(e)}"
        demisto.error(error_message)
        notify(error_message)


def main():
    """Entry point for running the SLA risk handler script."""
    demisto.debug('Starting the METCIRT Incident Notification SLA Risk Handler...')
    handle_incidents_at_risk_of_breaching_incident_notification_sla()
    try:
        # Schedule the job
        schedule.every(verify_frequency_mins).minutes.do(handle_incidents_at_risk_of_breaching_incident_notification_sla)

        while True:
            schedule.run_pending()
            time.sleep(1)

    except Exception as e:
        error_message = f"Main function encountered an error: {str(e)}"
        demisto.error(error_message)
        notify(error_message)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
