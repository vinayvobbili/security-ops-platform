import json
import time
from datetime import datetime

import requests
import schedule

approved_testing_list_name = "METCIRT_Approved_Testing"


def get_list_by_name(list_name):
    """Fetches a list by its name from Demisto's internal lists."""
    try:
        response = demisto.internalHttpRequest('GET', '/lists')
        all_lists = json.loads(response.get("body", "[]"))
        matching_lists = [item for item in all_lists if item.get('id') == list_name]

        if not matching_lists:
            raise ValueError(f"No list found with the name '{list_name}'.")
        if len(matching_lists) > 1:
            raise ValueError(f"Multiple lists found with the name '{list_name}'.")

        return json.loads(matching_lists[0].get('data', '{}'))

    except json.JSONDecodeError as json_error:
        demisto.error(f"Error decoding JSON for list '{list_name}': {str(json_error)}")
        raise
    except Exception as e:
        demisto.error(f"Error fetching list '{list_name}': {str(e)}")
        raise


xsoar_details = get_list_by_name('METCIRT XSOAR')


def get_api_headers():
    """Helper function to create headers for API requests."""
    return {
        'Authorization': xsoar_details.get('api_key'),
        'x-xdr-auth-id': xsoar_details.get('auth_id'),
        'Content-Type': 'application/json'
    }


def save_list(list_name, data):
    """Saves the list back to Demisto."""
    try:
        # Get the list's current version
        response = demisto.internalHttpRequest('GET', '/lists', body=None)
        all_lists = json.loads(response.get("body", "[]"))
        matching_list = next((item for item in all_lists if item.get('id') == list_name), None)

        # Prepare API request to save the list
        api_url = f"{xsoar_details.get('api_base_url')}/lists/save"
        headers = get_api_headers()
        payload = {
            "data": json.dumps(data, indent=4),
            "name": list_name,
            "type": "json",
            "id": list_name,
            "version": matching_list.get('version', 0)
        }

        # Send the request
        response = requests.post(api_url, headers=headers, json=payload)
        if response.status_code != 200:
            demisto.error(f"Failed to save list '{list_name}'. Status code: {response.status_code}")
            raise RuntimeError(f"Failed to save list. Status code: {response.status_code}")
        demisto.debug(f"List '{list_name}' saved successfully.")

    except Exception as e:
        demisto.error(f"Error saving list '{list_name}': {str(e)}")
        raise


def clean():
    """Cleans expired entries from the approved testing list."""
    try:
        approved_test_items = get_list_by_name(approved_testing_list_name)
        today = datetime.now()

        for category, items in approved_test_items.items():
            valid_items = []
            for item in items:
                try:
                    expiry_date = datetime.fromisoformat(item['expiry_date'])
                    if expiry_date > today:
                        valid_items.append(item)
                except ValueError as e:
                    demisto.error(f"Invalid date format for item '{item}': {str(e)}")
                    continue
            approved_test_items[category] = valid_items

        save_list(approved_testing_list_name, approved_test_items)
    except Exception as e:
        demisto.error(f"Error during clean operation: {str(e)}")


def main():
    """Main function that schedules the daily clean operation."""
    schedule.every().day.at("17:00", "America/New_York").do(clean)
    demisto.debug("Scheduler started, running daily cleanup at 17:00.")

    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
