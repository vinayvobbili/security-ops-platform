import logging
from datetime import datetime

from services.xsoar import ListHandler

approved_testing_list_name = "METCIRT_Approved_Testing"
list_handler = ListHandler()

xsoar_details = get_list_by_name('METCIRT XSOAR')


def get_api_headers():
    """Helper function to create headers for API requests."""
    return {
        'Authorization': xsoar_details.get('api_key'),
        'x-xdr-auth-id': xsoar_details.get('auth_id'),
        'Content-Type': 'application/json'
    }


def refresh_list():
    """Cleans expired entries from the approved testing list."""
    try:
        approved_test_items = get_list_by_name(approved_testing_list_name)
        today = datetime.now()

        updated_approved_test_items = {}
        for category, items in approved_test_items.items():
            valid_items = []
            for item in items:
                try:
                    expiry_date = datetime.fromisoformat(item['expiry_date'])
                    if expiry_date > today:
                        valid_items.append(item)
                except ValueError as e:
                    logging.ERROR(f"Invalid date format for item '{item}': {str(e)}")
                    continue
            updated_approved_test_items[category] = valid_items

        list_handler.save(approved_testing_list_name, updated_approved_test_items)
    except Exception as e:
        logging.error(f"Error during clean operation: {str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    refresh_list()
