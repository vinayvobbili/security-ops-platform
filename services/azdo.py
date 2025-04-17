import datetime
import time
from datetime import datetime, timedelta

from azure.devops.connection import Connection
from azure.devops.exceptions import AzureDevOpsClientRequestError
from azure.devops.v7_0.work_item_tracking.models import Wiql
from msrest.authentication import BasicAuthentication

from config import get_config

config = get_config()
personal_access_token = config.azdo_pat
organization_url = f'https://dev.azure.com/{config.azdo_org}'

# Create a connection to the org
credentials = BasicAuthentication('', personal_access_token)
connection = Connection(base_url=organization_url, creds=credentials)


def fetch_work_items(query: str):
    """
    Fetch work items based on a WIQL query.

    Args:
        query (str): The WIQL query string.

    Returns:
        List of work items or a message if no work items are found.
    """
    work_item_tracking_client = connection.clients.get_work_item_tracking_client()
    query_result = work_item_tracking_client.query_by_wiql(Wiql(query=query)).work_items

    if query_result:
        work_item_ids = [item.id for item in query_result]
        batch_size = 50  # Process IDs in batches of 50
        all_work_items = []
        for i in range(0, len(work_item_ids), batch_size):
            batch_ids = work_item_ids[i:i + batch_size]
            try:
                work_items = work_item_tracking_client.get_work_items(ids=batch_ids)
                all_work_items.extend(work_items)
            except AzureDevOpsClientRequestError as e:
                print(f"Error fetching work items for batch {batch_ids}: {e}")
                time.sleep(5)  # Wait before retrying
        return all_work_items
    else:
        return []


def get_stories_from_area_path(area_path):
    """
    Get user stories from a specific area path.

    Args:
        area_path (str): The area path to query.

    Returns:
        List of work items or a message if no work items are found.
    """
    query = f"""
    SELECT [System.Id], [System.Title], [System.State], [System.CreatedDate]
    FROM WorkItems
    WHERE [System.AreaPath] = '{area_path}'
    AND [System.WorkItemType] = 'User Story'
    AND [System.CreatedDate] >= @Today-30
    """
    return fetch_work_items(query)


def get_tuning_requests_submitted_by_last_shift():
    """
    Get tuning requests submitted by the last shift.

    Returns:
        List of work item strings (formatted as "ID: Title") or a message if no work items are found.
    """
    # Get items from today and yesterday
    query = """
    SELECT [System.Id], [System.Title], [System.State], [System.CreatedDate]
    FROM WorkItems
    WHERE [System.AreaPath] = "Detection-Engineering\\Detection Engineering\\Tuning"
    AND [System.WorkItemType] = 'User Story'
    AND [System.CreatedDate] >= @Today-1
    """

    all_items = fetch_work_items(query)

    if isinstance(all_items, str):  # "No work items found" message
        return []  # Return empty list instead of the message

    # Filter in Python for the last 8 hours
    eight_hours_ago = datetime.now()  # This is a naive datetime

    # Filter the items and convert to strings
    recent_item_strings = []
    for item in all_items:
        # Parse the ISO format string to datetime, then make it naive by removing the timezone
        created_date_str = item.fields["System.CreatedDate"]
        created_date = datetime.fromisoformat(created_date_str.replace("Z", "+00:00"))
        created_date_naive = created_date.replace(tzinfo=None)

        # Now compare naive to naive
        if created_date_naive >= eight_hours_ago - timedelta(hours=8):
            # Convert WorkItem to string format
            item_str = f"{item.id}: {item.fields.get('System.Title', 'No Title')}"
            recent_item_strings.append(item_str)

    return recent_item_strings


def main():
    # Example usage
    get_stories_from_area_path("Detection-Engineering\\DE Rules\\Threat Hunting")
    # get_tuning_requests_submitted_by_last_shift()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
