import datetime
import pprint
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
                for work_item in work_items:
                    pprint.pprint(f"ID: {work_item.id}, Title: {work_item.fields['System.Title']}, State: {work_item.fields['System.State']}")
                all_work_items.extend(work_items)
            except AzureDevOpsClientRequestError as e:
                print(f"Error fetching work items for batch {batch_ids}: {e}")
                time.sleep(5)  # Wait before retrying
        return all_work_items
    else:
        return "No work items found."


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
    """
    return fetch_work_items(query)


def get_tuning_requests_submitted_by_last_shift():
    """
    Get tuning requests submitted by the last shift.

    Returns:
        List of work items or a message if no work items are found.
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
        return all_items

    # Filter in Python for the last 8 hours
    eight_hours_ago = datetime.now() - timedelta(hours=8)

    # Filter the items
    recent_items = []
    for item in all_items:
        created_date = datetime.fromisoformat(item.fields["System.CreatedDate"].replace("Z", "+00:00"))
        if created_date >= eight_hours_ago:
            recent_items.append(item)

    if not recent_items:
        return "No work items found in the last 8 hours."

    return recent_items


def main():
    # Example usage
    # get_stories_from_area_path("Detection-Engineering\\DE Rules\\Threat Hunting")
    get_tuning_requests_submitted_by_last_shift()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
