import logging
import pprint
import time

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
    try:
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
    except Exception as e:
        print(f"An error occurred while fetching work items: {e}")
        return "Error occurred while fetching work items."


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
    WHERE [System.AreaPath] = "Detection-Engineering\\DE Rules\\Threat Hunting"
    AND [System.WorkItemType] = 'User Story'
    """
    return fetch_work_items(query)


def get_tuning_requests_submitted_by_last_shift():
    """
    Get tuning requests (User Stories) submitted within the last 8 hours.

    Returns:
        List[int]: A list of work item IDs. Returns an empty list if none are found
                   or if an error occurs.
    """
    try:
        query = f"""
        SELECT [System.Id]
        FROM WorkItems
        WHERE [System.AreaPath] = 'Detection-Engineering\\Detection Engineering\\Tuning'
        AND [System.WorkItemType] = 'User Story'
        AND [System.CreatedDate] >= @today - 0.3
        ORDER BY [System.CreatedDate] DESC
        """
        # Note: Selecting only System.Id might be slightly more efficient if you only need the IDs later.
        # If you need Title/State, keep them in SELECT and adjust processing below.

        logging.info(f"Executing WIQL query for recent tuning requests:\n{query}")
        work_items = fetch_work_items(query)  # Assuming fetch_work_items returns a list of work items or empty list/error string

        # 4. Process the results
        if isinstance(work_items, str):  # Handle potential error messages from fetch_work_items
            logging.warning(f"Could not fetch tuning requests: {work_items}")
            return []
        elif not work_items:
            logging.info("No tuning requests found submitted in the last 8 hours.")
            return []
        else:
            # Extract IDs from the returned WorkItem objects
            work_item_ids = [item.id for item in work_items if item and hasattr(item, 'id')]
            logging.info(f"Found {len(work_item_ids)} tuning requests submitted in the last 8 hours.")
            return work_item_ids

    except Exception as e:
        # Catch any unexpected errors during query construction or processing
        logging.error(f"An error occurred in get_tuning_requests_submitted_by_last_shift: {e}", exc_info=True)
        return []  # Return empty list on error


def main():
    # Example usage
    # get_stories_from_area_path("Detection-Engineering\\DE Rules\\Threat Hunting")
    get_tuning_requests_submitted_by_last_shift()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
