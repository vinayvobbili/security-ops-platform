import base64
import datetime
import json
import time
from datetime import datetime, timedelta

import pytz
import requests
from azure.devops.connection import Connection
from azure.devops.exceptions import AzureDevOpsClientRequestError
from azure.devops.v7_0.work_item_tracking.models import Wiql
from msrest.authentication import BasicAuthentication

from config import get_config
from data.transient.data_maps import azdo_projects, azdo_orgs
from services.xsoar import ListHandler, CONFIG

config = get_config()
personal_access_token = config.azdo_pat
organization_url = f'https://dev.azure.com/{config.azdo_org}'

# Create a connection to the org
credentials = BasicAuthentication('', personal_access_token)
connection = Connection(base_url=organization_url, creds=credentials)

list_handler = ListHandler()


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
              AND [System.CreatedDate] >= @Today-1 \
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
        created_date = datetime.fromisoformat(created_date_str.replace("Z", "+00:00")).astimezone(pytz.timezone("US/Eastern"))
        created_date_naive = created_date.replace(tzinfo=None)

        # Now compare naive to naive
        if created_date_naive >= eight_hours_ago - timedelta(hours=8):
            # Convert WorkItem to string format
            item_str = f"{item.id}: {item.fields.get('System.Title', 'No Title')}"
            recent_item_strings.append(item_str)

    return recent_item_strings


def create_wit(title, item_type, description, project, submitter, area_path=None, iteration=None, assignee=None, parent_url=None) -> str:
    org = azdo_orgs[project]
    project_name = azdo_projects.get(project)
    description += f'<br><br>Submitted by <strong>{submitter}</strong>'

    url = f"https://dev.azure.com/{org}/{project_name}/_apis/wit/workitems/${item_type}?api-version=7.0"

    payload = [
        {
            "op": "add",
            "path": "/fields/System.Title",
            "value": title
        },
        {
            "op": "add",
            "path": "/fields/Microsoft.VSTS.TCM.ReproSteps" if item_type == 'Bug' else "/fields/System.Description",
            "value": description
        },
        {
            "op": "add",
            "path": "/fields/Microsoft.VSTS.Common.StackRank",
            "value": "1"
        }
    ]

    if area_path is not None and area_path != '':
        payload.append(
            {
                'op': 'add',
                'path': '/fields/System.AreaPath',
                'value': f'{project}\{area_path}'
            }
        )

    if iteration is not None and iteration != '':
        payload.append(
            {
                'op': 'add',
                'path': '/fields/System.IterationPath',
                'value': iteration
            }
        )
    if parent_url is not None and parent_url != '':
        payload.append({
            "op": "add",
            "path": "/relations/-",
            "value": {
                "rel": "System.LinkTypes.Hierarchy-Reverse",
                "url": parent_url
            }
        })
    if assignee is not None and assignee != '':
        payload.append({
            "op": "add",
            "path": "/fields/System.AssignedTo",
            "value": assignee
        })

    api_token = CONFIG.azdo_pat
    api_key = base64.b64encode(b':' + api_token.encode('utf-8')).decode('utf-8')

    headers = {
        'Content-Type': 'application/json-patch+json',
        'Authorization': f'Basic {api_key}'
    }

    response = requests.request("POST", url, headers=headers, json=payload)
    return json.loads(response.text).get('id')


def main():
    # Example usage
    # get_stories_from_area_path("Detection-Engineering\\DE Rules\\Threat Hunting")
    # get_tuning_requests_submitted_by_last_shift()
    print(create_wit(
        title="Sample Work Item",
        item_type="Task",
        description="This is a sample description for testing.",
        project="platforms",
        submitter="Test User"
    ))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
