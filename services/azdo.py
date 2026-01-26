import base64
import datetime
import json
import logging
import time
from datetime import datetime, timedelta

import pytz
import requests

from data.data_maps import azdo_projects, azdo_orgs
from my_config import get_config
from services.xsoar import ListHandler, CONFIG, XsoarEnvironment
from src.utils.http_utils import RobustHTTPSession

logger = logging.getLogger(__name__)

config = get_config()
personal_access_token = config.azdo_pat
organization_url = f'https://dev.azure.com/{config.azdo_org}'

# Prepare authentication for REST API
credentials = base64.b64encode(f":{personal_access_token}".encode('ascii')).decode('ascii')
headers = {
    'Authorization': f'Basic {credentials}',
    'Content-Type': 'application/json'
}

# Create a robust HTTP session with longer timeout for Azure DevOps
azdo_session = RobustHTTPSession(max_retries=3, timeout=120, backoff_factor=0.5)

prod_list_handler = ListHandler(XsoarEnvironment.PROD)


def fetch_work_items(query: str, project: str = None):
    """
    Fetch work items based on a WIQL query using REST API.

    Args:
        query (str): The WIQL query string.
        project (str): The project name. If None, uses the DE project from config or defaults to 'Detection-Engineering'.

    Returns:
        List of work items with fields or empty list if no work items are found.
    """
    # Execute WIQL query to get work item IDs
    # Use provided project or default to DE project
    if project is None:
        project = config.azdo_de_project or 'Detection-Engineering'
    wiql_endpoint = f'{organization_url}/{project}/_apis/wit/wiql?api-version=7.0'
    query_body = {'query': query}

    try:
        logger.debug(f"Executing WIQL query against {wiql_endpoint}")
        logger.debug(f"Query: {query[:100]}...")
        response = azdo_session.post(wiql_endpoint, headers=headers, json=query_body)
        if response is None:
            logger.error("Failed to query work items after all retries")
            return []

        response.raise_for_status()
        work_item_ids = [item['id'] for item in response.json().get('workItems', [])]

        if not work_item_ids:
            logger.info("No work items found for query")
            return []

        logger.debug(f"Found {len(work_item_ids)} work items, fetching details in batches of 50")

        # Fetch work item details in batches of 50
        batch_size = 50
        all_work_items = []

        for i in range(0, len(work_item_ids), batch_size):
            batch_ids = work_item_ids[i:i + batch_size]
            ids_param = ",".join(map(str, batch_ids))

            # Get work item details for this batch
            work_items_endpoint = f'{organization_url}/_apis/wit/workitems?ids={ids_param}&$expand=fields&api-version=7.0'

            try:
                batch_response = azdo_session.get(work_items_endpoint, headers=headers)
                if batch_response is None:
                    logger.error(f"Failed to fetch work items for batch {batch_ids} after all retries")
                    continue

                batch_response.raise_for_status()
                batch_items = batch_response.json().get('value', [])
                all_work_items.extend(batch_items)

            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching work items for batch {batch_ids}: {e}")
                time.sleep(2)  # Brief pause before continuing with next batch
                continue

        return all_work_items

    except requests.exceptions.RequestException as e:
        logger.error(f"Error executing WIQL query: {e}")
        if "404" in str(e):
            logger.error(f"URL not found: {wiql_endpoint}")
            logger.error(f"Please verify AZDO_ORGANIZATION and AZDO_DE_PROJECT in .env match your Azure DevOps setup")
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
    Get tuning requests submitted by the last shift (last 8 hours).

    Returns:
        List of work item strings (formatted as "ID: Title") or empty list if no work items are found.
    """
    # Optimized query: Use a more precise time window to reduce result set
    # Using @Today-0.33 (~8 hours) instead of @Today-1 (24 hours) to reduce query load
    query = """
            SELECT [System.Id], [System.Title], [System.State], [System.CreatedDate]
            FROM WorkItems
            WHERE [System.AreaPath] = "Detection-Engineering\\Detection Engineering\\Tuning"
              AND [System.WorkItemType] = 'User Story'
              AND [System.CreatedDate] >= @Today-0.35
            """

    all_items = fetch_work_items(query)

    if not all_items:
        return []

    # Filter for the last 8 hours with timezone awareness
    eastern = pytz.timezone("US/Eastern")
    now_eastern = datetime.now(eastern)
    eight_hours_ago = now_eastern - timedelta(hours=8)

    # Filter the items and convert to strings
    recent_item_strings = []
    for item in all_items:
        try:
            # REST API returns items with 'fields' dictionary
            fields = item.get('fields', {})
            created_date_str = fields.get("System.CreatedDate")

            if not created_date_str:
                continue

            # Parse the ISO format string to datetime
            created_date = datetime.fromisoformat(created_date_str.replace("Z", "+00:00")).astimezone(eastern)

            # Compare timezone-aware datetimes
            if created_date >= eight_hours_ago:
                # Convert to string format
                item_id = item.get('id', 'Unknown')
                item_title = fields.get('System.Title', 'No Title')
                item_str = f"{item_id}: {item_title}"
                recent_item_strings.append(item_str)

        except (ValueError, AttributeError) as e:
            logger.warning(f"Error parsing work item: {e}")
            continue

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
                'value': area_path
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
    response.raise_for_status()
    print(response.text)
    return json.loads(response.text).get('id')


def add_comment_to_work_item(work_item_id: int, comment: str, project: str = None) -> dict:
    """
    Add a comment to an existing work item.

    Args:
        work_item_id: The ID of the work item to comment on
        comment: The comment text (supports HTML formatting)
        project: The project name. If None, uses the DE project from config.

    Returns:
        dict: The created comment response from AZDO API, or None if failed
    """
    if project is None:
        project = config.azdo_de_project or 'Detection-Engineering'

    url = f"{organization_url}/{project}/_apis/wit/workItems/{work_item_id}/comments?api-version=7.0-preview.3"

    payload = {
        "text": comment
    }

    try:
        logger.debug(f"Adding comment to work item {work_item_id}")
        response = azdo_session.post(url, headers=headers, json=payload)

        if response is None:
            logger.error(f"Failed to add comment to work item {work_item_id} after all retries")
            return None

        response.raise_for_status()
        result = response.json()
        logger.info(f"Successfully added comment to work item {work_item_id}")
        return result

    except requests.exceptions.RequestException as e:
        logger.error(f"Error adding comment to work item {work_item_id}: {e}")
        return None


def main():
    # Example usage
    # get_stories_from_area_path("Detection-Engineering\\DE Rules\\Threat Hunting")
    stories = get_stories_from_area_path("Detection-Engineering\\Detection Engineering\\Tuning")
    # get_tuning_requests_submitted_by_last_shift()
    '''
    print(create_wit(
        title="Sample Work Item",
        item_type="Task",
        description="This is a sample description for testing.",
        project="platforms",
        submitter="Test User"
    ))
    '''
    print(stories)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
