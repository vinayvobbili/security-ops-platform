import pprint
import time

from azure.devops.connection import Connection
from azure.devops.exceptions import AzureDevOpsClientRequestError
from azure.devops.v7_0.core.models import TeamProjectReference
from azure.devops.v7_0.work_item_tracking.models import Wiql
from msrest.authentication import BasicAuthentication

from config import get_config

config = get_config()
personal_access_token = config.azdo_pat
organization_url = f'https://dev.azure.com/{config.azdo_org}'

# Create a connection to the org
credentials = BasicAuthentication('', personal_access_token)
connection = Connection(base_url=organization_url, creds=credentials)


def get_projects_from_org():
    # Get a client (the "core" client provides access to projects, teams, etc.)
    core_client = connection.clients.get_core_client()

    # Get the first page of projects
    get_projects_response = core_client.get_projects()
    index = 0

    # Check if the response is a list or a paged response
    if isinstance(get_projects_response, list):
        # Handle the case where the response is a list directly
        for project in get_projects_response:
            if isinstance(project, TeamProjectReference):
                pprint.pprint("[" + str(index) + "] " + project.name)
                index += 1
            else:
                print(f"Unexpected project type: {type(project)}")
    else:
        # Handle the case where the response is a paged response
        while get_projects_response is not None:
            if hasattr(get_projects_response, 'value'):
                for project in get_projects_response.value:
                    pprint.pprint("[" + str(index) + "] " + project.name)
                    index += 1
            else:
                print("Response does not have a 'value' attribute.")
                break
            if hasattr(get_projects_response, 'continuation_token') and get_projects_response.continuation_token is not None and get_projects_response.continuation_token != "":
                # Get the next page of projects
                get_projects_response = core_client.get_projects(continuation_token=get_projects_response.continuation_token)
            else:
                # All projects have been retrieved
                get_projects_response = None


def get_stories_from_area_path():
    # Query work items from the area path "Detection-Engineering\\DE Rules\\Threat Hunting"
    query = Wiql(
        query="""
        SELECT [System.Id], [System.Title], [System.State]
        FROM WorkItems
        WHERE [System.AreaPath] = "Detection-Engineering\\DE Rules\\Threat Hunting"
        AND [System.WorkItemType] = 'User Story'
        """
    )

    work_item_tracking_client = connection.clients.get_work_item_tracking_client()
    query_result = work_item_tracking_client.query_by_wiql(query).work_items

    if query_result:
        work_item_ids = [item.id for item in query_result]
        batch_size = 50  # Process IDs in batches of 50
        for i in range(0, len(work_item_ids), batch_size):
            batch_ids = work_item_ids[i:i + batch_size]
            try:
                work_items = work_item_tracking_client.get_work_items(ids=batch_ids)
                for work_item in work_items:
                    pprint.pprint(f"ID: {work_item.id}, Title: {work_item.fields['System.Title']}, State: {work_item.fields['System.State']}")
                return work_items
            except AzureDevOpsClientRequestError as e:
                print(f"Error fetching work items for batch {batch_ids}: {e}")
                time.sleep(5)  # Wait before retrying
    else:
        return f"No work items found in the area path: {area_path}"


def main():
    get_stories_from_area_path()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
