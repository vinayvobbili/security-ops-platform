import pprint

from azure.devops.connection import Connection
from azure.devops.v7_0.core.models import TeamProjectReference
from msrest.authentication import BasicAuthentication

from config import get_config

config = get_config()
personal_access_token = config.azdo_pat
organization_url = f'https://dev.azure.com/{config.azdo_org}'

# Create a connection to the org
credentials = BasicAuthentication('', personal_access_token)
connection = Connection(base_url=organization_url, creds=credentials)

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
