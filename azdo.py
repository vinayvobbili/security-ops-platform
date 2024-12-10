import base64
from collections import Counter

import matplotlib.pyplot as plt
import requests


class ADOWorkItemRetriever:
    def __init__(self, organization, project, personal_access_token):
        """
        Initialize the ADO Work Item Retriever

        :param organization: Your Azure DevOps organization name
        :param project: The specific project to query
        :param personal_access_token: PAT for authentication
        """
        self.org = organization
        self.project = project
        self.pat = personal_access_token

        # Prepare authentication
        self.credentials = base64.b64encode(f":{self.pat}".encode('ascii')).decode('ascii')
        self.headers = {
            'Authorization': f'Basic {self.credentials}',
            'Content-Type': 'application/json'
        }

        # Base API URL
        self.base_url = f'https://dev.azure.com/{self.org}/{self.project}/_apis'

    def get_work_items_by_state(self, days_back=180, batch_size=200):
        """
        Retrieve work items states and count them, handling API limitations

        :param days_back: Number of days to look back
        :param batch_size: Number of work item IDs to retrieve in each batch
        """
        wiql_query = f'SELECT [System.Id], [System.State] FROM WorkItems WHERE [System.TeamProject] = "{self.project}" AND [System.CreatedDate] >= @Today - {days_back}'

        wiql_endpoint = f'{self.base_url}/wit/wiql?api-version=6.0'
        query_body = {'query': wiql_query}

        try:
            response = requests.post(wiql_endpoint, headers=self.headers, json=query_body)
            response.raise_for_status()

            # Extract work item IDs
            work_item_ids = [item['id'] for item in response.json().get('workItems', [])]

            if not work_item_ids:
                return {}

            # Batch processing of work item details
            states = []
            for i in range(0, len(work_item_ids), batch_size):
                # Get a batch of work item IDs
                batch_ids = work_item_ids[i:i + batch_size]

                # Retrieve work item details for this batch
                work_items_endpoint = f'{self.base_url}/wit/workitems?ids={",".join(map(str, batch_ids))}&$expand=fields&api-version=6.0'
                work_items_response = requests.get(work_items_endpoint, headers=self.headers)
                work_items_response.raise_for_status()

                # Extract states from this batch
                batch_states = [item['fields']['System.State'] for item in work_items_response.json()['value']]
                states.extend(batch_states)

            # Count states
            return dict(Counter(states))

        except requests.exceptions.RequestException as e:
            print(f"Error retrieving work items: {e}")
            return {}

    def create_work_item(self, work_item_type, title, description=None, additional_fields=None):
        """
        Create a new work item

        :param work_item_type: Type of work item (e.g., 'Bug', 'Task')
        :param title: Title of the work item
        :param description: Optional description
        :param additional_fields: Optional dictionary of additional field values
        :return: Created work item details
        """
        create_endpoint = f'{self.base_url}/wit/workitems/${work_item_type}?api-version=6.0'

        # Prepare work item payload
        payload = [
            {'op': 'add', 'path': '/fields/System.Title', 'value': title}
        ]

        if description:
            payload.append({
                'op': 'add',
                'path': '/fields/System.Description',
                'value': description
            })

        # Add any additional fields
        if additional_fields:
            for field, value in additional_fields.items():
                payload.append({
                    'op': 'add',
                    'path': f'/fields/{field}',
                    'value': value
                })

        # Create the work item
        response = requests.post(create_endpoint,
                                 headers=self.headers,
                                 json=payload)
        response.raise_for_status()

        return response.json()


# Example usage
def main():
    # Replace these with your actual values
    ORGANIZATION = 'Acme-US'
    PROJECT = 'Detection-Engineering'
    PERSONAL_ACCESS_TOKEN = 'yfb5ocrcwhstjzmrdqju7mlpj3vh7qonues2ktat6z357iif7x7q'

    # Initialize the retriever
    ado_retriever = ADOWorkItemRetriever(ORGANIZATION, PROJECT, PERSONAL_ACCESS_TOKEN)

    # Retrieve work items
    try:
        # Example 1: Get recent work items
        state_counts = ado_retriever.get_work_items_by_state()
        print(f"Recent Work Items Count: {state_counts}")

        # Plot the bar graph
        plt.figure(figsize=(10, 6))  # Adjust figure size for better readability
        bars = plt.bar(state_counts.keys(), state_counts.values(), color='#1f77b4')  # Store bar objects
        plt.xlabel('Work Item State (last 180 days)')
        plt.ylabel('Count')
        plt.title('DE AZDO Work Items by State')

        # Add count labels on top of each bar
        for bar in bars:
            yval = bar.get_height()
            plt.text(bar.get_x() + bar.get_width() / 2, yval, int(yval), va='bottom', ha='center', fontdict={'fontsize': 10, 'fontweight': 'bold'})  # Display count as integer

        plt.xticks(rotation=45, ha='right')  # Rotate x-axis labels for better readability
        plt.tight_layout()  # Adjust layout to prevent labels from overlapping
        plt.show()



    except requests.exceptions.RequestException as e:
        print(f"Error retrieving work items: {e}")


if __name__ == '__main__':
    main()
