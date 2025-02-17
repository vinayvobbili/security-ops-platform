import base64
from collections import Counter
from datetime import datetime

import matplotlib.pyplot as plt
import pytz
import requests
from matplotlib import transforms

from config import get_config

config = get_config()
eastern = pytz.timezone('US/Eastern')  # Define the Eastern time zone


class ADOWorkItemRetriever:
    def __init__(self):
        """
        Initialize the ADO Work Item Retriever
        """
        self.org = config.azdo_org
        self.project = config.azdo_re_project
        self.pat = config.azdo_pat

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
        today = datetime.now(eastern).strftime('%Y-%m-%dT%H:%M:%SZ')
        wiql_query = f'''SELECT [System.Id], [System.State] FROM WorkItems 
                        WHERE [System.AreaPath] Under "Acme-Cyber-Security\\{config.ticket_type_prefix}\\{config.ticket_type_prefix} Tier III" 
                        AND [System.CreatedDate] >= @Today - {days_back}'''

        wiql_endpoint = f'{self.base_url}/wit/wiql?api-version=6.0'
        query_body = {'query': wiql_query}

        try:
            response = requests.post(wiql_endpoint, headers=self.headers, json=query_body)
            print(response.text)
            response.raise_for_status()

            # Extract work item IDs
            work_item_ids = [item['id'] for item in response.json().get('workItems', [])]

            if not work_item_ids:
                print("No work items found.")
                return {}

            # Batch processing of work item details
            states = []
            for i in range(0, len(work_item_ids), batch_size):
                # Get a batch of work item IDs
                batch_ids = work_item_ids[i:i + batch_size]

                # Retrieve work item details for this batch
                work_items_endpoint = f'{self.base_url}/wit/workitems?ids={",".join(map(str, batch_ids))}&$expand=fields&api-version=6.0'
                work_items_response = requests.get(work_items_endpoint, headers=self.headers)

                # Extract states from this batch
                batch_states = [item['fields']['System.State'] for item in work_items_response.json()['value']]
                states.extend(batch_states)

            # Count states
            return dict(Counter(states))

        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
            return {}


# Example usage
def make_chart():
    # Initialize the retriever
    ado_retriever = ADOWorkItemRetriever()

    # Retrieve work items
    try:
        # Get recent work items
        state_counts = ado_retriever.get_work_items_by_state()
        # print(f"Recent Work Items Count: {state_counts}")

        # Plot the bar graph
        plt.figure(figsize=(10, 6))  # Adjust figure size for better readability
        bars = plt.bar(state_counts.keys(), state_counts.values(), color='#1f77b4')  # Store bar objects
        plt.xlabel('Work Items Created in the last 180 days')
        plt.ylabel('Count')
        plt.title('Response Engineering AZDO Work Items by State')

        # Add count labels on top of each bar
        for bar in bars:
            yval = bar.get_height()
            plt.text(bar.get_x() + bar.get_width() / 2, yval, yval, va='bottom', ha='center', fontdict={'fontsize': 10, 'fontweight': 'bold'})  # Display count as integer

        now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
        fig = plt.gcf()  # Get the current figure
        trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
        plt.text(0.1, 0, now_eastern, ha='left', va='bottom', fontsize=10, transform=trans)

        plt.xticks(rotation=45, ha='right')  # Rotate x-axis labels for better readability
        plt.tight_layout()  # Adjust layout to prevent labels from overlapping
        plt.savefig('web/static/charts/RE Stories.png')
        plt.close(fig)

    except requests.exceptions.RequestException as e:
        print(f"Error retrieving work items: {e}")


if __name__ == '__main__':
    make_chart()
