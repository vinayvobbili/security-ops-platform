import base64
from collections import Counter
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import pytz
import requests
from matplotlib import transforms

from my_config import get_config

config = get_config()
eastern = pytz.timezone('US/Eastern')

root_directory = Path(__file__).parent.parent.parent


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
                        WHERE [System.AreaPath] Under "{config.ado_organization}\\{config.team_name}\\{config.team_name} Tier III" 
                        AND [System.CreatedDate] >= @Today - {days_back}'''

        wiql_endpoint = f'{self.base_url}/wit/wiql?api-version=6.0'
        query_body = {'query': wiql_query}

        try:
            response = requests.post(wiql_endpoint, headers=self.headers, json=query_body)
            # print(response.text)
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

        # Enhanced color scheme for work item states
        state_colors = {
            'New': '#FF9800',  # Orange - New items need attention
            'Active': '#2196F3',  # Blue - Currently being worked
            'Resolved': '#4CAF50',  # Green - Completed successfully
            'Closed': '#8BC34A',  # Light Green - Fully closed
            'Removed': '#9E9E9E',  # Gray - Removed items
            'To Do': '#FF5722',  # Deep Orange - Backlog items
            'In Progress': '#3F51B5',  # Indigo - Active work
            'Done': '#4CAF50',  # Green - Completed
            'Approved': '#CDDC39',  # Lime - Approved items
        }

        # Create enhanced figure with modern styling
        fig, ax = plt.subplots(figsize=(14, 10), facecolor='#f8f9fa')
        fig.patch.set_facecolor('#f8f9fa')

        # Get colors for the bars based on state
        colors = [state_colors.get(state, '#2196F3') for state in state_counts.keys()]
        total_items = sum(state_counts.values())

        # Enhanced bar plot
        bars = ax.bar(list(state_counts.keys()), list(state_counts.values()),
                      color=colors, edgecolor='white', linewidth=1.5,
                      alpha=0.9, width=0.6)

        # Enhanced axes styling
        ax.set_facecolor('#ffffff')
        ax.grid(False)  # Remove gridlines for cleaner look
        ax.set_axisbelow(True)

        # Enhanced titles with total count
        plt.suptitle('Response Engineering Work Items',
                     fontsize=24, fontweight='bold', color='#1A237E', y=0.98)
        ax.set_title(f'AZDO Work Items from last 180 days (Total: {total_items})',
                     fontsize=16, fontweight='bold', color='#3F51B5', pad=20)

        # Enhanced axis labels
        ax.set_xlabel('Work Items Created in the last 180 days',
                      fontsize=14, fontweight='bold', labelpad=15, color='#1A237E')
        ax.set_ylabel('Count', fontweight='bold', fontsize=14,
                      labelpad=15, color='#1A237E')

        # Enhanced count labels on bars
        for bar, state in zip(bars, state_counts.keys()):
            yval = int(bar.get_height())
            ax.text(bar.get_x() + bar.get_width() / 2, yval + max(state_counts.values()) * 0.01,
                    f'{yval}',
                    va='bottom', ha='center', fontsize=12, fontweight='bold',
                    color='#1A237E')

        # Enhanced border with rounded corners
        from matplotlib.patches import FancyBboxPatch
        border_width = 4
        fig.patch.set_edgecolor('none')
        fig.patch.set_linewidth(0)

        fancy_box = FancyBboxPatch(
            (0, 0), width=1.0, height=1.0,
            boxstyle="round,pad=0,rounding_size=0.01",
            edgecolor='#1A237E',
            facecolor='none',
            linewidth=border_width,
            transform=fig.transFigure,
            zorder=1000,
            clip_on=False
        )
        fig.patches.append(fancy_box)

        # Enhanced timestamp and branding
        now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
        trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
        fig.text(0.02, 0.02, f"Generated@ {now_eastern}",
                 ha='left', va='bottom', fontsize=10, color='#1A237E', fontweight='bold',
                 bbox=dict(boxstyle="round,pad=0.4", facecolor='white', alpha=0.9,
                           edgecolor='#1A237E', linewidth=1.5),
                 transform=trans)

        # Add GS-DnR branding
        fig.text(0.98, 0.02, 'GS-DnR', ha='right', va='bottom', fontsize=10,
                 alpha=0.7, color='#3F51B5', style='italic', fontweight='bold',
                 transform=trans)

        # Enhanced tick styling
        ax.tick_params(axis='x', rotation=45, colors='#1A237E', labelsize=12, width=1.5)
        ax.tick_params(axis='y', colors='#1A237E', labelsize=12, width=1.5)

        # Style the spines
        for spine in ax.spines.values():
            spine.set_color('#CCCCCC')
            spine.set_linewidth(1.5)

        plt.tight_layout()  # Adjust layout to prevent labels from overlapping

        today_date = datetime.now().strftime('%m-%d-%Y')
        OUTPUT_PATH = root_directory / "web" / "static" / "charts" / today_date / "RE Stories.png"
        plt.savefig(OUTPUT_PATH)
        plt.close(fig)

    except requests.exceptions.RequestException as e:
        print(f"Error retrieving work items: {e}")


if __name__ == '__main__':
    make_chart()
