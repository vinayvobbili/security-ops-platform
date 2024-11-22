import json
import tempfile
from datetime import datetime

import matplotlib.pyplot as plt
import pandas as pd
from matplotlib import transforms
from pytz import timezone
from webex_bot.models.command import Command
from webexteamssdk import WebexTeamsAPI

from config import get_config
from incident_fetcher import IncidentFetcher

config = get_config()
eastern = timezone('US/Eastern')  # Define the Eastern time zone
fun_messages = []

api = WebexTeamsAPI(access_token=config.bot_api_token)

with open('fun_messages.json', 'r') as f:
    messages_data = json.load(f)
    fun_messages.extend(messages_data.get("messages", []))  # Modify the global list


def create_flashback_chart(tickets) -> str:
    df = pd.DataFrame(tickets)

    df['type'] = df['type'].str.replace('METCIRT ', '', regex=False)
    # Calculate counts for outer pie (type)
    type_counts = df['type'].value_counts()

    # Set up the colors
    outer_colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2', '#bcbd22', '#17becf', '#7f7f7f', '#ff9896',
                    '#c5b0d5', '#a6cee3', '#1f78b4', '#b2df8a', '#33a02c', '#fb9a99']

    # Create figure and axis
    fig, ax = plt.subplots()

    # Create the outer pie chart (types)
    wedges, _, autotexts = ax.pie(type_counts.values,
                                  labels=None,
                                  colors=outer_colors,
                                  autopct='%1.1f%%',  # Show percentage
                                  wedgeprops=dict(width=0.5, edgecolor='white'),
                                  labeldistance=1.1,
                                  pctdistance=0.75,
                                  startangle=140  # Rotate the chart
                                  )

    # Add a legend
    ax.legend(
        wedges,
        type_counts.index,
        loc="center left",  # Position the legend outside the chart
        bbox_to_anchor=(1, 0, 0.5, 1),  # Fine-tune the position
    )

    # Add counts as annotations
    total_tickets = len(df)
    # Get figure and axes objects
    fig = plt.gcf()
    ax = plt.gca()
    # Transform coordinates to figure coordinates (bottom-left is 0,0)
    trans = transforms.blended_transform_factory(fig.transFigure, ax.transAxes)  # gets transform object
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    plt.text(0, -0.15, now_eastern, transform=trans, ha='left', va='bottom', fontsize=10)

    plt.title(f'Total tickets past month: {total_tickets}', transform=trans, loc='left', ha='left', va='bottom', fontsize=12, fontweight='bold')  # uses transform object instead of xmin, ymin

    # Adjust layout to prevent label clipping
    plt.tight_layout()

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmpfile:
        filepath = tmpfile.name  # Get the full path
        plt.savefig(filepath, format="png", bbox_inches='tight', dpi=300)
        plt.close(fig)

    return filepath  # Return the full path


class Flashback(Command):
    """Webex Bot command to display a graph of mean times to respond and contain."""
    QUERY = '-category:job status:closed type:METCIRT -owner:""'
    PERIOD = {
        "byTo": "months",
        "toValue": None,
        "byFrom": "months",
        "fromValue": 1
    }

    def __init__(self):
        super().__init__(command_keyword="flashback", help_message="Flashback")

    def execute(self, message, attachment_actions, activity):
        incident_fetcher = IncidentFetcher()
        tickets = incident_fetcher.get_tickets(query=self.QUERY, period=self.PERIOD)
        filepath = create_flashback_chart(tickets)  # Store the full path

        # Use WebexTeamsAPI to send the file
        api.messages.create(
            roomId=attachment_actions.json_data["roomId"],
            text=f"{activity['actor']['displayName']}, here's your Flashback chart!",
            files=[filepath]  # Path to the file
        )
