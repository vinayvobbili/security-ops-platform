import json
import logging
import tempfile
from datetime import datetime
from typing import List, Dict, Any

import matplotlib.pyplot as plt
import matplotlib.transforms as transforms
import pandas as pd
import pytz
from webex_bot.models.command import Command
from webexpythonsdk import WebexAPI

from config import get_config
from incident_fetcher import IncidentFetcher

config = get_config()
webex_api = WebexAPI(access_token=config.bot_access_token)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

webex_headers = {
    'Content-Type': 'application/json',
    'Authorization': f"Bearer {config.bot_access_token}"
}
eastern = pytz.timezone('US/Eastern')  # Define the Eastern time zone

fun_messages = []
with open('fun_messages.json', 'r') as f:
    messages_data = json.load(f)
    fun_messages.extend(messages_data.get("messages", []))  # Modify the global list


def get_df(tickets: List[Dict[Any, Any]]) -> pd.DataFrame:
    if not tickets:
        return pd.DataFrame(columns=['created', 'type', 'phase'])

    df = pd.DataFrame(tickets)
    df['created'] = pd.to_datetime(df['created'])
    # Clean up type names by removing repeating prefix
    df['type'] = df['type'].str.replace(config.ticket_type_prefix, '', regex=False, case=False)
    # Set 'phase' to 'Unknown' if it's missing
    df['phase'] = df['phase'].fillna('Unknown')
    return df


def generate_plot(tickets) -> str | None:
    """Generate a bar plot of open ticket types older than 30 days, returned as a base64 string."""
    df = get_df(tickets)

    if df.empty:
        # Create a simple figure with a message
        fig, ax = plt.subplots(figsize=(8, 6))
        ax.text(0.5, 0.5, 'No tickets found!',
                horizontalalignment='center',
                verticalalignment='center',
                transform=ax.transAxes,
                fontsize=12)
    else:
        # Group and count tickets by 'type' and 'phase'
        grouped_data = df.groupby(['type', 'phase']).size().unstack(fill_value=0)

        # Sort types by total count in descending order
        grouped_data['total'] = grouped_data.sum(axis=1)
        grouped_data = grouped_data.sort_values(by='total', ascending=False).drop(columns='total')

        colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2', '#bcbd22', '#17becf', '#7f7f7f', '#ff9896']

        # Adjust figure size to control overall width
        fig, ax = plt.subplots(figsize=(8, 6))  # Example: plt.subplots(figsize=(10, 6)) makes 10 inches wide, 6 inches tall. Adjust these values.

        # Plotting
        grouped_data.plot(
            kind='bar',
            stacked=True,
            color=colors,
            edgecolor='black',
            ax=ax,
            width=0.2,  # Controls bar width
        )

    # Transform coordinates to figure coordinates (bottom-left is 0,0)
    trans = transforms.blended_transform_factory(fig.transFigure, ax.transAxes)  # gets transform object
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    plt.text(0.05, -0.3, now_eastern, transform=trans, ha='left', va='bottom', fontsize=10)

    # Annotate each segment of the stacked bars
    for container in ax.containers:  # ax.containers contains the bar segments
        for bar in container:
            height = bar.get_height()
            # Only annotate if height is non-zero
            if height > 0:  # Skip annotating bars with zero height
                ax.annotate(f'{int(height)}',  # just height is showing the decimal part too
                            xy=(bar.get_x() + bar.get_width() / 2, bar.get_y() + height / 2),
                            xytext=(0, 3),  # 3 points vertical offset for better visibility. Adjust as needed
                            textcoords="offset points",
                            ha='center', va='bottom', fontsize=10, color='black', fontweight='bold')

    plt.title('Tickets created 30+ days ago', fontweight='bold')
    plt.xlabel('Type', fontweight='bold')
    plt.ylabel('Count', fontweight='bold')
    plt.xticks(rotation=45, ha='right', fontsize=8)  # Rotate X-axis labels by 45 degrees

    # Update legend
    plt.legend(title='Phase', loc='upper right')
    plt.tight_layout()

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmpfile:
        filepath = tmpfile.name  # Get the full path
        plt.savefig(filepath, format="png", bbox_inches='tight', dpi=300)
        plt.close()

    return filepath  # Return the full path


class AgingTickets(Command):
    """Webex Bot command to display a graph of aging tickets."""
    QUERY = f"-status:closed -category:job type:{config.ticket_type_prefix}"
    PERIOD = {"byTo": "months", "toValue": 1, "byFrom": "months", "fromValue": None}

    def __init__(self):
        super().__init__(command_keyword="aging_tickets", help_message="Aging Tickets")

    def execute(self, message, attachment_actions, activity):
        tickets = IncidentFetcher().get_tickets(query=self.QUERY, period=self.PERIOD)
        plot_filepath = generate_plot(tickets)

        # Use WebexTeamsAPI to send the file
        webex_api.messages.create(
            roomId=attachment_actions.json_data["roomId"],
            text=f"{activity['actor']['displayName']}, here's the latest Aging Tickets chart!",
            files=[plot_filepath]  # Path to the file
        )
