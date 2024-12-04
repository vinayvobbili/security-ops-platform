import logging
import tempfile
from datetime import datetime

import matplotlib.pyplot as plt
import pandas as pd
import pytz
from matplotlib import transforms
from webex_bot.models.command import Command
from webexpythonsdk import WebexAPI

from config import get_config
from incident_fetcher import IncidentFetcher

config = get_config()
webex_api = WebexAPI(access_token=config.bot_access_token)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

QUERY = '-category:job type:METCIRT -owner:"" status:closed'
PERIOD = {
    "byFrom": "months",
    "fromValue": 1
}

eastern = pytz.timezone('US/Eastern')  # Define the Eastern time zone


def get_lifespan_chart(tickets):
    if not tickets:
        # Handle empty ticket list
        fig, ax = plt.subplots()
        ax.text(0.5, 0.5, 'No tickets found!', ha='center', va='center', fontsize=12)
        # Save the plot to a temporary file
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmpfile:
            filepath = tmpfile.name
            plt.savefig(filepath, format="png")
            plt.close()
        return filepath

    data = []
    for ticket in tickets:
        ticket_type = ticket.get('type').replace('METCIRT ', '')
        custom_fields = ticket.get('CustomFields', {})  # Handle missing CustomFields

        # Extract time fields and handle potential missing values with .get()
        triage_time = custom_fields.get('labtriagetime', {}).get('totalDuration', 0) / 3600  # Default to 0 if not found
        lessons_time = custom_fields.get('lablessonslearnedtime', {}).get('totalDuration', 0) / 3600
        investigate_time = custom_fields.get('labinvestigatetime', {}).get('totalDuration', 0) / 3600
        eradication_time = custom_fields.get('laberadicationtime', {}).get('totalDuration', 0) / 3600
        closure_time = custom_fields.get('labclosuretime', {}).get('totalDuration', 0) / 3600

        lifespan = (
                triage_time
                + lessons_time
                + investigate_time
                + eradication_time
                + closure_time
        )
        data.append(
            {
                'type': ticket_type,
                'triage': triage_time,
                'lessons': lessons_time,
                'investigate': investigate_time,
                'eradicate': eradication_time,
                'closure': closure_time,
                'lifespan': lifespan,
            }
        )

    df = pd.DataFrame(data)
    df = df.groupby('type').sum().reset_index()

    # Filter out rows where lifespan is 0 *before* sorting
    df = df[df['lifespan'] > 0]  # Keep only rows with lifespan > 0

    # Sort the DataFrame by 'lifespan' column in descending order
    df = df.sort_values('lifespan', ascending=False)

    fig, ax = plt.subplots(figsize=(12, 6))

    # Define a list of colors for the stacked bars. Add more as needed.
    colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']

    bottom = [0] * len(df)  # Ensures the segments start at the bottom

    # The order you specify determines stack order (bottom to top):
    for i, col in enumerate(['closure', 'lessons', 'eradicate', 'investigate', 'triage']):  # Correct order
        ax.bar(df['type'], df[col], label=col.capitalize(), bottom=bottom, color=colors[i % len(colors)])
        bottom += df[col]  # Important: Increment bottom for the next segment

    ax.set_xlabel("Ticket Type (last 30 days)", fontweight='bold')
    ax.set_ylabel("Hours", fontweight='bold')
    ax.set_title(
        "Ticket Lifespan by Type",
        fontweight='bold',  # Keep the bold
        fontsize=14,  # Increase font size
        fontname='Arial',  # Use a clear font like Arial, Tahoma, or Calibri
        color='darkred',  # Darker gray for better contrast (adjust as needed)
        # Use a background color for the title (adjust as needed):
        backgroundcolor='#f0f0f0',  # Light gray
        pad=1  # Add some padding
    )
    ax.legend()

    # Transform coordinates to figure coordinates (bottom-left is 0,0)
    trans = transforms.blended_transform_factory(fig.transFigure, ax.transAxes)  # gets transform object
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    plt.text(0.05, -0.7, now_eastern, transform=trans, ha='left', va='bottom', fontsize=10)

    plt.xticks(rotation=45, ha='right')  # Rotate x-axis labels if needed

    # Annotate bars with counts
    for bar, label in zip(ax.containers[0], df['type']):  # Iterate over the main bar containers
        height = bar.get_height()
        count = df[df['type'] == label]['lifespan'].values[0]  # Get total lifespan count for ticket type
        ax.annotate(f'({int(count)})',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=8, fontweight='bold')

    plt.tight_layout()  # Adjust layout to prevent labels from overlapping

    # Save the plot to a temporary file
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmpfile:
        filepath = tmpfile.name
        plt.savefig(filepath, format="png")
        plt.close()

    return filepath


class Lifespan(Command):
    def __init__(self):
        super().__init__(command_keyword="lifespan", help_message="Lifespan")

    def execute(self, message, attachment_actions, activity):
        incident_fetcher = IncidentFetcher()
        tickets = incident_fetcher.get_tickets(query=QUERY, period=PERIOD)
        filepath = get_lifespan_chart(tickets)  # Store the full path

        # Use WebexTeamsAPI to send the file
        webex_api.messages.create(
            roomId=attachment_actions.json_data["roomId"],
            text=f"{activity['actor']['displayName']}, here's the latest Lifespan chart!",
            files=[filepath]  # Path to the file
        )
