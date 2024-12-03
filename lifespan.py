import logging
import tempfile

import matplotlib.pyplot as plt
import pandas as pd
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
        ticket_type = ticket.get('type')
        custom_fields = ticket.get('CustomFields', {})  # Handle missing CustomFields

        # Extract time fields and handle potential missing values with .get()
        triage_time = custom_fields.get('labtriagetime', 0)  # Default to 0 if not found
        lessons_time = custom_fields.get('lablessonslearnedtime', 0)
        investigate_time = custom_fields.get('labinvestigatetime', 0)
        eradication_time = custom_fields.get('laberadicationtime', 0)
        closure_time = custom_fields.get('labclosuretime', 0)

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
    df = df.groupby('type').sum().reset_index()  # fixes incorrect stacking

    fig, ax = plt.subplots(figsize=(12, 6))

    # Define a list of colors for the stacked bars. Add more as needed.
    colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']

    bottom = [0] * len(df)
    for i, col in enumerate(['triage', 'lessons', 'investigate', 'eradicate', 'closure']):
        ax.bar(df['type'], df[col], label=col.capitalize(), bottom=bottom, color=colors[i % len(colors)])
        bottom += df[col]  # Add current column values to the bottom

    ax.set_xlabel("Ticket Type")
    ax.set_ylabel("Lifespan (seconds or the unit the time fields use)")
    ax.set_title("Ticket Lifespan by Type")
    ax.legend()
    plt.xticks(rotation=45, ha='right')  # Rotate x-axis labels if needed
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
        tickets = incident_fetcher.get_tickets(query=self.QUERY, period=self.PERIOD)
        filepath = get_lifespan_chart(tickets)  # Store the full path

        # Use WebexTeamsAPI to send the file
        webex_api.messages.create(
            roomId=attachment_actions.json_data["roomId"],
            text=f"{activity['actor']['displayName']}, here's the latest MTTR-MTTC chart!",
            files=[filepath]  # Path to the file
        )
