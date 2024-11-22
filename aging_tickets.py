import base64
import datetime
import io
import json
import logging
import random
import tempfile
from typing import List, Dict, Any

import matplotlib.pyplot as plt
import pandas as pd
import pytz
from webex_bot.models.command import Command
from webex_bot.models.response import response_from_adaptive_card
from webexpythonsdk import WebexAPI
from webexpythonsdk.models.cards import AdaptiveCard, Image, TextBlock

from config import get_config
from incident_fetcher import IncidentFetcher

config = get_config()
api = WebexAPI(access_token=config.bot_api_token)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

webex_headers = {
    'Content-Type': 'application/json',
    'Authorization': f"Bearer {config.bot_api_token}"
}
eastern = pytz.timezone('US/Eastern')  # Define the Eastern time zone

fun_messages = []
with open('fun_messages.json', 'r') as f:
    messages_data = json.load(f)
    fun_messages.extend(messages_data.get("messages", []))  # Modify the global list


def get_df(tickets: List[Dict[Any, Any]]) -> pd.DataFrame:
    df = pd.DataFrame(tickets)
    df['created'] = pd.to_datetime(df['created'])
    # Clean up type names by removing 'METCIRT ' prefix
    df['type'] = df['type'].str.replace('METCIRT ', '', regex=False)
    return df


def generate_plot(tickets: list) -> str | None:
    """Generate a bar plot of open ticket types older than 30 days, returned as a base64 string."""
    df = get_df(tickets)

    type_counts = df['type'].value_counts()
    categories = df['type'].unique()
    plt.bar(categories, type_counts)

    # Bold the title, x-label, and y-label
    plt.title('Counts of Tickets created 30+ days ago by Type', fontweight='bold')
    plt.xlabel('METCIRT Ticket Types', fontweight='bold')
    plt.ylabel('Counts', fontweight='bold')

    plt.xticks(rotation=45, ha='right')

    # Add value labels and total
    max_count = max(type_counts)
    for i, v in enumerate(type_counts):
        label_y = v + (max_count * 0.05) if v < max_count * 0.1 else v / 2
        plt.text(i, label_y, str(v), ha='center', va='center', fontsize=14, fontweight='bold')

    now_eastern = datetime.datetime.now(eastern)  # Get the current time in Eastern
    plt.text(len(categories) * 0.8, max_count * 0.95,
             f"{now_eastern.strftime('%m/%d/%Y %I:%M %p %Z')}",
             ha='right', va='bottom', fontsize=10)
    plt.text(len(categories) * 0.8, max_count * 0.85,
             f"Total: {sum(type_counts)}",
             ha='right', va='bottom', fontsize=12, fontweight='bold')

    # Adjust layout to prevent label clipping
    plt.tight_layout()

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmpfile:
        filepath = tmpfile.name  # Get the full path
        plt.savefig(filepath, format="png", bbox_inches='tight', dpi=300)
        plt.close()

    return filepath  # Return the full path


class AgingTickets(Command):
    """Webex Bot command to display a graph of aging tickets."""
    QUERY = "-status:closed -category:job type:METCIRT"
    PERIOD = {"byTo": "months", "toValue": 1, "byFrom": "months", "fromValue": None}

    def __init__(self):
        super().__init__(command_keyword="aging_tickets", help_message="Aging Tickets")

    def execute(self, message, attachment_actions, activity):
        incident_fetcher = IncidentFetcher()
        tickets = incident_fetcher.get_tickets(query=self.QUERY, period=self.PERIOD)
        filepath = generate_plot(tickets)  # Store the full path

        # Use WebexTeamsAPI to send the file
        api.messages.create(
            roomId=attachment_actions.json_data["roomId"],
            text=f"{activity['actor']['displayName']}, here's the latest Aging Tickets chart!",
            files=[filepath]  # Path to the file
        )
