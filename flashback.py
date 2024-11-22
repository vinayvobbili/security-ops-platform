import base64
import io
import json
import random
from datetime import datetime

import matplotlib.pyplot as plt
import pandas as pd
from matplotlib import transforms
from pytz import timezone
from webex_bot.models.command import Command
from webex_bot.models.response import response_from_adaptive_card
from webexpythonsdk.models.cards import AdaptiveCard, Image, ImageSize

from incident_fetcher import IncidentFetcher

eastern = timezone('US/Eastern')  # Define the Eastern time zone
fun_messages = []
with open('fun_messages.json', 'r') as f:
    messages_data = json.load(f)
    fun_messages.extend(messages_data.get("messages", []))  # Modify the global list


def create_flashback_chart(tickets):
    df = pd.DataFrame(tickets)

    df['type'] = df['type'].str.replace('METCIRT ', '', regex=False)
    # Calculate counts for outer pie (type)
    type_counts = df['type'].value_counts()

    # Set up the colors
    outer_colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2', '#bcbd22', '#17becf', '#7f7f7f', '#ff9896', '#c5b0d5']

    # Create figure and axis
    fig, ax = plt.subplots()

    # Create the outer pie chart (types)
    ax.pie(type_counts.values,
           radius=1,
           labels=type_counts.index,
           colors=outer_colors,
           wedgeprops=dict(width=0.3, edgecolor='white'),
           labeldistance=1.1,
           pctdistance=0.85)

    # Add counts as annotations
    total_tickets = len(df)
    # Get figure and axes objects
    fig = plt.gcf()
    ax = plt.gca()
    # Transform coordinates to figure coordinates (bottom-left is 0,0)
    trans = transforms.blended_transform_factory(fig.transFigure, ax.transAxes)  # gets transform object
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    plt.text(0, -0.15, now_eastern, transform=trans, ha='left', va='bottom', fontsize=10)
    plt.text(0.45, -0.15, f'Total tickets past month: {total_tickets}', transform=trans, ha='left', va='bottom', fontsize=12, fontweight='bold')  # uses transform object instead of xmin, ymin

    # Adjust layout to prevent label clipping
    plt.tight_layout()

    # Convert plot to base64 for Adaptive Card
    buf = io.BytesIO()
    plt.savefig(buf, format="png", bbox_inches='tight', dpi=300)  # Adjust dpi as needed
    buf.seek(0)
    image_base64 = base64.b64encode(buf.read()).decode('utf-8')
    plt.close()  # Close the plot to free resources
    buf.close()

    # Create Adaptive Card
    card = AdaptiveCard(
        body=[
            Image(
                url=f"data:image/png;base64,{image_base64}",
                size=ImageSize.AUTO
            ),
        ]
    )

    return card


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

    def pre_execute(self, message, attachment_actions, activity):
        return f"{activity['actor']['displayName']}, {random.choice(fun_messages)}"

    def execute(self, message, attachment_actions, activity):
        incident_fetcher = IncidentFetcher()
        tickets = incident_fetcher.get_tickets(query=self.QUERY, period=self.PERIOD)
        card = create_flashback_chart(tickets)
        return response_from_adaptive_card(card)
