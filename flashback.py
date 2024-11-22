import json
import random
import matplotlib.pyplot as plt

import pandas as pd
import numpy as np
from webex_bot.models.command import Command
from webex_bot.models.response import response_from_adaptive_card
from webexpythonsdk.models.cards import AdaptiveCard, Image, ImageSize

from incident_fetcher import IncidentFetcher

fun_messages = []
with open('fun_messages.json', 'r') as f:
    messages_data = json.load(f)
    fun_messages.extend(messages_data.get("messages", []))  # Modify the global list


def get_flashback_card():
    return AdaptiveCard(
        body=[Image(url="flashback.png", size=ImageSize.LARGE)]
    )


def create_flashback_chart(tickets):
    df = pd.DataFrame(tickets)
    # Extract impact from CustomFields
    df['impact'] = df['CustomFields'].apply(lambda x: x.get('impact', 'Unknown') if x else 'Unknown')

    # Calculate counts for outer pie (type)
    type_counts = df['type'].value_counts()

    # Calculate counts for inner pie (impact)
    impact_counts = df['impact'].value_counts()

    # Set up the colors
    outer_colors = plt.cm.Set3(np.linspace(0, 1, len(type_counts)))
    inner_colors = plt.cm.Greys(np.linspace(0.4, 0.8, len(impact_counts)))

    # Create figure and axis
    fig, ax = plt.subplots()

    # Create the outer pie chart (types)
    outer_pie = ax.pie(type_counts.values,
                       radius=1,
                       labels=type_counts.index,
                       colors=outer_colors,
                       wedgeprops=dict(width=0.3, edgecolor='white'),
                       labeldistance=1.1,
                       pctdistance=0.85)

    # Create the inner pie chart (impacts)
    inner_pie = ax.pie(impact_counts.values,
                       radius=0.7,
                       labels=impact_counts.index,
                       colors=inner_colors,
                       wedgeprops=dict(width=0.4, edgecolor='white'),
                       labeldistance=0.6,
                       pctdistance=0.75)

    # Add title
    plt.title('Ticket Distribution by Type and Impact', pad=20, size=14)

    # Add legend for both pies
    outer_legend = ax.legend(outer_pie[0], type_counts.index,
                             title="Ticket Types",
                             loc="center left",
                             bbox_to_anchor=(1, 0, 0.5, 1))

    # Add the first legend manually
    plt.gca().add_artist(outer_legend)

    # Add legend for inner pie
    ax.legend(inner_pie[0], impact_counts.index,
              title="Impact",
              loc="center left",
              bbox_to_anchor=(1, 0, 0.5, 0))

    # Add counts as annotations
    total_tickets = len(df)
    plt.annotate(f'Total Tickets: {total_tickets}',
                 xy=(0, 0),
                 xytext=(0, -1.2),
                 ha='center',
                 va='center')
    plt.savefig('flashback.png', bbox_inches='tight', dpi=600)


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
        create_flashback_chart(tickets)
        card = get_flashback_card()
        return response_from_adaptive_card(card)
