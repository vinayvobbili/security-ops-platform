import logging

import pytz
from webex_bot.models.command import Command
from webexpythonsdk import WebexAPI

from config import get_config
from incident_fetcher import IncidentFetcher

eastern = pytz.timezone('US/Eastern')  # Define the Eastern time zone

import tempfile
from datetime import datetime

import matplotlib.pyplot as plt
import pandas as pd

config = get_config()
webex_api = WebexAPI(access_token=config.webex_bot_access_token)

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
        fig, ax = plt.subplots()
        ax.text(0.5, 0.5, 'No tickets found!', ha='center', va='center', fontsize=12)
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmpfile:
            plt.savefig(tmpfile.name, format="png")
        plt.close()
        return tmpfile.name

    data = []
    for ticket in tickets:
        custom_fields = ticket.get('CustomFields', {})
        data.append({
            'type': ticket.get('type').replace('METCIRT ', ''),
            'triage': custom_fields.get('metcirttriagetime', {}).get('totalDuration', 0) / 3600,
            'lessons': custom_fields.get('metcirtlessonslearnedtime', {}).get('totalDuration', 0) / 3600,
            'investigate': custom_fields.get('metcirtinvestigatetime', {}).get('totalDuration', 0) / 3600,
            'eradicate': custom_fields.get('metcirteradicationtime', {}).get('totalDuration', 0) / 3600,
            'closure': custom_fields.get('metcirtclosuretime', {}).get('totalDuration', 0) / 3600,
        })

    df = pd.DataFrame(data)
    df['lifespan'] = df[['triage', 'lessons', 'investigate', 'eradicate', 'closure']].sum(axis=1)
    df['count'] = 1
    df = df.groupby('type').sum().reset_index()
    df = df[df['lifespan'] > 0].sort_values('lifespan', ascending=False)

    colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']
    fig, ax = plt.subplots(figsize=(12, 6))

    bar_width = 0.6
    bottom = 0
    for i, col in enumerate(['closure', 'lessons', 'eradicate', 'investigate', 'triage']):
        ax.bar(df['type'], df[col], label=col.capitalize(), bottom=bottom, color=colors[i % len(colors)], width=bar_width)
        bottom += df[col]

    ax.set_xlabel("Ticket Type (last 30 days)", fontweight='bold')
    ax.set_ylabel("Hours", fontweight='bold')
    ax.set_title("Cumulative Lifespan by Type", fontweight='bold', fontsize=14, fontname='Arial', color='darkred', backgroundcolor='#f0f0f0', pad=1)
    ax.legend()
    plt.xticks(rotation=45, ha='right')  # Rotate x-axis labels if needed

    for bar, label in zip(ax.containers[0], df['type']):  # Correct container indexing
        height = bar.get_height()  # Height is now correct since bottom is updated within the loop
        count = df[df['type'] == label]['count'].values[0]
        ax.annotate(f'({int(count)})', xy=(bar.get_x() + bar.get_width() / 2, height), xytext=(0, 3), textcoords="offset points", ha='center', va='bottom',
                    fontsize=12)  # ha and va are correct here for annotations

    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    fig.text(0.05, 0.01, now_eastern, ha='left', fontsize=10)

    plt.tight_layout(rect=[0, 0.1, 1, 1])

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmpfile:
        plt.savefig(tmpfile.name, format="png")
    plt.close()
    return tmpfile.name


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
