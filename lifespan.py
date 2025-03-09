import json
import logging
import re
import tempfile
from datetime import datetime

import matplotlib.pyplot as plt
import pandas as pd
import pytz

from config import get_config
from xsoar import IncidentFetcher

eastern = pytz.timezone('US/Eastern')  # Define the Eastern time zone

config = get_config()

with open('data/detection_source_name_abbreviations.json', 'r') as f:
    detection_source_codes_by_name = json.load(f)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

QUERY = f'type:{config.ticket_type_prefix} -owner:"" status:closed'
PERIOD = {
    "byFrom": "months",
    "fromValue": 1
}


def get_lifespan_chart(tickets):
    if not tickets:
        fig, ax = plt.subplots(figsize=(8, 6))  # set the default file size here
        ax.text(0.5, 0.5, 'No tickets found!', ha='center', va='center', fontsize=12)
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmpfile:
            plt.savefig(tmpfile.name, format="png")
        plt.close()
        return tmpfile.name

    data = []
    for ticket in tickets:
        custom_fields = ticket.get('CustomFields', {})
        data.append({
            'type': ticket.get('type').replace(f'{config.ticket_type_prefix} ', ''),
            'triage': custom_fields.get(config.triage_timer, {}).get('totalDuration', 0) / 3600,
            'lessons': custom_fields.get(config.lessons_learned_time, {}).get('totalDuration', 0) / 3600,
            'investigate': custom_fields.get(config.investigation_time, {}).get('totalDuration', 0) / 3600,
            'eradicate': custom_fields.get(config.eradication_time, {}).get('totalDuration', 0) / 3600,
            'closure': custom_fields.get(config.closure_time, {}).get('totalDuration', 0) / 3600,
        })

    df = pd.DataFrame(data)
    df['lifespan'] = df[['triage', 'lessons', 'investigate', 'eradicate', 'closure']].sum(axis=1)
    df['count'] = 1
    for pattern, replacement in detection_source_codes_by_name.items():
        df['type'] = df['type'].str.replace(pattern, replacement, regex=True, flags=re.IGNORECASE)
    df = df.groupby('type').sum().reset_index()
    df = df[df['lifespan'] > 0].sort_values('lifespan', ascending=False)

    colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']
    fig, ax = plt.subplots(figsize=(8, 6))  # set the default file size here

    bar_width = 0.5
    bottom = 0
    for i, col in enumerate(['closure', 'lessons', 'eradicate', 'investigate', 'triage']):
        ax.bar(df['type'], df[col], label=col.capitalize(), bottom=bottom, color=colors[i % len(colors)], width=bar_width)
        bottom += df[col]

    ax.set_xlabel("Ticket Type (last 30 days)", fontweight='bold')
    ax.set_ylabel("Hours", fontweight='bold')
    ax.set_title("Cumulative Lifespan by Type", fontweight='bold', fontsize=14, fontname='Arial', color='darkred', backgroundcolor='#f0f0f0', pad=0)
    ax.legend(title='Phase', loc='upper right')
    plt.xticks(rotation=45, ha='right')  # Rotate x-axis labels if needed

    for bar, label in zip(ax.containers[0], df['type']):  # Correct container indexing
        height = bar.get_height()  # Height is now correct since bottom is updated within the loop
        count = df[df['type'] == label]['count'].values[0]
        ax.annotate(f'{int(count)}', xy=(bar.get_x() + bar.get_width() / 2, height), xytext=(0, 3), textcoords="offset points", ha='center', va='bottom',
                    fontsize=12)  # ha and va are correct here for annotations

    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    fig.text(0.05, 0.01, now_eastern, ha='left', fontsize=10)

    # Add a thin black border around the figure
    fig.patch.set_edgecolor('black')
    fig.patch.set_linewidth(5)

    plt.tight_layout()

    plt.savefig('web/static/charts/Lifespan.png', format="png")
    plt.close()


def make_chart():
    incident_fetcher = IncidentFetcher()
    tickets = incident_fetcher.get_tickets(query=QUERY, period=PERIOD)
    get_lifespan_chart(tickets)


if __name__ == '__main__':
    make_chart()
