import json
import re
from datetime import datetime, timedelta

import matplotlib.pyplot as plt
import pandas as pd
import pytz
from matplotlib import transforms

from config import get_config
from incident_fetcher import IncidentFetcher

eastern = pytz.timezone('US/Eastern')  # Define the Eastern time zone

config = get_config()

with open('data/detection_source_codes_by_name.json', 'r') as f:
    detection_source_codes_by_name = json.load(f)


def create_bar_chart(df, x_label, y_label, title):
    """Creates a bar chart from a pandas DataFrame."""
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(df.index, df['count'], color='#153289', width=0.5)
    ax.set_xlabel(x_label)
    ax.set_ylabel(y_label)
    ax.set_title(title, fontweight='bold', fontsize=12, )

    # Add count labels on top of each bar
    for bar in bars:
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, yval, yval, va='bottom', ha='center',
                fontdict={'fontsize': 10, 'fontweight': 'bold'})

    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    return fig


def add_timestamp(fig, now_eastern):
    """Adds a timestamp to the chart."""
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    plt.text(0.08, 0.03, now_eastern, ha='left', va='bottom', fontsize=10, transform=trans)


def plot_inflow():
    """Plots the ticket inflow by source using pandas."""
    query = f'-category:job type:{config.ticket_type_prefix} -owner:""'
    # Unable to build a period that fetches only yesterday's tickets. Work around: Fetch both today's and yesterday's tickets and filter out today's
    period = {"byFrom": "days", "fromValue": 1, "byTo": "days", "toValue": 0}

    tickets = IncidentFetcher().get_tickets(query=query, period=period)

    yesterday = (datetime.now(eastern) - timedelta(days=1)).date()
    tickets = [ticket for ticket in tickets if datetime.strptime(ticket.get('created'), '%Y-%m-%dT%H:%M:%S.%fZ').date() == yesterday]

    # Create a DataFrame from the tickets
    if not tickets:
        print('No tickets found matching the current query')
        return

    df = pd.DataFrame(tickets)

    # Extract the 'detectionsource' from the 'CustomFields' dictionary
    df['source'] = df['CustomFields'].apply(lambda x: x.get('detectionsource'))

    for pattern, replacement in detection_source_codes_by_name.items():
        df['source'] = df['source'].str.replace(pattern, replacement, regex=True, flags=re.IGNORECASE)

    # Count the occurrences of each source
    source_counts = df['source'].value_counts().rename_axis('source').reset_index(name='count')
    source_counts = source_counts.set_index('source')

    # Create the bar chart
    fig = create_bar_chart(source_counts, "Detection Source", "Number of Alerts", "Inflow Yesterday")

    # Add a thin black border around the figure
    fig.patch.set_edgecolor('black')
    fig.patch.set_linewidth(10)

    # Add the current time to the chart
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    add_timestamp(fig, now_eastern)

    fig.savefig('web/static/charts/Inflow.png')
    plt.close(fig)


if __name__ == '__main__':
    plot_inflow()
