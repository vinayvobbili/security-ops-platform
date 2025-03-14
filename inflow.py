import json
import re
from datetime import datetime, timedelta

import matplotlib.pyplot as plt
import pandas as pd
import pytz
from matplotlib import transforms

from config import get_config
from services.xsoar import IncidentFetcher

eastern = pytz.timezone('US/Eastern')

config = get_config()

QUERY_TEMPLATE = 'type:{ticket_type_prefix} -owner:"" created:>={start} created:<{end}'

with open('data/detection_source_name_abbreviations.json', 'r') as f:
    detection_source_codes_by_name = json.load(f)


def create_stacked_bar_chart(df, x_label, y_label, title):
    """Creates a stacked bar chart from a pandas DataFrame."""
    fig, ax = plt.subplots(figsize=(10, 6))

    # Pivot the DataFrame to get the counts of each severity per source
    df_pivot = df.pivot_table(index='source', columns='severity', values='count', fill_value=0)

    # Plot the stacked bar chart with lighter shades
    bars = df_pivot.plot(kind='bar', stacked=True, ax=ax, color=['#6989e8', '#ffbb78', '#98df8a', '#ff9896'])

    ax.set_xlabel(x_label)
    ax.set_ylabel(y_label)
    ax.set_title(title, fontweight='bold', fontsize=12)

    # Increase the y-axis limit a few units over the max value
    max_value = df_pivot.sum(axis=1).max()
    ax.set_ylim(0, max_value + 3)

    # Add count labels on top of each stack
    for container in bars.containers:
        for bar in container:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_y() + height / 2, f'{int(height)}', ha='center', va='center', fontsize=10, fontweight='bold')

    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    return fig


def make_chart():
    """Plots the ticket inflow by source."""

    # Calculate fresh values EACH TIME the command is run
    et = pytz.timezone("US/Eastern")
    yesterday_start = datetime.now(et).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
    yesterday_end = yesterday_start + timedelta(days=1)
    yesterday_start_utc = yesterday_start.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    yesterday_end_utc = yesterday_end.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    query = QUERY_TEMPLATE.format(ticket_type_prefix=config.ticket_type_prefix, start=yesterday_start_utc, end=yesterday_end_utc)
    tickets = IncidentFetcher().get_tickets(query=query)

    # Create a DataFrame from the tickets
    if not tickets:
        print('No tickets found matching the current query')
        return

    df = pd.DataFrame(tickets)

    # Extract the 'detectionsource' from the 'CustomFields' dictionary and 'severity' directly from the ticket
    df['source'] = df['CustomFields'].apply(lambda x: x.get('detectionsource'))
    df['severity'] = df['severity']

    for pattern, replacement in detection_source_codes_by_name.items():
        df['source'] = df['source'].str.replace(pattern, replacement, regex=True, flags=re.IGNORECASE)

    # Count the occurrences of each source and severity
    source_severity_counts = df.groupby(['source', 'severity']).size().reset_index(name='count')

    # Create the stacked bar chart
    fig = create_stacked_bar_chart(source_severity_counts, "Detection Source", "Number of Alerts", "Inflow Yesterday")

    # Add a thin black border around the figure
    fig.patch.set_edgecolor('black')
    fig.patch.set_linewidth(5)

    # Add the current time to the chart
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    plt.text(0.08, 0.03, now_eastern, ha='left', va='bottom', fontsize=10, transform=trans)

    fig.savefig('web/static/charts/Inflow.png')
    plt.close(fig)


if __name__ == '__main__':
    make_chart()
