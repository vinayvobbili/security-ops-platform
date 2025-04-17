import json
import re
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pytz
from matplotlib import transforms

from config import get_config
from services.xsoar import IncidentHandler

eastern = pytz.timezone('US/Eastern')

config = get_config()

QUERY_TEMPLATE = 'type:{ticket_type_prefix} -owner:"" created:>={start} created:<{end}'

root_directory = Path(__file__).parent.parent.parent
DETECTION_SOURCE_NAMES_ABBREVIATION_FILE = root_directory / 'data' / 'detection_source_name_abbreviations.json'

with open(DETECTION_SOURCE_NAMES_ABBREVIATION_FILE, 'r') as f:
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

    # Ensure y-ticks are integers
    ax.yaxis.set_major_locator(plt.MaxNLocator(integer=True))

    # Add count labels on top of each stack
    for container in bars.containers:
        for bar in container:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_y() + height / 2, f'{int(height)}', ha='center', va='center', fontsize=10, fontweight='bold')

    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    return fig


def plot_yesterday():
    """Plots the ticket inflow by source."""

    # Calculate fresh values EACH TIME the command is run
    et = pytz.timezone("US/Eastern")
    yesterday_start = datetime.now(et).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
    yesterday_end = yesterday_start + timedelta(days=1)
    yesterday_start_utc = yesterday_start.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    yesterday_end_utc = yesterday_end.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    query = QUERY_TEMPLATE.format(ticket_type_prefix=config.ticket_type_prefix, start=yesterday_start_utc, end=yesterday_end_utc)
    tickets = IncidentHandler().get_tickets(query=query)

    # Create a DataFrame from the tickets
    if not tickets:
        print('No tickets found matching the current query')
        return

    df = pd.DataFrame(tickets)

    # Extract the 'detectionsource' from the 'CustomFields' dictionary and 'severity' directly from the ticket
    df['source'] = df['CustomFields'].apply(lambda x: x.get('detectionsource'))
    df['severity'] = df['severity']

    # Handle missing values:
    df['source'] = df['source'].fillna('Unknown')
    df['severity'] = df['severity'].fillna('Unknown')

    for pattern, replacement in detection_source_codes_by_name.items():
        df['source'] = df['source'].str.replace(pattern, replacement, regex=True, flags=re.IGNORECASE)

    # Normalize empty strings to "Unknown"
    df['source'] = df['source'].replace('', 'Unknown')

    # Count the occurrences of each source and severity
    source_severity_counts = df.groupby(['source', 'severity']).size().reset_index(name='count')

    # Create the stacked bar chart
    fig = create_stacked_bar_chart(source_severity_counts, "Detection Source", "Number of Alerts", f"Inflow Yesterday ({len(tickets)})")

    # Add a thin black border around the figure
    fig.patch.set_edgecolor('black')
    fig.patch.set_linewidth(5)

    # Add the current time to the chart
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    plt.text(0.08, 0.03, now_eastern, ha='left', va='bottom', fontsize=10, transform=trans)

    today_date = datetime.now().strftime('%m-%d-%Y')
    OUTPUT_PATH = root_directory / "web" / "static" / "charts" / today_date / "Inflow Yesterday.png"
    fig.savefig(OUTPUT_PATH)
    plt.close(fig)


def plot_past_60_days():
    query = f'type:{config.ticket_type_prefix} -owner:""'
    period = {
        "by": "day",
        "fromValue": 60
    }
    tickets = IncidentHandler().get_tickets(query=query, period=period)

    if not tickets:
        print("No tickets found for the past 60 days.")
        return

    df = pd.DataFrame(tickets)

    # Extract 'created_date' and 'impact' fields
    df['created_date'] = pd.to_datetime(df['created'], format='ISO8601', errors='coerce').dt.date
    df['impact'] = df['CustomFields'].apply(lambda x: x.get('impact', 'Unknown'))

    # Group by 'created_date' and 'impact', then count occurrences
    date_impact_counts = df.groupby(['created_date', 'impact'], observed=True).size().reset_index(name='count')

    # Define custom order and colors
    CUSTOM_IMPACT_ORDER = ["Significant", "Confirmed", "Detected", "Prevented", "Ignore", "Testing", "False Positive"]
    impact_colors = {
        "Significant": "#ff0000",  # Red
        "Confirmed": "#ffa500",  # Orange
        "Detected": "#ffd700",  # Gold
        "Prevented": "#008000",  # Green
        "Ignore": "#808080",  # Gray
        "Testing": "#add8e6",  # Light Blue
        "False Positive": "#90ee90",  # Light green
    }

    # Ensure impacts follow the custom order
    date_impact_counts['impact'] = pd.Categorical(date_impact_counts['impact'], categories=CUSTOM_IMPACT_ORDER, ordered=True)

    # Instead of using pivot_table (which might trigger the warning),
    # We'll manually create the pivot data structure
    # First, sort by date and get unique dates
    unique_dates = sorted(date_impact_counts['created_date'].unique())

    # Create a dict to hold our data
    pivot_data = {impact: np.zeros(len(unique_dates)) for impact in CUSTOM_IMPACT_ORDER}

    # Fill in the values
    for _, row in date_impact_counts.iterrows():
        date_idx = list(unique_dates).index(row['created_date'])
        impact = row['impact']
        count = row['count']
        if impact in pivot_data:
            pivot_data[impact][date_idx] += count

    # Create a figure with proper size
    fig, ax = plt.subplots(figsize=(16, 8))

    # Get dates and format them for display
    dates = [date.strftime('%m/%d') for date in unique_dates]

    # Get position indices for the x-axis
    x = np.arange(len(dates))

    # Plot each impact category as a separate bar component
    bottom = np.zeros(len(dates))
    for impact in CUSTOM_IMPACT_ORDER:
        values = pivot_data[impact]
        ax.bar(x, values, bottom=bottom, label=impact, color=impact_colors.get(impact, '#000000'))
        bottom += values

    # Plot a horizontal line for the daily average
    daily_average = date_impact_counts.groupby('created_date')['count'].sum().mean()
    ax.axhline(daily_average, color='blue', linestyle='--', linewidth=1.5, label=f'Daily Average ({int(daily_average)})')
    # Set x-ticks at the correct positions
    ax.set_xticks(x)
    ax.set_ylim(0, bottom.max() * 1.1)  # Add 10% extra space above the tallest bar

    # Show only every nth label to prevent crowding
    n = 5  # Show every 5th label
    date_labels = dates.copy()
    for i in range(len(dates)):
        if i % n != 0:
            date_labels[i] = ""

    ax.set_xticklabels(date_labels, rotation=45, ha='right', fontsize=8)

    # Add labels and title
    ax.set_xlabel("Created Date", fontweight='bold', fontsize=10)
    ax.set_ylabel("Number of Tickets", fontweight='bold', fontsize=10)
    ax.set_title("Ticket Inflow Over the Past 60 Days", fontweight='bold', fontsize=12)

    # Add legend
    ax.legend(title='Impact', title_fontproperties={'weight': 'bold'})

    # Add a thin black border around the figure
    fig.patch.set_edgecolor('black')
    fig.patch.set_linewidth(5)

    # Add the current time to the chart
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    plt.text(0.05, 0.01, now_eastern, ha='left', va='bottom', fontsize=10, transform=trans)

    # Save the chart
    today_date = datetime.now().strftime('%m-%d-%Y')
    OUTPUT_PATH = root_directory / "web" / "static" / "charts" / today_date / "Inflow Past 60 Days.png"

    # Ensure directory exists
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    plt.tight_layout()
    fig.savefig(OUTPUT_PATH)
    plt.close(fig)


def make_chart():
    try:
        plot_yesterday()
        plot_past_60_days()
    except Exception as e:
        print(f"An error occurred while generating charts: {e}")


if __name__ == '__main__':
    plot_past_60_days()
