import json
import re
from datetime import datetime, timedelta

import matplotlib.pyplot as plt
import pandas as pd
import pytz
from matplotlib import transforms

from config import get_config
from incident_fetcher import IncidentFetcher

eastern = pytz.timezone('US/Eastern')

config = get_config()

with open('data/detection_source_codes_by_name.json', 'r') as f:
    detection_source_codes_by_name = json.load(f)

QUERY_TEMPLATE = '-category:job type:{ticket_type_prefix} -owner:"" closed:>={start} closed:<{end}'

# Define a custom order for the impacts
CUSTOM_IMPACT_ORDER = ["Significant", "Confirmed", "Detected", "Prevented", "Ignore", "Testing", "False Positive"]


def create_graph(tickets):
    if not tickets:
        print("No tickets to plot.")
        return

    # Process data
    df = pd.DataFrame(tickets)

    # Extract the 'detectionsource' and 'impact' from the 'CustomFields' dictionary
    df['source'] = df['CustomFields'].apply(lambda x: x.get('detectionsource'))
    df['impact'] = df['CustomFields'].apply(lambda x: x.get('impact'))

    for pattern, replacement in detection_source_codes_by_name.items():
        df['source'] = df['source'].str.replace(pattern, replacement, regex=True, flags=re.IGNORECASE)

    # Count the occurrences of each source and impact
    source_impact_counts = df.groupby(['source', 'impact']).size().reset_index(name='count')

    # Sort sources by total ticket count (descending)
    source_totals = source_impact_counts.groupby('source')['count'].sum().sort_values(ascending=False)
    sorted_sources = source_totals.index.tolist()

    # Define Colors for impacts (Updated for new values)
    impact_colors = {
        "Significant": "#ff0000",  # Red
        "Confirmed": "#ffa500",  # Orange
        "Detected": "#ffd700",  # Gold
        "Prevented": "#008000",  # Green
        "Ignore": "#808080",  # Gray
        "Testing": "#add8e6",  # Light Blue
        "False Positive": "#90ee90",  # Light green
    }

    # Create figure and axis
    fig, ax = plt.subplots(figsize=(12, 10))

    # Plot data
    bottom = [0] * len(sorted_sources)
    impacts = source_impact_counts['impact'].unique()

    # Sort impacts based on the custom order
    sorted_impacts = [impact for impact in CUSTOM_IMPACT_ORDER if impact in impacts]

    for impact in sorted_impacts:
        impact_data = source_impact_counts[source_impact_counts['impact'] == impact]

        # Use the pre-sorted sources
        counts = []
        for source in sorted_sources:
            if source in impact_data['source'].values:
                count = impact_data.loc[impact_data['source'] == source, 'count'].iloc[0]
                counts.append(count)
            else:
                counts.append(0)

        ax.barh(sorted_sources, counts, left=bottom, label=impact, color=impact_colors.get(impact, "#808080"),
                edgecolor="black", linewidth=0.3)

        # Add Value Labels
        for i, count in enumerate(counts):
            if count > 0:
                x_pos = bottom[i] + count / 2
                if impact in ("Ignore", "Testing", "False Positive"):
                    ax.text(x_pos, i, str(count), ha='center', va='center', color='black', fontsize=10, fontweight='bold')
                else:
                    ax.text(x_pos, i, str(count), ha='center', va='center', color='white', fontsize=10, fontweight='bold')

        bottom = [b + c for b, c in zip(bottom, counts)]

    # Extend the x-axis
    max_x_value = max(bottom)
    ax.set_xlim([0, max_x_value * 1.1])  # Extend 10% beyond the maximum x-value

    # Add labels and title
    ax.set_yticks(range(len(sorted_sources)))
    ax.set_yticklabels(sorted_sources)
    ax.set_ylabel('Detection Source')
    ax.set_xlabel('Ticket Counts')

    ax.set_title('Outflow Yesterday', fontweight='bold', fontsize=12)
    ax.legend(title='Impact', loc='upper right')

    # Add a thin black border around the figure
    fig.patch.set_edgecolor('black')
    fig.patch.set_linewidth(5)

    # Add the current time to the chart
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    """Adds a timestamp to the chart."""
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    plt.text(0.08, 0.03, now_eastern, ha='left', va='bottom', fontsize=10, transform=trans)

    # Adjust layout
    plt.tight_layout()
    plt.savefig('web/static/charts/Outflow.png')
    plt.close(fig)


def make_chart() -> None:
    # Calculate fresh values EACH TIME the command is run
    et = pytz.timezone("US/Eastern")
    yesterday_start = datetime.now(et).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
    yesterday_end = yesterday_start + timedelta(days=1)
    yesterday_start_utc = yesterday_start.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    yesterday_end_utc = yesterday_end.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    query = QUERY_TEMPLATE.format(ticket_type_prefix=config.ticket_type_prefix, start=yesterday_start_utc,
                                  end=yesterday_end_utc)
    tickets = IncidentFetcher().get_tickets(query=query)
    print(f"Number of tickets returned: {len(tickets)}")
    create_graph(tickets)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    make_chart()
