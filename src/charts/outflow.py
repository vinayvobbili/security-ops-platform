import json
import os
import re
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import pytz
from PIL import Image
from matplotlib import transforms
from matplotlib.offsetbox import OffsetImage, AnnotationBbox
from matplotlib.ticker import MaxNLocator

from config import get_config
from services.xsoar import IncidentHandler

eastern = pytz.timezone('US/Eastern')

config = get_config()

ROOT_DIRECTORY = Path(__file__).parent.parent.parent
DETECTION_SOURCE_NAMES_ABBREVIATION_FILE = ROOT_DIRECTORY / 'data' / 'metrics' / 'detection_source_name_abbreviations.json'

with open(DETECTION_SOURCE_NAMES_ABBREVIATION_FILE, 'r') as f:
    detection_source_codes_by_name = json.load(f)

QUERY_TEMPLATE = 'type:{ticket_type_prefix} -owner:"" closed:>={start} closed:<{end}'

# Define a custom order for the impacts
CUSTOM_IMPACT_ORDER = ["Significant", "Confirmed", "Detected", "Prevented", "Ignore", "Testing", "False Positive"]

# --- Logo Configuration ---
LOGO_DIR = "web/static/logos"  # Directory where logos are stored
LOGO_SIZE = 0.04  # Size of the logo relative to the figure width (adjust as needed)

# Create a mapping of detection sources to logo file names (lowercase for matching)
LOGO_MAPPING = {
    "crowdstrike": "crowdstrike.png",
    "sentinelone": "sentinelone.png",
    "microsoft defender": "microsoft_defender.png",
    "cofense": "cofense.png",
    "proofpoint": "proofpoint.png",
    "virustotal": "virustotal.png",
    "trendmicro": "trendmicro.png",
    "mcafee": "mcafee.png",
    "checkpoint": "checkpoint.png"
}


def create_graph(tickets):
    if not tickets:
        print("No tickets to plot.")
        return

    # Process data
    df = pd.DataFrame(tickets)

    # Extract the 'detectionsource' and 'impact' from the 'CustomFields' dictionary
    df['source'] = df['CustomFields'].apply(lambda x: x.get('detectionsource'))
    df['impact'] = df['CustomFields'].apply(lambda x: x.get('impact'))

    # Fill missing values in a source with "Unknown" at the beginning
    df['source'] = df['source'].fillna('Unknown')

    for pattern, replacement in detection_source_codes_by_name.items():
        df['source'] = df['source'].str.replace(pattern, replacement, regex=True, flags=re.IGNORECASE)

    df['source'] = df.apply(lambda row: row['type']
                            .replace(config.ticket_type_prefix, '').strip()
                            .replace('CrowdStrike Falcon Detection', 'CS Detection').strip()
                            .replace('CrowdStrike Falcon Incident', 'CS Incident').strip()
                                        + ' - ' + row['source'], axis=1)

    # Count the occurrences of each source and impact
    source_impact_counts = df.groupby(['source', 'impact']).size().reset_index(name='count')

    # Sort sources by total ticket count (descending)
    source_totals = source_impact_counts.groupby('source')['count'].sum().sort_values(ascending=False)
    sorted_sources = source_totals.index.tolist()

    # Reorder sources to form a pyramid shape
    mid_index = len(sorted_sources) // 2
    pyramid_sources = sorted_sources[mid_index::-1] + sorted_sources[mid_index + 1:]

    # Define Colors for impacts
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
    fig, ax = plt.subplots(figsize=(14, 10))

    # Plot data
    bottom = [0] * len(pyramid_sources)
    impacts = source_impact_counts['impact'].unique()

    # Sort impacts based on the custom order
    sorted_impacts = [impact for impact in CUSTOM_IMPACT_ORDER if impact in impacts]

    for impact in sorted_impacts:
        impact_data = source_impact_counts[source_impact_counts['impact'] == impact]

        # Use the pre-sorted sources
        counts = []
        for source in pyramid_sources:
            if source in impact_data['source'].values:
                count = impact_data.loc[impact_data['source'] == source, 'count'].iloc[0]
                counts.append(count)
            else:
                counts.append(0)

        bars = ax.barh(pyramid_sources, counts, height=0.5, left=bottom, label=impact, color=impact_colors.get(impact, "#808080"), edgecolor="black", linewidth=0.3)

        # Add Value Labels
        for i, count in enumerate(counts):
            if count > 0:
                x_pos = bottom[i] + count / 2
                ax.text(x_pos, i, str(count), ha='center', va='center', color='black' if impact in ("Ignore", "Testing", "False Positive") else 'white', fontsize=12, fontweight='bold')

        bottom = [b + c for b, c in zip(bottom, counts)]

        # --- Add Logos at the End of Bars ---
        for i, bar in enumerate(bars):
            if counts[i] == 0:
                continue  # no logo on empty bars

            source = pyramid_sources[i]
            logo_filename = LOGO_MAPPING.get(source.lower())  # match logo with a source

            if logo_filename:  # If a logo is found for the source
                logo_path = os.path.join(LOGO_DIR, logo_filename)
                if os.path.exists(logo_path):  # Verify that the logo file exists
                    try:
                        # Resize logo
                        im = Image.open(logo_path)
                        width, height = im.size
                        max_size = 50  # max size for the logo
                        if max(width, height) > max_size:
                            if width > height:
                                new_width = max_size
                                new_height = int(max_size * (height / width))
                            else:
                                new_height = max_size
                                new_width = int(max_size * (width / height))
                            im = im.resize((new_width, new_height))
                        im.save(logo_path)
                        image = plt.imread(logo_path)
                        imagebox = OffsetImage(image, zoom=LOGO_SIZE)
                        ab = AnnotationBbox(imagebox, (bar.get_width() + bottom[i], bar.get_y() + bar.get_height() / 2), frameon=False)
                        ax.add_artist(ab)
                    except Exception as e:
                        print(f"Error adding logo {logo_filename}: {e}")

    ax.xaxis.set_major_locator(MaxNLocator(integer=True))

    # Extend the x-axis
    max_x_value = max(bottom)
    ax.set_xlim((0, max_x_value * 1.1))  # Extend 10% beyond the maximum x-value

    # Add labels and title
    ax.set_yticks(range(len(pyramid_sources)))
    ax.set_yticklabels(pyramid_sources, fontsize=12)
    ax.set_ylabel('Ticket Type - Detection Source', fontweight='bold', fontsize=12)
    ax.set_xlabel('Alert Counts', fontweight='bold', fontsize=10, labelpad=10)

    ax.set_title(f'Outflow Yesterday ({len(tickets)})', fontweight='bold', fontsize=12)
    ax.legend(title='Impact', loc='upper right', fontsize=10, title_fontsize=12)

    # Add a thin black border around the figure
    fig.patch.set_edgecolor('black')
    fig.patch.set_linewidth(5)

    # Add the current time to the chart
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    plt.text(0.08, 0.03, now_eastern, ha='left', va='bottom', fontsize=10, transform=trans)

    # Adjust layout
    plt.tight_layout()

    today_date = datetime.now().strftime('%m-%d-%Y')
    OUTPUT_PATH = ROOT_DIRECTORY / "web" / "static" / "charts" / today_date / "Outflow.png"
    plt.savefig(OUTPUT_PATH)
    plt.close(fig)


def make_chart() -> None:
    # Calculate fresh values EACH TIME the command is run
    yesterday_start = datetime.now(eastern).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
    yesterday_end = yesterday_start + timedelta(days=1)
    yesterday_start_utc = yesterday_start.astimezone(eastern).strftime('%Y-%m-%dT%H:%M:%SZ')
    yesterday_end_utc = yesterday_end.astimezone(eastern).strftime('%Y-%m-%dT%H:%M:%SZ')

    query = QUERY_TEMPLATE.format(ticket_type_prefix=config.ticket_type_prefix, start=yesterday_start_utc, end=yesterday_end_utc)
    tickets = IncidentHandler().get_tickets(query=query)
    create_graph(tickets)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    make_chart()
