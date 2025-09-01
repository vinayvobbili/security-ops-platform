import json
import os
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import pytz
from PIL import Image
from matplotlib import transforms
from matplotlib.offsetbox import OffsetImage, AnnotationBbox
from matplotlib.ticker import MaxNLocator

# Add the project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from my_config import get_config
from services.xsoar import TicketHandler

eastern = pytz.timezone('US/Eastern')

config = get_config()

ROOT_DIRECTORY = Path(__file__).parent.parent.parent
DETECTION_SOURCE_NAMES_ABBREVIATION_FILE = ROOT_DIRECTORY / 'data' / 'metrics' / 'detection_source_name_abbreviations.json'

with open(DETECTION_SOURCE_NAMES_ABBREVIATION_FILE, 'r') as f:
    detection_source_codes_by_name = json.load(f)

QUERY_TEMPLATE = 'type:{ticket_type_prefix} -owner:"" closed:>={start} closed:<{end}'

# Define a custom order for the impacts
CUSTOM_IMPACT_ORDER = ["Significant", "Confirmed", "Detected", "Prevented", "Ignore", "Testing", "Security Testing", "False Positive", "Benign True Positive", "Malicious True Positive"]

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

    # Set up enhanced plot style without grids
    plt.style.use('default')

    # Configure matplotlib fonts
    import matplotlib
    matplotlib.rcParams['font.family'] = ['DejaVu Sans', 'Arial Unicode MS', 'Arial']

    # Process data
    df = pd.DataFrame(tickets)

    # Extract the 'detectionsource' and 'impact' from the 'CustomFields' dictionary
    df['source'] = df['CustomFields'].apply(lambda x: x.get('detectionsource'))
    df['impact'] = df['CustomFields'].apply(lambda x: x.get('impact'))

    # Fill missing values in a source with "Unknown" at the beginning
    df['source'] = df['source'].fillna('Unknown')
    df['impact'] = df['impact'].fillna('Unknown')
    df['impact'] = df['impact'].replace('', 'Unknown')

    for pattern, replacement in detection_source_codes_by_name.items():
        df['source'] = df['source'].str.replace(pattern, replacement, regex=True, flags=re.IGNORECASE)

    # Simplify to show only ticket types without detection sources
    df['source'] = df.apply(lambda row: row['type']
                            .replace(config.team_name, '').strip()
                            .replace('CrowdStrike Falcon Detection', 'CS Detection').strip()
                            .replace('CrowdStrike Falcon Incident', 'CS Incident').strip()
                            .replace('Prisma Cloud Compute Runtime Alert', 'Prisma Runtime').strip()
                            .replace('Lost or Stolen Computer', 'Lost/Stolen Device').strip(), axis=1)

    # Count the occurrences of each source and impact
    source_impact_counts = df.groupby(['source', 'impact']).size().reset_index(name='count')

    # Sort sources by total ticket count (descending)
    source_totals = source_impact_counts.groupby('source')['count'].sum().sort_values(ascending=False)
    sorted_sources = source_totals.index.tolist()

    # Reorder sources to form a pyramid shape
    mid_index = len(sorted_sources) // 2
    pyramid_sources = sorted_sources[mid_index::-1] + sorted_sources[mid_index + 1:]

    # Define Colors for impacts with enhanced professional palette
    impact_colors = {
        "Malicious True Positive": "#DC2626",  # Modern red
        "Confirmed": "#EA580C",  # Modern orange
        "Detected": "#CA8A04",  # Modern amber
        "Prevented": "#16A34A",  # Modern green
        "Ignore": "#1F2937",  # Dark gray
        "Testing": "#10B981",  # Emerald
        "Security Testing": "#059669",  # Dark emerald
        "False Positive": "#9CA3AF",  # Light gray
        "Benign True Positive": "#6B7280",  # Medium gray
        "Unknown": "#3B82F6"  # Modern blue
    }

    # Enhanced figure with better proportions and styling
    fig, ax = plt.subplots(figsize=(14, 10), facecolor='#f8f9fa')
    fig.patch.set_facecolor('#f8f9fa')

    # Plot data
    bottom = [0] * len(pyramid_sources)
    impacts = source_impact_counts['impact'].unique()

    # Sort impacts based on the custom order, including any impacts not in the custom order
    sorted_impacts = [impact for impact in CUSTOM_IMPACT_ORDER if impact in impacts]
    # Add any impacts that are in the data but not in the custom order
    for impact in impacts:
        if impact not in sorted_impacts:
            sorted_impacts.append(impact)

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

        bars = ax.barh(pyramid_sources, counts, height=0.6, left=bottom, label=impact,
                       color=impact_colors.get(impact, "#6B7280"),
                       edgecolor="white", linewidth=1.5, alpha=0.95)

        # Enhanced value labels with black circles (matching MTTR style)
        for i, count in enumerate(counts):
            if count > 0:
                x_pos = bottom[i] + count / 2

                ax.text(x_pos, i, str(count), ha='center', va='center',
                        color='white', fontsize=10, fontweight='bold',
                        bbox=dict(boxstyle="circle,pad=0.2", facecolor='black',
                                  alpha=0.8, edgecolor='white', linewidth=1))

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

    # Enhanced axes styling
    ax.set_facecolor('#ffffff')
    ax.grid(False)  # Explicitly disable grid
    ax.set_axisbelow(True)

    # Style the spines
    for spine in ax.spines.values():
        spine.set_color('#CCCCCC')
        spine.set_linewidth(1.5)

    ax.xaxis.set_major_locator(MaxNLocator(integer=True))

    # Extend the x-axis
    max_x_value = max(bottom)
    ax.set_xlim((0, max_x_value * 1.1))  # Extend 10% beyond the maximum x-value

    # Enhanced border with rounded corners like MTTR chart
    from matplotlib.patches import FancyBboxPatch
    border_width = 4
    fig.patch.set_edgecolor('none')
    fig.patch.set_linewidth(0)

    fancy_box = FancyBboxPatch(
        (0, 0), width=1.0, height=1.0,
        boxstyle="round,pad=0,rounding_size=0.01",
        edgecolor='#1A237E',
        facecolor='none',
        linewidth=border_width,
        transform=fig.transFigure,
        zorder=1000,
        clip_on=False
    )
    fig.patches.append(fancy_box)

    # Enhanced titles and labels
    plt.suptitle(f'Outflow Yesterday ({len(tickets)})',
                 fontsize=20, fontweight='bold', color='#1A237E', y=0.95)

    # Add labels with enhanced styling
    ax.set_yticks(range(len(pyramid_sources)))
    ax.set_yticklabels(pyramid_sources, fontsize=10, color='#1A237E')
    ax.set_ylabel('Ticket Type', fontweight='bold', fontsize=12, color='#1A237E')
    ax.set_xlabel('Alert Counts', fontweight='bold', fontsize=12, labelpad=10, color='#1A237E')

    # Calculate impact totals for legend
    impact_totals = df.groupby('impact')['impact'].count().to_dict()
    
    # Update legend labels with counts
    impact_labels = []
    for impact in sorted_impacts:
        count = impact_totals.get(impact, 0)
        impact_labels.append(f"{impact} ({count})")
    
    # Enhanced legend positioned outside like MTTR chart
    legend = ax.legend(impact_labels, title='Impact', loc='upper left', bbox_to_anchor=(1.15, 1),
                       frameon=True, fancybox=True, shadow=True,
                       title_fontsize=12, fontsize=10)
    legend.get_frame().set_facecolor('white')
    legend.get_frame().set_alpha(0.95)
    legend.get_frame().set_edgecolor('#1A237E')
    legend.get_frame().set_linewidth(2)
    
    # Make legend title bold
    legend.get_title().set_fontweight('bold')

    # Enhanced timestamp with modern styling - moved to left end
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')

    plt.text(0.02, 0.02, f"Generated@ {now_eastern}",
             transform=trans, ha='left', va='bottom',
             fontsize=10, color='#1A237E', fontweight='bold',
             bbox=dict(boxstyle="round,pad=0.4", facecolor='white', alpha=0.9,
                       edgecolor='#1A237E', linewidth=1.5))

    # Add GS-DnR watermark
    fig.text(0.99, 0.01, 'GS-DnR',
             ha='right', va='bottom', fontsize=10,
             alpha=0.7, color='#3F51B5', style='italic', fontweight='bold')

    # Adjust layout with space for external legend and Y-axis labels
    plt.tight_layout()
    plt.subplots_adjust(top=0.88, bottom=0.15, left=0.20, right=0.73)

    today_date = datetime.now().strftime('%m-%d-%Y')
    output_path = ROOT_DIRECTORY / "web" / "static" / "charts" / today_date / "Outflow.png"
    output_path.parent.mkdir(parents=True, exist_ok=True)  # Ensure the directory exists
    plt.savefig(output_path, format='png', bbox_inches='tight', pad_inches=0.2, dpi=300)
    plt.close(fig)


def make_chart() -> None:
    # Calculate fresh values EACH TIME the command is run
    yesterday_start = datetime.now(eastern).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
    yesterday_end = yesterday_start + timedelta(days=1)
    yesterday_start_utc = yesterday_start.astimezone(eastern).strftime('%Y-%m-%dT%H:%M:%SZ')
    yesterday_end_utc = yesterday_end.astimezone(eastern).strftime('%Y-%m-%dT%H:%M:%SZ')

    query = QUERY_TEMPLATE.format(ticket_type_prefix=config.team_name, start=yesterday_start_utc, end=yesterday_end_utc)
    tickets = TicketHandler().get_tickets(query=query)
    create_graph(tickets)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    make_chart()
