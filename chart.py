import tempfile
from datetime import datetime

import pandas as pd
from matplotlib import pyplot as plt
from pytz import timezone


def make_pie(tickets, title) -> str:
    eastern = timezone('US/Eastern')  # Define the Eastern time zone
    df = pd.DataFrame(tickets)

    df['type'] = df['type'].str.replace('METCIRT ', '', regex=False)
    # Calculate counts for outer pie (type)
    type_counts = df['type'].value_counts()

    # Set up the colors
    outer_colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2', '#bcbd22', '#17becf', '#7f7f7f', '#ff9896',
                    '#c5b0d5', '#a6cee3', '#1f78b4', '#b2df8a', '#33a02c', '#fb9a99']

    # Create figure with wider aspect ratio to accommodate legend
    fig, ax = plt.subplots(figsize=(12, 8))

    # Create the outer pie chart (types)
    wedges, _, autotexts = ax.pie(type_counts.values,
                                  labels=None,
                                  colors=outer_colors,
                                  autopct='%1.1f%%',
                                  wedgeprops=dict(width=0.5, edgecolor='white'),
                                  pctdistance=0.75,
                                  startangle=140)

    # Add a legend on the right side in a single column
    ax.legend(
        wedges,
        type_counts.index,
        loc="center left",
        bbox_to_anchor=(1.0, 0.5),  # Position legend to the right of the chart
        ncol=1,  # Single column
        frameon=False  # Remove legend border
    )

    # Add counts as annotations
    total_tickets = len(df)

    # Add title
    plt.title(f'{title}: {total_tickets}', pad=15, fontsize=12, fontweight='bold')

    # Add timestamp at the bottom left
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    plt.figtext(0.02, 0.02, now_eastern, fontsize=10)

    # Adjust layout to accommodate legend
    plt.subplots_adjust(right=0.85)  # Make room for legend on right

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmpfile:
        filepath = tmpfile.name
        plt.savefig(filepath, format="png", bbox_inches='tight', dpi=300)
        plt.close(fig)

    return filepath
