import tempfile
from datetime import datetime

import pandas as pd
from matplotlib import pyplot as plt
from pytz import timezone

from config import get_config

config = get_config()


def make_pie(tickets, title) -> str:
    eastern = timezone('US/Eastern')  # Define the Eastern time zone
    df = pd.DataFrame(tickets)

    if df.empty:
        fig, ax = plt.subplots()
        ax.text(0.5, 0.5, "No data available", ha='center', va='center')

        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmpfile:
            filepath = tmpfile.name
            plt.savefig(filepath, format="png", bbox_inches='tight', dpi=300)
            plt.close(fig)
        return filepath

    df['type'] = df['type'].str.replace(config.ticket_type_prefix, '', regex=False)
    # Calculate counts for outer pie (type)
    type_counts = df['type'].value_counts()

    # Set up the colors
    outer_colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2', '#bcbd22', '#17becf', '#7f7f7f', '#ff9896',
                    '#c5b0d5', '#a6cee3', '#1f78b4', '#b2df8a', '#33a02c', '#fb9a99']

    # Reduce height in figure size
    fig, ax = plt.subplots(figsize=(6, 4))

    # Create the outer pie chart (types)
    wedges, _, autotexts = ax.pie(type_counts.values,
                                  labels=None,
                                  colors=outer_colors,
                                  autopct='%1.1f%%',
                                  wedgeprops=dict(width=0.5, edgecolor='white'),
                                  pctdistance=0.75,
                                  startangle=140)

    # Add a legend with tight spacing
    ax.legend(
        wedges,
        type_counts.index,
        loc="center left",
        bbox_to_anchor=(1.0, 0.5),
        ncol=1,
        frameon=False,
        handletextpad=0.5,
        labelspacing=0.8
    )

    # Add title with minimal padding
    total_tickets = len(df)
    plt.title(f'{title}: {total_tickets}', pad=5, fontsize=12, fontweight='bold')

    # Timestamp with minimal bottom margin
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    plt.figtext(0.99, 0.02, now_eastern, fontsize=8, ha='right')

    # Much tighter vertical margins
    plt.subplots_adjust(left=0.05, right=0.85, top=0.95, bottom=0.05)

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmpfile:
        filepath = tmpfile.name
        plt.savefig(filepath, format="png", bbox_inches='tight', dpi=300)
        plt.close(fig)

    return filepath
