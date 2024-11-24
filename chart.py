from datetime import datetime
import tempfile

import pandas as pd
from matplotlib import pyplot as plt, transforms
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

    # Create figure and axis
    fig, ax = plt.subplots()

    # Create the outer pie chart (types)
    wedges, _, autotexts = ax.pie(type_counts.values,
                                  labels=None,
                                  colors=outer_colors,
                                  autopct='%1.1f%%',  # Show percentage
                                  wedgeprops=dict(width=0.5, edgecolor='white'),
                                  labeldistance=1.1,
                                  pctdistance=0.75,
                                  startangle=140  # Rotate the chart
                                  )

    # Add a legend
    ax.legend(
        wedges,
        type_counts.index,
        loc="upper right",  # Position the legend outside the chart
        bbox_to_anchor=(1, 0, 0.5, 1),  # Fine-tune the position
    )

    # Add counts as annotations
    total_tickets = len(df)
    # Get figure and axes objects
    fig = plt.gcf()
    ax = plt.gca()
    # Transform coordinates to figure coordinates (bottom-left is 0,0)
    trans = transforms.blended_transform_factory(fig.transFigure, ax.transAxes)  # gets transform object
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    plt.text(0, -0.15, now_eastern, transform=trans, ha='left', va='bottom', fontsize=10)

    plt.title(f'{title}: {total_tickets}', transform=trans, loc='left', ha='left', va='bottom', fontsize=12,
              fontweight='bold')  # uses transform object instead of xmin, ymin

    # Adjust layout to prevent label clipping
    plt.tight_layout()

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmpfile:
        filepath = tmpfile.name  # Get the full path
        plt.savefig(filepath, format="png", bbox_inches='tight', dpi=300)
        plt.close(fig)

    return filepath  # Return the full path
