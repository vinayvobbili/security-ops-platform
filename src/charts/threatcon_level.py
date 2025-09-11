import json
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyArrow

# Define constants
ROOT_DIRECTORY = Path(__file__).parent.parent.parent
THREAT_CON_FILE = ROOT_DIRECTORY / "data" / "transient" / "secOps" / "threatcon.json"

# Original clean color mappings with darker, more professional colors
COLORS = {
    'red': {
        'arc': '#8B0000',  # Dark red
        'font': '#8B0000',
        'table_bg': '#FFB6C1'
    },
    'orange': {
        'arc': '#FF8C00',  # Proper bright orange
        'font': '#CC6600',  # Darker orange for text readability
        'table_bg': '#FFE4B5'
    },
    'yellow': {
        'arc': '#FFD700',  # Proper yellow - gold color
        'font': '#B8860B',  # Darker yellow for text readability
        'table_bg': '#FFFFE0'
    },
    'green': {
        'arc': '#006400',  # Dark green
        'font': '#006400',
        'table_bg': '#F0FFF0'
    }
}

# Define threat levels and their angles
THREAT_ANGLES = {
    'red': 22.5,
    'orange': 67.5,
    'yellow': 112.5,
    'green': 157.5
}


def load_threatcon_data(file_path):
    """
    Load the threatcon data from the specified JSON file.

    Args:
        file_path (Path): Path to the JSON file containing threatcon data.
            Expected format: {"level": "red|orange|yellow|green", "reason": "text explanation"}

    Returns:
        dict: The threatcon details with level and reason.

    Raises:
        FileNotFoundError: If the threatcon file doesn't exist.
        ValueError: If the threatcon data is missing required fields or has invalid values.
    """
    try:
        with open(file_path, "r") as file:
            data = json.load(file)

        # Validate the data structure
        if not isinstance(data, dict):
            raise ValueError("Threatcon data must be a JSON object")

        if 'level' not in data:
            raise ValueError("Threatcon data missing 'level' field")

        if data['level'] not in COLORS:
            raise ValueError(f"Invalid threatcon level: {data['level']}. Must be one of: {', '.join(COLORS.keys())}")

        if 'reason' not in data and data['level'] != 'green':
            # Only require reason for non-green levels
            data['reason'] = "No reason provided"

        return data

    except json.JSONDecodeError:
        raise ValueError("Invalid JSON format in threatcon file")


def create_gauge_arcs(ax):
    """
    Create clean colored arcs for the gauge - simple and professional.

    Args:
        ax (matplotlib.axes.Axes): The axes to draw on.
    """
    # Set the gauge range
    angles = np.linspace(0, 180)

    # Create color ranges
    red_range = angles <= 45
    orange_range = (angles > 45) & (angles <= 90)
    yellow_range = (angles > 90) & (angles <= 135)
    green_range = angles > 135

    # Define radius and draw clean arcs
    radius = 1
    ax.plot(radius * np.cos(np.radians(angles[red_range])),
            radius * np.sin(np.radians(angles[red_range])),
            color=COLORS['red']['arc'], linewidth=20, zorder=1)

    ax.plot(radius * np.cos(np.radians(angles[orange_range])),
            radius * np.sin(np.radians(angles[orange_range])),
            color=COLORS['orange']['arc'], linewidth=20, zorder=1)

    ax.plot(radius * np.cos(np.radians(angles[yellow_range])),
            radius * np.sin(np.radians(angles[yellow_range])),
            color=COLORS['yellow']['arc'], linewidth=20, zorder=1)

    ax.plot(radius * np.cos(np.radians(angles[green_range])),
            radius * np.sin(np.radians(angles[green_range])),
            color=COLORS['green']['arc'], linewidth=20, zorder=1)

    # Add simple gauge border
    outer_radius = 1.04
    ax.plot(outer_radius * np.cos(np.radians(angles)),
            outer_radius * np.sin(np.radians(angles)),
            color='black', linewidth=1, zorder=2)

    # Add horizontal baseline
    ax.plot([-outer_radius, outer_radius], [0, 0], color='black', linewidth=1, zorder=2)


def add_gauge_needle(ax, threatcon_color):
    """
    Add a clean needle to the gauge based on the threat level.
    """
    # Get the angle for the needle
    rad_angle = np.radians(THREAT_ANGLES[threatcon_color])

    # Draw the needle (arrow) - clean and simple
    arrow_length = 0.80
    arrow_width = 0.04
    arrow = FancyArrow(0, 0,
                       arrow_length * np.cos(rad_angle),
                       arrow_length * np.sin(rad_angle),
                       width=arrow_width,
                       color='#1A237E', zorder=3)
    ax.add_patch(arrow)

    # Add simple center dot (pivot point)
    ax.plot(0, 0, 'ko', markersize=20, zorder=2)


def add_reason_text(fig, threatcon_details):
    """
    Add reason text to the figure if the threat level is not green.
    """
    threatcon_color = threatcon_details['level']

    if threatcon_color != 'green':
        reason_text = f"Reason:\n{threatcon_details['reason']}"
        # Use darker color for better readability
        font_color = '#333333'  # Dark gray for better contrast on light background

        fig.text(0.2, 0.4, reason_text,
                 ha='left', va='center',
                 fontsize=10,
                 color=font_color,
                 bbox=dict(facecolor='#F5F5F5',  # Much lighter gray background
                           edgecolor='black',
                           boxstyle='round,pad=0.5',
                           linewidth=1))


def create_definitions_table(plt):
    """
    Create a table with threat level definitions at the bottom of the chart.

    Args:
        plt (matplotlib.pyplot): The pyplot instance.

    Returns:
        matplotlib.table.Table: The created table object.
    """
    # Define the threat level details
    threat_details = [
        ["Level", "Description"],
        ["GREEN", "No known significant threats or on-going attacks"],
        ["YELLOW", "There are global threats and/or non-specific threats which could affect MetLife"],
        ["ORANGE", "There are known threats which are specifically targeting MetLife"],
        ["RED", "There is an ongoing attack confirmed to be targeting MetLife"]
    ]

    # Create table
    definitions_table = plt.table(
        cellText=threat_details[1:],
        colLabels=threat_details[0],
        loc='bottom',
        bbox=[0.05, -0.35, 0.9, 0.3],
        colWidths=[0.15, 0.85]
    )

    # Style the table
    definitions_table.auto_set_font_size(False)
    definitions_table.set_fontsize(10)

    # Style header cells
    for col in range(2):
        definitions_table.get_celld()[(0, col)].set_facecolor('#3366CC')
        definitions_table.get_celld()[(0, col)].set_text_props(color='white', ha='center')

    # Style level cells with appropriate colors
    level_colors = ['green', 'yellow', 'orange', 'red']
    for i, color in enumerate(level_colors, 1):
        # Style level cell
        definitions_table.get_celld()[(i, 0)].set_facecolor(COLORS[color]['arc'])
        definitions_table.get_celld()[(i, 0)].set_text_props(ha='left')

        # Style description cell
        definitions_table.get_celld()[(i, 1)].set_facecolor(COLORS[color]['table_bg'])
        definitions_table.get_celld()[(i, 1)].set_text_props(ha='left')
        definitions_table.get_celld()[(i, 1)].PAD = 0.02

    # Adjust the table scale
    definitions_table.scale(1, 1.5)

    return definitions_table


def add_fancy_title(ax):
    """
    Add an enhanced title with modern styling and GS-DnR branding.
    """
    current_date = datetime.today().strftime("%m/%d/%Y")
    title_text = f'Threatcon Level - {current_date}'

    # Main title with enhanced styling - moved down from top edge
    ax.text(0, 1.25, title_text,
            ha='center', va='center',
            fontsize=18, fontweight='bold',
            color='#1A237E',
            bbox=dict(
                boxstyle="round,pad=0.2",
                facecolor='white',
                edgecolor='#1A237E',
                linewidth=2,
                alpha=0.95
            ),
            zorder=10)

    # Add GS-DnR watermark in top right
    ax.text(1.1, 1.25, 'GS-DnR',
            ha='right', va='center',
            fontsize=10, style='italic', fontweight='bold',
            color='#6B7280', alpha=0.8,
            zorder=10)


def gauge(threatcon_details):
    """
    Creates a gauge chart representing the threat level.

    Args:
        threatcon_details (dict): Dictionary with:
            - 'level' (str): The threat level ('red', 'orange', 'yellow', 'green')
            - 'reason' (str): The reason for the current threat level

    Returns:
        matplotlib.figure.Figure: The generated gauge chart figure.
    """
    # Create figure and axis
    fig, ax = plt.subplots(figsize=(8, 6))

    # Create the gauge arcs
    create_gauge_arcs(ax)

    # Add the needle based on threat level
    add_gauge_needle(ax, threatcon_details['level'])

    add_fancy_title(ax)

    # Add reason text if needed
    add_reason_text(fig, threatcon_details)

    # Create definitions table
    create_definitions_table(plt)

    # Configure plot
    ax.set_aspect('equal')
    ax.set_ylim(bottom=0)
    ax.set_xlim(-1.1, 1.1)
    ax.axis('off')
    plt.tight_layout()

    return fig


def make_chart():
    """
    Generates the threat level gauge chart with the text table and saves it as an image.

    Raises:
        FileNotFoundError: If the threatcon file doesn't exist.
        ValueError: If there's an issue with the threatcon data.
    """
    try:

        # Load the threatcon data
        threatcon_details = load_threatcon_data(THREAT_CON_FILE)

        # Generate the gauge chart
        fig = gauge(threatcon_details)

        # Add rounded blue border around the figure to match Vectra styling
        from matplotlib.patches import FancyBboxPatch
        # Create rounded corners for the figure border
        rounded_border = FancyBboxPatch((0, 0), 1, 1,
                                        boxstyle="round,pad=0.02",
                                        transform=fig.transFigure,
                                        facecolor='none',
                                        edgecolor='#1A237E',
                                        linewidth=2,
                                        zorder=1000)
        fig.patches.append(rounded_border)

        # Save the figure
        today_date = datetime.now().strftime('%m-%d-%Y')
        OUTPUT_PATH = ROOT_DIRECTORY / "web" / "static" / "charts" / today_date / "Threatcon Level.png"
        OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(OUTPUT_PATH, format='png', bbox_inches='tight', pad_inches=0, dpi=300)
        plt.close()

    except (FileNotFoundError, ValueError, json.JSONDecodeError) as e:
        print(f"Error generating threatcon chart: {e}")


if __name__ == '__main__':
    make_chart()
