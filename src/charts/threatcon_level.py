import json
from datetime import datetime
from pathlib import Path

import matplotlib.patheffects as path_effects
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyArrow

# Define constants
THREAT_CON_FILE = Path("../../data/transient/secOps/threatcon.json")
OUTPUT_PATH = Path("../../web/static/charts/Threatcon Level.png")

# Define color mappings for better maintenance
COLORS = {
    'red': {
        'arc': '#8B0000',  # Dark red
        'font': '#8B0000',
        'table_bg': '#FFB3B3'  # Light red
    },
    'orange': {
        'arc': '#FF8C00',  # Dark orange
        'font': '#FF8C00',
        'table_bg': '#FFCC99'  # Light orange
    },
    'yellow': {
        'arc': '#FFD700',  # Dark yellow
        'font': '#FFD700',
        'table_bg': '#FFFFB3'  # Light yellow
    },
    'green': {
        'arc': '#006400',  # Dark green
        'font': '#006400',
        'table_bg': '#B3FFB3'  # Light green
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
    Create the colored arcs for the gauge.

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

    # Define radius and draw arcs
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

    # Add gauge border
    outer_radius = 1.04
    ax.plot(outer_radius * np.cos(np.radians(angles)),
            outer_radius * np.sin(np.radians(angles)),
            color='black', linewidth=1, zorder=2)

    # Add horizontal baseline
    ax.plot([-outer_radius, outer_radius], [0, 0], color='black', linewidth=1, zorder=2)


def add_gauge_needle(ax, threatcon_color):
    """
    Add the needle to the gauge based on the threat level.

    Args:
        ax (matplotlib.axes.Axes): The axes to draw on.
        threatcon_color (str): The color representing the threat level.
    """
    # Get the angle for the needle
    rad_angle = np.radians(THREAT_ANGLES[threatcon_color])

    # Draw the needle (arrow)
    arrow_length = 0.80
    arrow_width = 0.04
    arrow = FancyArrow(0, 0,
                       arrow_length * np.cos(rad_angle),
                       arrow_length * np.sin(rad_angle),
                       width=arrow_width,
                       color='black', zorder=3)
    ax.add_patch(arrow)

    # Add center dot (pivot point)
    ax.plot(0, 0, 'ko', markersize=20, zorder=2)


def add_reason_text(fig, threatcon_details):
    """
    Add reason text to the figure if the threat level is not green.

    Args:
        fig (matplotlib.figure.Figure): The figure to add text to.
        threatcon_details (dict): The threatcon details including level and reason.
    """
    threatcon_color = threatcon_details['level']

    if threatcon_color != 'green':
        reason_text = f"Reason: \n{threatcon_details['reason']}"
        font_color = COLORS[threatcon_color]['font']

        fig.text(0.2, 0.4, reason_text,
                 ha='left', va='center',
                 fontsize=10,
                 color=font_color,
                 bbox=dict(facecolor='gray',
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
        bbox=[0.05, -0.5, 0.9, 0.3],
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
    Add a fancy title to the gauge chart.
    """
    current_date = datetime.today().strftime("%m/%d/%Y")
    title_text = f'Threatcon Level - {current_date}'

    # Create a fancy title with gradient effect and shadow
    ax.text(0, 1.2, title_text,
            ha='center', va='center',
            fontsize=12, fontweight='bold',
            fontname='Arial Black',  # More impactful font
            color='#003366',  # Navy blue for corporate feel
            bbox=dict(
                boxstyle="round,pad=0.3",
                ec=(0.1, 0.1, 0.1, 0.9),  # Dark edge
                fc=(0.9, 0.9, 0.95, 0.7),  # Light blue background with transparency
                lw=2
            ),
            path_effects=[
                plt.matplotlib.patheffects.withStroke(linewidth=2, foreground='#8a8a8a')  # Add shadow effect
            ]
            )


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
    ax.set_xlim([-1.1, 1.1])
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
        # Ensure output directory exists
        OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

        # Load the threatcon data
        threatcon_details = load_threatcon_data(THREAT_CON_FILE)

        # Generate the gauge chart
        fig = gauge(threatcon_details)

        # Add a thin black border around the figure
        fig.patch.set_edgecolor('black')
        fig.patch.set_linewidth(5)

        # Save the figure
        fig.savefig(OUTPUT_PATH, format='png', bbox_inches='tight', pad_inches=0.2, dpi=300)
        plt.close()

        print(f"Threatcon chart successfully generated at {OUTPUT_PATH}")

    except (FileNotFoundError, ValueError, json.JSONDecodeError) as e:
        print(f"Error generating threatcon chart: {e}")


if __name__ == '__main__':
    make_chart()
