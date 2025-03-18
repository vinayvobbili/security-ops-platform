from datetime import datetime

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyArrow


def gauge(color):
    """
    Creates a gauge chart representing the threat level.

    Args:
        color (str): The color representing the threat level ('red', 'orange', 'yellow', 'green').

    Returns:
        matplotlib.figure.Figure: The generated gauge chart figure.
    """
    # Create figure and axis
    rad_angle = 0
    fig, ax = plt.subplots(figsize=(8, 6))  # Increased figure height to accommodate table

    # Set the gauge range
    angles = np.linspace(0, 180)

    # Create color ranges
    red = angles <= 45
    orange = (angles > 45) & (angles <= 90)
    yellow = (angles > 90) & (angles <= 135)
    green = angles > 135

    # Plot the colored arcs
    radius = 1
    # Plot the colored arcs with darker colors
    ax.plot(radius * np.cos(np.radians(angles[red])),
            radius * np.sin(np.radians(angles[red])),
            color='#8B0000', linewidth=20)  # Dark red
    ax.plot(radius * np.cos(np.radians(angles[orange])),
            radius * np.sin(np.radians(angles[orange])),
            color='#FF8C00', linewidth=20)  # Dark orange
    ax.plot(radius * np.cos(np.radians(angles[yellow])),
            radius * np.sin(np.radians(angles[yellow])),
            color='#FFD700', linewidth=20)  # Dark yellow
    ax.plot(radius * np.cos(np.radians(angles[green])),
            radius * np.sin(np.radians(angles[green])),
            color='#006400', linewidth=20)  # Dark green

    # Add the arrow (needle)
    if color == 'red':
        rad_angle = np.radians(22.5)
    elif color == 'orange':
        rad_angle = np.radians(67.5)
    elif color == 'yellow':
        rad_angle = np.radians(112.5)
    elif color == 'green':
        rad_angle = np.radians(157.5)

    arrow_length = 0.75
    arrow_width = 0.04
    arrow = FancyArrow(0, 0,
                       arrow_length * np.cos(rad_angle),
                       arrow_length * np.sin(rad_angle),
                       width=arrow_width,
                       color='black')
    ax.add_patch(arrow)

    # Add a center dot
    ax.plot(0, 0, 'ko', markersize=10)

    # Add a black line along the top edge of the gauge
    outer_radius = 1.04  # Adjust this value to move the line outward
    ax.plot(outer_radius * np.cos(np.radians(angles)),
            outer_radius * np.sin(np.radians(angles)),
            color='black', linewidth=1)

    '''
    # Add a horizontal black line at the bottom of the gauge
    ax.plot([-outer_radius, outer_radius], [0, 0], color='black', linewidth=1)
    '''

    # Set title with a nice font
    ax.text(0, 1.2, f'Threatcon Level - {datetime.today().strftime("%m/%d/%Y")}',
            ha='center', va='center', fontsize=14, fontweight='bold',
            fontname='Arial')

    # Configure plot
    ax.set_aspect('equal')
    ax.axis('off')
    plt.tight_layout()

    # --- Add Text Table based on the attachment ---
    # Define the threat level details according to the attachment
    threat_details = [
        ["Level", "Description"],
        ["GREEN", "No known significant threats or on-going attacks"],
        ["YELLOW", "There are global threats and/or non-specific threats which could affect Acme"],
        ["ORANGE", "There are known threats which are specifically targeting Acme"],
        ["RED", "There is an ongoing attack confirmed to be targeting Acme"]
    ]

    # Create a table at the bottom of the chart
    table = plt.table(
        cellText=threat_details[1:],  # Skip the header row for cell text
        colLabels=threat_details[0],  # Use the header row for column labels
        cellLoc='left',
        loc='bottom',
        bbox=[0.0, -0.65, 1.0, 0.3],  # Adjust position and size as needed
        colWidths=[0.2, 0.8]  # Set the column widths - 20% for Level, 80% for Description
    )

    # Style the table
    table.auto_set_font_size(False)
    table.set_fontsize(10)

    # Apply colors to the cells
    table.get_celld()[(0, 0)].set_facecolor('#3366CC')  # Header background
    table.get_celld()[(0, 1)].set_facecolor('#3366CC')  # Header background
    table.get_celld()[(0, 0)].set_text_props(color='white')  # Header text color
    table.get_celld()[(0, 1)].set_text_props(color='white')  # Header text color

    # Color the level cells according to the threat level
    table.get_celld()[(1, 0)].set_facecolor('#006400')  # Dark GREEN
    table.get_celld()[(2, 0)].set_facecolor('#FFD700')  # Dark YELLOW
    table.get_celld()[(3, 0)].set_facecolor('#FF8C00')  # Dark ORANGE
    table.get_celld()[(4, 0)].set_facecolor('#8B0000')  # Dark RED

    # Set the description cell backgrounds
    table.get_celld()[(1, 1)].set_facecolor('#B3FFB3')  # Light green
    table.get_celld()[(2, 1)].set_facecolor('#FFFFB3')  # Light yellow
    table.get_celld()[(3, 1)].set_facecolor('#FFCC99')  # Light orange
    table.get_celld()[(4, 1)].set_facecolor('#FFB3B3')  # Light red

    # Adjust the table scale
    table.scale(1, 1.5)

    return fig


def make_chart():
    """
    Generates the threat level gauge chart with the text table and saves it as an image.
    """
    threat_level = "yellow"  # Example threat level

    fig = gauge(threat_level)

    # Add a thin black border around the figure
    fig.patch.set_edgecolor('black')
    fig.patch.set_linewidth(5)

    fig.savefig('web/static/charts/Threatcon Level.png', format='png', bbox_inches='tight', pad_inches=0.2, dpi=300)
    plt.close()


if __name__ == '__main__':
    make_chart()
