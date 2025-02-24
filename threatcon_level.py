from datetime import datetime

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyArrow


def gauge(color):
    # Create figure and axis
    rad_angle = 0
    fig, ax = plt.subplots(figsize=(8, 4))

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

    # Add a black line along the top edge of the gauge, moved outward a bit
    outer_radius = 1.05  # Adjust this value to move the line outward
    ax.plot(outer_radius * np.cos(np.radians(angles)),
            outer_radius * np.sin(np.radians(angles)),
            color='black', linewidth=1)

    # Set title with a nice font and underline
    ax.text(0, 1.2, f'Threatcon Level - {datetime.today().strftime("%m/%d/%Y")}',
            ha='center', va='center', fontsize=14, fontweight='normal',
            fontname='Comic Sans MS')

    # Configure plot
    ax.set_aspect('equal')
    ax.axis('off')
    plt.tight_layout()

    return fig


def make_chart():
    # Create gauge with value 60
    fig = gauge('orange')

    # Add a thin black border around the figure
    fig.patch.set_edgecolor('black')
    fig.patch.set_linewidth(10)

    fig.savefig('web/static/charts/Threatcon Level.png', format='png', bbox_inches='tight', pad_inches=0.2)
    plt.close()


if __name__ == '__main__':
    make_chart()
