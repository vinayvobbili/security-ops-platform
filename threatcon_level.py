import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Arrow


def gauge(color):
    # Create figure and axis
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
    ax.plot(radius * np.cos(np.radians(angles[red])),
            radius * np.sin(np.radians(angles[red])),
            color='red', linewidth=20)
    ax.plot(radius * np.cos(np.radians(angles[orange])),
            radius * np.sin(np.radians(angles[orange])),
            color='orange', linewidth=20)
    ax.plot(radius * np.cos(np.radians(angles[yellow])),
            radius * np.sin(np.radians(angles[yellow])),
            color='yellow', linewidth=20)
    ax.plot(radius * np.cos(np.radians(angles[green])),
            radius * np.sin(np.radians(angles[green])),
            color='green', linewidth=20)

    # Add the arrow (needle)
    if color == 'red':
        rad_angle = np.radians(22.5)
    elif color == 'orange':
        rad_angle = np.radians(67.5)
    elif color == 'yellow':
        rad_angle = np.radians(112.5)
    elif color == 'green':
        rad_angle = np.radians(157.5)

    arrow_length = 0.9
    arrow_width = 0.1
    arrow = Arrow(0, 0,
                  arrow_length * np.cos(rad_angle),
                  arrow_length * np.sin(rad_angle),
                  width=arrow_width,
                  color='black')
    ax.add_patch(arrow)

    # Add a center dot
    ax.plot(0, 0, 'ko', markersize=10)

    # Set title
    ax.text(0, 1.4, 'Threatcon Level', ha='center', va='center', fontsize=12)

    # Configure plot
    ax.set_aspect('equal')
    ax.axis('off')
    plt.tight_layout()

    return fig


# Create gauge with value 60
gauge('yellow')
plt.savefig('charts/Threatcon Level.png')
plt.close()

