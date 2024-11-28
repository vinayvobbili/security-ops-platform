import tempfile
from datetime import datetime, timedelta

import pytz
from matplotlib import pyplot as plt
from webex_bot.models.command import Command
from webexteamssdk import WebexTeamsAPI

from config import get_config
from incident_fetcher import IncidentFetcher

config = get_config()
webex_api = WebexTeamsAPI(access_token=config.bot_access_token)

QUERY_TEMPLATE = '-category:job type:{ticket_type_prefix} -owner:"" closed:>={start} closed:<{end}'


def create_nested_donut(tickets):
    eastern = pytz.timezone('US/Eastern')

    # Process data for outer ring (ticket types)
    type_counts = {}
    impact_by_type = {}

    for ticket in tickets:
        ticket_type = ticket['type'].replace(config.ticket_type_prefix, '', 1)
        impact = ticket['CustomFields'].get('impact', 'Unknown')

        # Count types for outer ring
        type_counts[ticket_type] = type_counts.get(ticket_type, 0) + 1

        # Count impacts within each type for inner ring
        if ticket_type not in impact_by_type:
            impact_by_type[ticket_type] = {}
        impact_by_type[ticket_type][impact] = impact_by_type[ticket_type].get(impact, 0) + 1

    # Prepare data for plotting
    types = list(type_counts.keys())
    type_values = list(type_counts.values())

    # Color scheme
    base_colors = [
        '#1A237E',  # Navy Blue
        '#E65100',  # Dark Orange
        '#1B5E20',  # Dark Green
        '#B71C1C',  # Dark Red
        '#4A148C',  # Dark Purple
        '#3E2723',  # Dark Brown
        '#006064',  # Dark Cyan
        '#827717',  # Olive Green
        '#004D40',  # Dark Teal
        '#0D47A1',  # Dark Blue
        '#33691E',  # Deep Green
        '#FF6F00',  # Dark Amber
        '#311B92'  # Dark Deep Purple
    ]

    # Create figure and axis
    fig, ax = plt.subplots(figsize=(10, 4))

    # Plot outer ring - with larger radius and width
    ax.pie(type_values, radius=1, labels=types, labeldistance=1,
           colors=base_colors[:len(types)],
           wedgeprops=dict(width=0.35, edgecolor='white'),
           textprops={'fontsize': 8, 'wrap': True})

    # Prepare inner ring data
    inner_data = []
    inner_colors = []
    inner_labels = []

    for type_idx, ticket_type in enumerate(types):
        base_color = base_colors[type_idx]
        impacts = impact_by_type[ticket_type]

        # Number of impacts within this type
        num_impacts = len(impacts)
        # Generate progressively lighter colors for each impact
        color_variations = [adjust_color_brightness(base_color, (i + 1) / (num_impacts + 1))
                            for i in range(num_impacts)]

        for idx, (impact, count) in enumerate(impacts.items()):
            inner_data.append(count)
            inner_colors.append(color_variations[idx])  # Use progressively lighter colors
            inner_labels.append(f'{impact}: {count}')

    # Plot inner ring - with smaller radius and width
    ax.pie(inner_data, radius=0.65, labels=inner_labels, labeldistance=0.7,
           colors=inner_colors,
           wedgeprops=dict(width=0.25, edgecolor='white'),
           textprops={'fontsize': 8})

    plt.title(f'Outflow Yesterday: {len(tickets)}', pad=1, fontsize=12, fontweight='bold')

    # Add timestamp at bottom right
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p EST')
    plt.figtext(0.7, 0.01, now_eastern, fontsize=6, ha='right')

    # Adjust layout
    plt.subplots_adjust(left=0.1, right=0.9, top=0.9, bottom=0.1)

    # Save to temporary file
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmpfile:
        filepath = tmpfile.name
        plt.savefig(filepath, format="png", bbox_inches='tight', dpi=600)
        plt.close(fig)

    return filepath


def adjust_color_brightness(hex_color, factor):
    """Adjust the brightness of a hex color progressively."""
    hex_color = hex_color.lstrip('#')
    rgb = tuple(int(hex_color[i:i + 2], 16) for i in (0, 2, 4))
    # Apply brightness adjustment based on the factor
    new_rgb = tuple(
        int(min(255, c + (255 - c) * factor)) if factor > 0 else max(0, c + c * factor)
        for c in rgb
    )
    return '#{:02x}{:02x}{:02x}'.format(*new_rgb)


def plot_outflow() -> str:
    # Calculate fresh values EACH TIME the command is run
    et = pytz.timezone("US/Eastern")
    yesterday_start = datetime.now(et).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
    yesterday_end = yesterday_start + timedelta(days=1)
    yesterday_start_utc = yesterday_start.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    yesterday_end_utc = yesterday_end.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    query = QUERY_TEMPLATE.format(ticket_type_prefix=config.ticket_type_prefix, start=yesterday_start_utc, end=yesterday_end_utc)
    tickets = IncidentFetcher().get_tickets(query=query)
    filepath = create_nested_donut(tickets)

    return filepath


class Outflow(Command):

    def __init__(self):
        super().__init__(command_keyword="outflow", help_message="Outflow")

    def execute(self, message, attachment_actions, activity):
        outflow_chart_filepath = plot_outflow()

        webex_api.messages.create(
            roomId=attachment_actions.json_data["roomId"],
            text=f"{activity['actor']['displayName']}, here's the Outflow chart!",
            files=[outflow_chart_filepath]  # Path to the file
        )
