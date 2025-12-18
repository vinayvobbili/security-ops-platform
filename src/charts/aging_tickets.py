"""Generate aging tickets visualization and reports for security operations.

This module creates bar charts showing ticket aging metrics and generates
summary reports for Webex notifications.
"""

import logging
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional

import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pytz
from matplotlib.patches import FancyBboxPatch
from webexpythonsdk import WebexAPI

from src.charts.chart_style import apply_chart_style
from src.utils.webex_messaging import send_message

apply_chart_style()

# Add project root to path for config imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import my_config as config

from my_config import get_config
CONFIG = get_config()

config = config.get_config()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
EASTERN = pytz.timezone('US/Eastern')
ROOT_DIR = Path(__file__).parent.parent.parent
AGING_THRESHOLD_DAYS = 30
THIRD_PARTY_AGING_DAYS = 90

# Phase colors for visualization
PHASE_COLORS = {
    # Incident Response Phases
    '1. Investigation': '#E91E63',
    '2. Containment': '#2196F3',
    '3. Investigation': '#9C27B0',
    '4. Eradication': '#FF5722',
    '5. Eradication': '#795548',
    '6. Recovery': '#4CAF50',
    '7. Lessons Learned': '#FFC107',
    '8. Closure': '#F44336',
    # Generic phases
    'Investigation': '#9C27B0',
    'Containment': '#2196F3',
    'Eradication': '#FF5722',
    'Recovery': '#4CAF50',
    'Lessons Learned': '#FFC107',
    'Closure': '#F44336',
    'Closure Phase': '#F44336',
    # Status phases
    'New': '#FF9800',
    'In Progress': '#3F51B5',
    'Pending': '#FF6F00',
    'Resolved': '#8BC34A',
    'Unknown': '#607D8B',
    'Unassigned': '#9E9E9E',
    # Default
    'Undefined Phase': '#FFEB3B',
}

PHASE_ORDER = [
    '1. Investigation', '2. Containment', '3. Investigation',
    '4. Eradication', '5. Eradication', '6. Recovery',
    '7. Lessons Learned', '8. Closure', 'Closure Phase',
    'Investigation', 'Containment', 'Eradication', 'Recovery',
    'Lessons Learned', 'Closure', 'New', 'In Progress', 'Pending',
    'Resolved', 'Unknown', 'Unassigned', 'Undefined Phase'
]


def prepare_dataframe(tickets: List[Dict[Any, Any]]) -> pd.DataFrame:
    """Convert ticket list to DataFrame with cleaned and formatted data.

    Args:
        tickets: List of ticket dictionaries

    Returns:
        DataFrame with created dates, cleaned types, and filled phases
    """
    if not tickets:
        return pd.DataFrame(columns=['created', 'type', 'phase'])

    df = pd.DataFrame(tickets)
    df['created'] = pd.to_datetime(df['created'], format='ISO8601')
    df['type'] = df['type'].str.replace(config.team_name, '', regex=False, case=False)
    df['phase'] = df['phase'].fillna('Unknown')
    return df


def create_empty_plot() -> plt.Figure:
    """Create a 'no data' visualization when no aging tickets exist.

    Returns:
        Matplotlib figure with no data message
    """
    fig, ax = plt.subplots(figsize=(10, 7), facecolor='#f8f9fa')

    # Gradient background
    gradient = np.linspace(0, 1, 256).reshape(256, -1)
    gradient = np.vstack((gradient, gradient))
    ax.imshow(gradient, extent=(0, 1, 0, 1), aspect='auto', cmap='coolwarm', alpha=0.3)

    ax.text(0.5, 0.5, 'No Aging Tickets Found!',
            horizontalalignment='center', verticalalignment='center',
            transform=ax.transAxes, fontsize=24, fontweight='bold',
            color='#2E8B57',
            bbox=dict(boxstyle="round,pad=0.5", facecolor='white',
                      alpha=0.8, edgecolor='#2E8B57', linewidth=2))
    ax.axis('off')
    return fig


def prepare_grouped_data(df: pd.DataFrame) -> pd.DataFrame:
    """Group tickets by type and phase, sort by count, and order phases.

    Args:
        df: DataFrame with ticket data

    Returns:
        Grouped DataFrame with phases as columns
    """
    # Group and count tickets
    grouped = df.groupby(['type', 'phase']).size().unstack(fill_value=0)

    # Sort by total count
    grouped['total'] = grouped.sum(axis=1)
    grouped = grouped.sort_values(by='total', ascending=False).drop(columns='total')

    # Clean up phase names
    grouped = grouped.rename(columns={'': 'Undefined Phase', '8. Closure': 'Closure Phase'})

    # Order phases logically
    existing_phases = grouped.columns.tolist()
    ordered_phases = [p for p in PHASE_ORDER if p in existing_phases]
    remaining_phases = [p for p in existing_phases if p not in ordered_phases]
    grouped = grouped[ordered_phases + remaining_phases]

    return grouped


def add_bar_styling(ax: plt.Axes) -> None:
    """Add subtle inner glow effect to bar segments.

    Args:
        ax: Matplotlib axes object
    """
    for container in ax.containers:
        for bar in container:
            if bar.get_height() > 0:
                x, y = bar.get_xy()
                width = bar.get_width()
                height = bar.get_height()
                color = bar.get_facecolor()

                # Add inner glow
                inner_rect = mpatches.Rectangle(
                    (x + width * 0.05, y + height * 0.05),
                    width * 0.9, height * 0.9,
                    facecolor=color, alpha=0.3, edgecolor='none'
                )
                ax.add_patch(inner_rect)


def add_value_labels(ax: plt.Axes) -> None:
    """Add count labels to bar segments.

    Args:
        ax: Matplotlib axes object
    """
    for container in ax.containers:
        for bar in container:
            height = bar.get_height()
            if height > 0:
                ax.annotate(
                    f'{int(height)}',
                    xy=(bar.get_x() + bar.get_width() / 2, bar.get_y() + height / 2),
                    xytext=(0, 0),
                    textcoords="offset points",
                    ha='center', va='center',
                    fontsize=13, color='white', fontweight='bold',
                    bbox=dict(boxstyle="circle,pad=0.2", facecolor='black',
                              alpha=0.8, edgecolor='white', linewidth=1)
                )


def style_axes(ax: plt.Axes, max_count: int, labels: List[str]) -> None:
    """Apply styling to axes including ticks, labels, and spines.

    Args:
        ax: Matplotlib axes object
        max_count: Maximum count for y-axis scaling
        labels: X-axis tick labels
    """
    ax.set_facecolor('#ffffff')
    ax.grid(False)
    ax.set_axisbelow(True)

    # Y-axis
    y_ticks = list(range(0, max_count + 2, max(1, max_count // 8)))
    ax.set_yticks(y_ticks)
    ax.set_ylim(0, max_count * 1.2)
    ax.tick_params(axis='y', colors='#1A237E', labelsize=11, width=1.5)

    # X-axis
    truncated_labels = [label[:12] + '...' if len(label) > 15 else label for label in labels]
    ax.set_xticklabels(truncated_labels, rotation=45, ha='right',
                       fontsize=11, color='#1A237E', fontweight='bold')

    # Spines
    for spine in ax.spines.values():
        spine.set_color('#CCCCCC')
        spine.set_linewidth(1.5)


def add_legend_with_counts(grouped_data: pd.DataFrame) -> None:
    """Add legend with phase counts.

    Args:
        grouped_data: DataFrame with grouped ticket data
    """
    phase_totals = grouped_data.sum(axis=0)
    legend = plt.legend(
        title='Phase', bbox_to_anchor=(1, 1), loc='upper left',
        frameon=True, fancybox=True, shadow=True,
        title_fontsize=14, fontsize=12
    )

    # Update labels with counts
    for phase, text in zip(grouped_data.columns, legend.get_texts()):
        count = int(phase_totals[phase])
        text.set_text(f"{phase} ({count})")

    # Style legend
    legend.get_frame().set_facecolor('white')
    legend.get_frame().set_alpha(0.95)
    legend.get_frame().set_edgecolor('#1A237E')
    legend.get_frame().set_linewidth(2)
    legend.get_title().set_fontweight('bold')
    legend.get_title().set_color('#1A237E')


def add_figure_border(fig: plt.Figure) -> None:
    """Add rounded border to figure.

    Args:
        fig: Matplotlib figure object
    """
    fig.patch.set_edgecolor('none')
    fig.patch.set_linewidth(0)

    fig_width, fig_height = fig.get_size_inches()
    corner_radius = 15

    border = FancyBboxPatch(
        (0, 0), width=1.0, height=1.0,
        boxstyle=f"round,pad=0,rounding_size={corner_radius / max(fig_width * fig.dpi, fig_height * fig.dpi)}",
        edgecolor='#1A237E', facecolor='none', linewidth=4,
        transform=fig.transFigure, zorder=1000, clip_on=False
    )
    fig.patches.append(border)


def add_timestamp(fig: plt.Figure) -> None:
    """Add generation timestamp to figure.

    Args:
        fig: Matplotlib figure object
    """
    timestamp = datetime.now(EASTERN).strftime('%m/%d/%Y %I:%M %p %Z')
    plt.text(
        0.02, 0.02, f"Generated@ {timestamp}",
        transform=fig.transFigure, ha='left', va='bottom',
        fontsize=10, color='#1A237E', fontweight='bold',
        bbox=dict(boxstyle="round,pad=0.4", facecolor='white',
                  alpha=0.9, edgecolor='#1A237E', linewidth=1.5)
    )


def create_data_plot(df: pd.DataFrame) -> plt.Figure:
    """Create bar chart visualization of aging tickets.

    Args:
        df: DataFrame with ticket data

    Returns:
        Matplotlib figure with visualization
    """
    grouped_data = prepare_grouped_data(df)

    # Create figure
    fig, ax = plt.subplots(figsize=(14, 10), facecolor='#f8f9fa')
    fig.patch.set_facecolor('#f8f9fa')

    # Get colors for phases
    colors = [PHASE_COLORS.get(phase, '#9E9E9E') for phase in grouped_data.columns]

    # Plot stacked bars
    grouped_data.plot(
        kind='bar', stacked=True, color=colors,
        edgecolor='white', linewidth=1.5,
        ax=ax, width=0.25, alpha=0.95
    )

    # Add styling and annotations
    add_bar_styling(ax)
    add_value_labels(ax)

    # Style axes
    max_count = int(grouped_data.sum(axis=1).max())
    labels = [label.get_text() for label in ax.get_xticklabels()]
    style_axes(ax, max_count, labels)

    # Add titles
    total_tickets = int(grouped_data.sum().sum())
    plt.suptitle('Aging Tickets', fontsize=24, fontweight='bold', color='#1A237E', y=0.98)
    plt.title(f'Tickets created 1+ months ago (Total: {total_tickets})',
              fontsize=16, fontweight='bold', color='#3F51B5', pad=40)

    # Add axis labels
    plt.xlabel('Ticket Type', fontsize=14, fontweight='bold', color='#1A237E')
    plt.ylabel('Count', fontsize=14, fontweight='bold', color='#1A237E')

    # Add legend and watermark
    add_legend_with_counts(grouped_data)
    fig.text(0.99, 0.01, 'GS-DnR', ha='right', va='bottom',
             fontsize=10, alpha=0.7, color='#3F51B5',
             style='italic', fontweight='bold')

    return fig


def generate_plot(tickets: List[Dict[Any, Any]]) -> None:
    """Generate and save aging tickets visualization.

    Args:
        tickets: List of ticket dictionaries
    """
    df = prepare_dataframe(tickets)
    plt.style.use('seaborn-v0_8-whitegrid')

    # Create appropriate plot
    if df.empty:
        fig = create_empty_plot()
    else:
        fig = create_data_plot(df)

    # Add common elements
    add_figure_border(fig)
    add_timestamp(fig)

    # Save plot
    plt.tight_layout()
    plt.subplots_adjust(top=0.85, bottom=0.15, left=0.08, right=0.80)

    today = datetime.now().strftime('%m-%d-%Y')
    output_path = ROOT_DIR / "web" / "static" / "charts" / today / "Aging Tickets.png"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path)
    plt.close(fig)


def generate_daily_summary(tickets: List[Dict[Any, Any]]) -> Optional[str]:
    """Generate Markdown table summary of aging tickets by owner.

    Args:
        tickets: List of ticket dictionaries

    Returns:
        Markdown-formatted table string or None on error
    """
    try:
        if not tickets:
            return pd.DataFrame(columns=['Owner', 'Count', 'Average Age (days)']).to_markdown(index=False)

        df = pd.DataFrame(tickets)
        df['owner'] = df['owner'].astype(str).str.replace(f'@{CONFIG.my_web_domain}', '', regex=False)
        df['created'] = pd.to_datetime(df['created'], errors='coerce')
        df = df.dropna(subset=['created'])

        # Calculate age in days
        now_ts = pd.Timestamp.now(tz=EASTERN)  # noqa
        current_time = now_ts.replace(tzinfo=None)  # type: ignore[union-attr]

        if df['created'].dt.tz is not None:
            df['created'] = df['created'].dt.tz_convert(None)
        else:
            df['created'] = df['created'].dt.tz_localize(None)  # type: ignore[arg-type]

        df['age'] = (current_time - df['created']).apply(lambda x: x.days)  # type: ignore[operator]

        # Create summary table
        table = df.groupby('owner').agg({'id': 'count', 'age': 'mean'}).reset_index()
        table = table.rename(columns={'owner': 'Owner', 'id': 'Count', 'age': 'Average Age (days)'})
        table['Average Age (days)'] = table['Average Age (days)'].round(1)
        table = table.sort_values(by='Average Age (days)', ascending=False)

        return table.to_markdown(index=False)
    except Exception as e:
        logger.error(f"Error generating daily summary: {e}")
        return "Error generating report. Please check the logs."


def get_aging_tickets(days_ago: int, ticket_type: str) -> List[Dict[Any, Any]]:
    """Fetch aging tickets based on criteria.

    Args:
        days_ago: Number of days threshold for aging
        ticket_type: Ticket type filter

    Returns:
        List of ticket dictionaries
    """
    from services.xsoar import TicketHandler, XsoarEnvironment

    now = datetime.now(EASTERN)
    threshold_date = (now - timedelta(days=days_ago)).replace(hour=0, minute=0, second=0, microsecond=0)
    threshold_utc = threshold_date.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    query = f'-status:closed type:{ticket_type} created:<{threshold_utc}'
    prod_ticket_handler = TicketHandler(XsoarEnvironment.PROD)
    return prod_ticket_handler.get_tickets(query=query)


def send_report(room_id: str) -> None:
    """Send aging tickets report to Webex room.

    Args:
        room_id: Webex room identifier
    """
    try:
        webex_api = WebexAPI(access_token=config.webex_bot_access_token_soar)

        # Regular tickets (30+ days)
        tickets = get_aging_tickets(
            AGING_THRESHOLD_DAYS,
            f'{config.team_name} -type:"{config.team_name} Third Party Compromise"'
        )

        send_message(
            webex_api, room_id,
            text="Aging Tickets Summary!",
            markdown=f'Summary (Type={config.team_name}* - TP, Created=1+ months ago)\n ``` \n {generate_daily_summary(tickets)}'
        )

        # Third Party Compromise tickets (90+ days)
        tp_tickets = get_aging_tickets(
            THIRD_PARTY_AGING_DAYS,
            f'"{config.team_name} Third Party Compromise"'
        )

        if tp_tickets:
            send_message(
                webex_api, room_id,
                text="Aging Tickets Summary!",
                markdown=f'Summary (Type=Third Party Compromise, Created=3+ months ago)\n ``` \n {generate_daily_summary(tp_tickets)}'
            )
    except Exception as e:
        logger.error(f"Error sending report: {e}")


def make_chart() -> None:
    """Generate aging tickets chart with all relevant data."""
    try:
        # Get regular tickets (30+ days)
        tickets = get_aging_tickets(
            AGING_THRESHOLD_DAYS,
            f'{config.team_name} -type:"{config.team_name} Third Party Compromise"'
        )

        # Get Third Party Compromise tickets (90+ days)
        tp_tickets = get_aging_tickets(
            THIRD_PARTY_AGING_DAYS,
            f'"{config.team_name} Third Party Compromise"'
        )

        generate_plot(tickets + tp_tickets)
    except Exception as e:
        logger.error(f"Error generating chart: {e}")


def main() -> None:
    """Main entry point for testing."""
    # room_id = config.webex_room_id_test_space
    # send_report(room_id)
    make_chart()


if __name__ == "__main__":
    main()
