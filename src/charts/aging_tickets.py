import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

import matplotlib.pyplot as plt
import matplotlib.transforms as transforms
import numpy as np
import pandas as pd
import pytz
from matplotlib.patches import FancyBboxPatch
# Add centralized style
from .chart_style import apply_chart_style
apply_chart_style()

# Add the project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Import project modules after path setup - necessary due to custom path setup
import my_config as config
from services.xsoar import TicketHandler

config = config.get_config()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

webex_headers = {
    'Content-Type': 'application/json',
    'Authorization': f"Bearer {config.webex_bot_access_token_moneyball}"
}
eastern = pytz.timezone('US/Eastern')

root_directory = Path(__file__).parent.parent.parent


def get_df(tickets: List[Dict[Any, Any]]) -> pd.DataFrame:
    if not tickets:
        return pd.DataFrame(columns=['created', 'type', 'phase'])

    df = pd.DataFrame(tickets)
    df['created'] = pd.to_datetime(df['created'], format='ISO8601')  # Use ISO8601 format
    # Clean up type names by removing repeating prefix
    df['type'] = df['type'].str.replace(config.team_name, '', regex=False, case=False)
    # Set 'phase' to 'Unknown' if it's missing
    df['phase'] = df['phase'].fillna('Unknown')
    return df


def generate_plot(tickets):
    """Generate a visually enhanced bar plot of open ticket types older than 30 days."""
    df = get_df(tickets)

    # Set up the plot style
    plt.style.use('seaborn-v0_8-whitegrid')

    # Removed per-file font family override to rely on centralized style
    # import matplotlib
    # matplotlib.rcParams['font.family'] = ['DejaVu Sans', 'Arial Unicode MS', 'Arial']

    if df.empty:
        # Create an enhanced "no data" visualization
        fig, ax = plt.subplots(figsize=(10, 7), facecolor='#f8f9fa')

        # Create a gradient background
        gradient = np.linspace(0, 1, 256).reshape(256, -1)
        gradient = np.vstack((gradient, gradient))
        ax.imshow(gradient, extent=(0, 1, 0, 1), aspect='auto', cmap='coolwarm', alpha=0.3)

        ax.text(0.5, 0.5, 'No Aging Tickets Found!',
                horizontalalignment='center', verticalalignment='center',
                transform=ax.transAxes, fontsize=24, fontweight='bold',
                color='#2E8B57',
                bbox=dict(boxstyle="round,pad=0.5", facecolor='white', alpha=0.8, edgecolor='#2E8B57', linewidth=2))
        ax.axis('off')
    else:
        # Distinct, high-contrast color palette with unique colors for each phase
        phase_colors = {
            # Incident Response Phases - Sequential color scheme
            '1. Investigation': '#E91E63',  # Pink - initial phase
            '2. Containment': '#2196F3',  # Blue - containment
            '3. Investigation': '#9C27B0',  # Purple - investigation
            '4. Eradication': '#FF5722',  # Deep Orange - eradication
            '5. Eradication': '#795548',  # Brown - eradication variant
            '6. Recovery': '#4CAF50',  # Green - recovery
            '7. Lessons Learned': '#FFC107',  # Amber - learning
            '8. Closure': '#F44336',  # Red - closure

            # Generic phases
            'Investigation': '#9C27B0',  # Purple - investigation
            'Containment': '#2196F3',  # Blue - containment
            'Eradication': '#FF5722',  # Deep Orange - eradication
            'Recovery': '#4CAF50',  # Green - recovery
            'Lessons Learned': '#FFC107',  # Amber - learning
            'Closure': '#F44336',  # Red - closure
            'Closure Phase': '#F44336',  # Red - closure phase

            # Status phases
            'New': '#FF9800',  # Orange - new items
            'In Progress': '#3F51B5',  # Indigo - in progress
            'Pending': '#FF6F00',  # Dark Orange - pending action
            'Resolved': '#8BC34A',  # Light Green - resolved
            'Unknown': '#607D8B',  # Blue Grey - unknown state
            'Unassigned': '#9E9E9E',  # Grey - unassigned

            # Special cases
            '': '#FFEB3B',  # Yellow - undefined
            None: '#FFEB3B',  # Yellow - null
            'Undefined Phase': '#FFEB3B'  # Yellow - undefined phase
        }

        # Group and count tickets by 'type' and 'phase'
        grouped_data = df.groupby(['type', 'phase']).size().unstack(fill_value=0)

        # Sort types by total count in descending order
        grouped_data['total'] = grouped_data.sum(axis=1)
        grouped_data = grouped_data.sort_values(by='total', ascending=False).drop(columns='total')

        # Clean up column names for better legend display
        column_mapping = {
            '': 'Undefined Phase',
            '8. Closure': 'Closure Phase'
        }
        grouped_data = grouped_data.rename(columns=column_mapping)

        # 4. Sort phases in logical IR workflow order
        phase_order = [
            '1. Investigation', '2. Containment', '3. Investigation',
            '4. Eradication', '5. Eradication', '6. Recovery',
            '7. Lessons Learned', '8. Closure', 'Closure Phase',
            'Investigation', 'Containment', 'Eradication', 'Recovery',
            'Lessons Learned', 'Closure', 'New', 'In Progress', 'Pending',
            'Resolved', 'Unknown', 'Unassigned', 'Undefined Phase'
        ]
        # Reorder columns based on phase order (keep only existing phases)
        existing_phases = grouped_data.columns.tolist()
        ordered_phases = [phase for phase in phase_order if phase in existing_phases]
        # Add any remaining phases not in our order
        remaining_phases = [phase for phase in existing_phases if phase not in ordered_phases]
        final_order = ordered_phases + remaining_phases
        grouped_data = grouped_data[final_order]

        # Create figure with even better proportions to completely fix title overlap
        fig, ax = plt.subplots(figsize=(14, 10), facecolor='#f8f9fa')
        fig.patch.set_facecolor('#f8f9fa')

        # Get distinct colors for the phases present in data with gradients
        colors_for_plot = []
        for phase in grouped_data.columns:
            base_color = phase_colors.get(phase, '#9E9E9E')
            colors_for_plot.append(base_color)

        # Enhanced plotting with MUCH NARROWER bars and gradient backgrounds
        bars = grouped_data.plot(
            kind='bar',
            stacked=True,
            color=colors_for_plot,
            edgecolor='white',
            linewidth=1.5,  # Clean white borders
            ax=ax,
            width=0.25,  # MUCH narrower bars (was 0.4, now 0.25)
            alpha=0.95  # High alpha for vibrant colors
        )

        # 6. Add subtle gradient backgrounds to bars
        import matplotlib.patches as mpatches

        # Apply gradient effect to each bar segment
        for container in ax.containers:
            for bar in container:
                if bar.get_height() > 0:
                    # Create a subtle gradient effect
                    x, y = bar.get_xy()
                    width = bar.get_width()
                    height = bar.get_height()

                    # Get the original color
                    original_color = bar.get_facecolor()

                    # Create a gradient from the original color to a slightly lighter version
                    gradient = mpatches.Rectangle((x, y), width, height,
                                                  facecolor=original_color,
                                                  edgecolor='white',
                                                  linewidth=1.5,
                                                  alpha=0.95)

                    # Add a subtle inner glow effect
                    inner_rect = mpatches.Rectangle((x + width * 0.05, y + height * 0.05),
                                                    width * 0.9, height * 0.9,
                                                    facecolor=original_color,
                                                    alpha=0.3,
                                                    edgecolor='none')
                    ax.add_patch(inner_rect)

        # Enhance the axes with better spacing
        ax.set_facecolor('#ffffff')
        ax.grid(False)  # Remove grid lines
        ax.set_axisbelow(True)

        # Set y-axis with better spacing
        max_count = int(grouped_data.sum(axis=1).max())
        y_ticks = list(range(0, max_count + 2, max(1, max_count // 8)))
        ax.set_yticks(y_ticks)
        ax.set_ylim(0, max_count * 1.2)  # More headroom

        # Style the spines with more contrast
        for spine in ax.spines.values():
            spine.set_color('#CCCCCC')
            spine.set_linewidth(1.5)

        # REMOVED: All shadow effects to eliminate distractions
        # Clean, minimal styling without any shadows

    # Add enhanced border with more prominent styling
    border_width = 4

    # Create a rounded rectangular border that extends to the very edge
    # Remove the standard border to avoid conflicts
    fig.patch.set_edgecolor('none')  # Remove default border
    fig.patch.set_linewidth(0)

    # Calculate the exact position to ensure the border appears correctly at the corners
    fig_width, fig_height = fig.get_size_inches()
    corner_radius = 15  # Adjust this value to control the roundness of corners

    # Add a custom FancyBboxPatch that extends to the full figure bounds
    fancy_box = FancyBboxPatch(
        (0, 0),
        width=1.0, height=1.0,  # Full figure dimensions
        boxstyle=f"round,pad=0,rounding_size={corner_radius / max(fig_width * fig.dpi, fig_height * fig.dpi)}",
        edgecolor='#1A237E',  # Deep blue border
        facecolor='none',
        linewidth=border_width,
        transform=fig.transFigure,
        zorder=1000,  # Ensure it's on top of other elements
        clip_on=False  # Don't clip the border
    )
    fig.patches.append(fancy_box)

    # Enhanced timestamp with better positioning
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')

    # Add background box for timestamp
    plt.text(0.02, 0.02, f"Generated@ {now_eastern}",
             transform=trans, ha='left', va='bottom',
             fontsize=10, color='#1A237E', fontweight='bold',
             bbox=dict(boxstyle="round,pad=0.4", facecolor='white', alpha=0.9, edgecolor='#1A237E', linewidth=1.5))

    if not df.empty:
        # Enhanced annotations with better styling - bringing back the black circles
        for container in ax.containers:
            for bar in container:
                height = bar.get_height()
                if height > 0:
                    # Add count labels with black circular backgrounds for better readability
                    ax.annotate(f'{int(height)}',
                                xy=(bar.get_x() + bar.get_width() / 2, bar.get_y() + height / 2),
                                xytext=(0, 0),
                                textcoords="offset points",
                                ha='center', va='center',
                                fontsize=13, color='white',
                                fontweight='bold',
                                bbox=dict(boxstyle="circle,pad=0.2", facecolor='black', alpha=0.8, edgecolor='white', linewidth=1))

        # 9. Calculate total aging tickets for subtitle
        total_aging_tickets = int(grouped_data.sum().sum())

        # Fix title overlap with much better spacing and move total to subtitle
        plt.suptitle('Aging Tickets',
                     fontsize=24, fontweight='bold', color='#1A237E', y=0.98)  # Even higher
        plt.title(f'Tickets created 1+ months ago (Total: {total_aging_tickets})',
                  fontsize=16, fontweight='bold', color='#3F51B5', pad=40)  # Much more padding

        # Enhanced axis labels with better colors
        plt.xlabel('Ticket Type', fontsize=14, fontweight='bold', color='#1A237E')
        plt.ylabel('Count', fontsize=14, fontweight='bold', color='#1A237E')

        # Better x-axis tick formatting with improved label handling
        labels = [label.get_text() for label in ax.get_xticklabels()]
        truncated_labels = []
        for label in labels:
            if len(label) > 15:  # Truncate long labels
                truncated_labels.append(label[:12] + '...')
            else:
                truncated_labels.append(label)

        ax.set_xticklabels(truncated_labels, rotation=45, ha='right', fontsize=11, color='#1A237E', fontweight='bold')
        ax.tick_params(axis='y', colors='#1A237E', labelsize=11, width=1.5)

        # Enhanced legend with counts for each phase and correct colors
        # Calculate total count for each phase across all ticket types
        phase_totals = grouped_data.sum(axis=0)

        # Get the legend from the plot (which has correct colors) and move it outside
        legend = plt.legend(title='Phase', bbox_to_anchor=(1, 1), loc='upper left',
                            frameon=True, fancybox=True, shadow=True,
                            title_fontsize=14, fontsize=12)

        # Update legend labels with counts while preserving colors
        for i, (phase, text) in enumerate(zip(grouped_data.columns, legend.get_texts())):
            count = int(phase_totals[phase])
            text.set_text(f"{phase} ({count})")
        legend.get_frame().set_facecolor('white')
        legend.get_frame().set_alpha(0.95)
        legend.get_frame().set_edgecolor('#1A237E')
        legend.get_frame().set_linewidth(2)
        legend.get_title().set_fontweight('bold')
        legend.get_title().set_color('#1A237E')

        # Add a more prominent watermark with GS-DnR branding
        fig.text(0.99, 0.01, 'GS-DnR',
                 ha='right', va='bottom', fontsize=10,
                 alpha=0.7, color='#3F51B5', style='italic', fontweight='bold')

    plt.tight_layout()
    plt.subplots_adjust(top=0.85, bottom=0.15, left=0.08, right=0.80)  # More right space for external legend

    today_date = datetime.now().strftime('%m-%d-%Y')
    output_path = root_directory / "web" / "static" / "charts" / today_date / "Aging Tickets.png"
    output_path.parent.mkdir(parents=True, exist_ok=True)  # Ensure the directory exists
    plt.savefig(output_path)
    plt.close(fig)


def generate_daily_summary(tickets) -> str | None:
    try:
        if not tickets:
            return pd.DataFrame(columns=['Owner', 'Count', 'Average Age (days)']).to_markdown(index=False)
        df = pd.DataFrame(tickets)
        df['owner'] = df['owner'].astype(str).str.replace('@company.com', '', regex=False)
        df['created'] = pd.to_datetime(df['created'], errors='coerce')
        # Drop rows where 'created' could not be parsed
        df = df.dropna(subset=['created'])
        # Make both sides timezone-naive for subtraction
        now = pd.Timestamp.now(tz=eastern).tz_localize(None)
        df['created'] = pd.to_datetime(df['created']).dt.tz_localize(None)
        # Calculate age in days - type: ignore to suppress PyCharm warning about Series/timedelta
        df['age'] = (now - df['created']).apply(lambda x: x.days)  # type: ignore[operator]
        table = df.groupby('owner').agg({'id': 'count', 'age': 'mean'}).reset_index()
        table = table.rename(columns={'owner': 'Owner', 'id': 'Count', 'age': 'Average Age (days)'})
        table['Average Age (days)'] = table['Average Age (days)'].round(1)
        table = table.sort_values(by='Average Age (days)', ascending=False)
        return table.to_markdown(index=False)
    except Exception as e:
        logger.error(f"Error generating daily summary: {e}")
        return "Error generating report. Please check the logs."


def send_report(room_id):
    try:
        webex_api = WebexAPI(access_token=config.webex_bot_access_token_soar)

        query = f'-status:closed type:{config.team_name} -type:"{config.team_name} Third Party Compromise"'
        period = {"byTo": "months", "toValue": 1, "byFrom": "months", "fromValue": None}
        tickets = TicketHandler().get_tickets(query=query, period=period)

        webex_api.messages.create(
            roomId=room_id,
            text=f"Aging Tickets Summary!",
            markdown=f'Summary (Type={config.team_name}* - TP, Created=1+ months ago)\n ``` \n {generate_daily_summary(tickets)}'
        )

        query = f'-status:closed type:"{config.team_name} Third Party Compromise"'
        period = {"byTo": "months", "toValue": 3, "byFrom": "months", "fromValue": None}
        tickets = TicketHandler().get_tickets(query=query, period=period)

        if tickets:
            webex_api.messages.create(
                roomId=room_id,
                text=f"Aging Tickets Summary!",
                markdown=f'Summary (Type=Third Party Compromise, Created=3+ months ago)\n ``` \n {generate_daily_summary(tickets)}'
            )
    except Exception as e:
        logger.error(f"Error sending report: {e}")


def make_chart():
    try:
        # METCIRT* tickets minus the Third Party are considered aging after 30 days
        query = f'-status:closed type:{config.team_name} -type:"{config.team_name} Third Party Compromise"'
        period = {"byTo": "months", "toValue": 1, "byFrom": "months", "fromValue": None}

        tickets = TicketHandler().get_tickets(query=query, period=period)

        # Third Party Compromise tickets are considered aging after 90 days
        query = f'-status:closed type:"{config.team_name} Third Party Compromise"'
        period = {"byTo": "months", "toValue": 3, "byFrom": "months", "fromValue": None}
        tickets = tickets + TicketHandler().get_tickets(query=query, period=period)

        generate_plot(tickets)
    except Exception as e:
        logger.error(f"Error generating chart: {e}")


def main():
    room_id = config.webex_room_id_vinay_test_space
    send_report(room_id)
    make_chart()


if __name__ == "__main__":
    main()
