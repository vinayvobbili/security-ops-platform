import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
import numpy as np
import sys

import matplotlib.pyplot as plt
import matplotlib.transforms as transforms
import matplotlib.patches as patches
import pandas as pd
import pytz
from webexpythonsdk import WebexAPI

# Add the project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import config
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

    # Configure matplotlib to suppress emoji warnings or use a different approach
    import matplotlib
    matplotlib.rcParams['font.family'] = ['DejaVu Sans', 'Arial Unicode MS', 'Arial']

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
        # Debug: Print phase data to understand the issue
        print(f"Debug - Unique phases: {df['phase'].unique()}")
        print(f"Debug - Phase counts: {df['phase'].value_counts()}")

        # VIBRANT, GLOSSY color palette with bright, eye-catching colors
        phase_colors = {
            'Investigation': '#FF0080',  # Hot Pink - urgent attention
            'Containment': '#00FFFF',  # Cyan - contained state
            'Eradication': '#0080FF',  # Electric Blue - active work
            'Recovery': '#00FF40',  # Neon Green - recovery mode
            'Lessons Learned': '#FFFF00',  # Bright Yellow - learning
            'Unknown': '#FF40FF',  # Magenta - unknown state
            'New': '#FF4000',  # Red Orange - new items
            'In Progress': '#4080FF',  # Sky Blue - in progress
            'Pending': '#FF8000',  # Orange - pending action
            'Resolved': '#8000FF',  # Purple - resolved
            '8. Closure': '#FF1744',  # Bright Red - closure issues
            'Closure': '#FF1744',  # Bright Red - closure phase
            '': '#FFA500',  # Bright Orange - undefined
            None: '#FFA500',  # Bright Orange - null
            'Unassigned': '#808080'  # Gray - unassigned
        }

        # Group and count tickets by 'type' and 'phase'
        grouped_data = df.groupby(['type', 'phase']).size().unstack(fill_value=0)
        print(f"Debug - Grouped data columns: {grouped_data.columns.tolist()}")
        print(f"Debug - Grouped data:\n{grouped_data}")

        # Sort types by total count in descending order
        grouped_data['total'] = grouped_data.sum(axis=1)
        grouped_data = grouped_data.sort_values(by='total', ascending=False).drop(columns='total')

        # Clean up column names for better legend display
        column_mapping = {
            '': 'Undefined Phase',
            '8. Closure': 'Closure Phase'
        }
        grouped_data = grouped_data.rename(columns=column_mapping)

        # Create figure with even better proportions to completely fix title overlap
        fig, ax = plt.subplots(figsize=(16, 12), facecolor='#f8f9fa')
        fig.patch.set_facecolor('#f8f9fa')

        # Get VIBRANT colors for the phases present in data
        colors_for_plot = []
        for phase in grouped_data.columns:
            if phase == 'Undefined Phase':
                colors_for_plot.append('#FFA500')  # Bright Orange for undefined
            elif phase == 'Closure Phase':
                colors_for_plot.append('#FF1744')  # Bright Red for closure
            else:
                colors_for_plot.append(phase_colors.get(phase, '#808080'))

        print(f"Debug - Colors being used: {colors_for_plot}")
        print(f"Debug - Phases in data: {grouped_data.columns.tolist()}")

        # Enhanced plotting with MUCH NARROWER bars and NO shadows
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

        # Enhance the axes with better spacing
        ax.set_facecolor('#ffffff')
        ax.grid(True, alpha=0.2, linestyle='--', linewidth=0.8)
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
    fig.patch.set_edgecolor('#1A237E')  # Deep blue border
    fig.patch.set_linewidth(border_width)

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

        # Fix title overlap with much better spacing
        plt.suptitle('Aging Tickets',
                     fontsize=24, fontweight='bold', color='#1A237E', y=0.98)  # Even higher
        plt.title('Tickets created 1+ months ago',
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

        # Enhanced legend with glossy styling
        legend = plt.legend(title='Phase', loc='upper right',
                            frameon=True, fancybox=True, shadow=True,
                            title_fontsize=14, fontsize=12)
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
    plt.subplots_adjust(top=0.85, bottom=0.15, left=0.08, right=0.95)  # Much more top space

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
        df['created'] = df['created'].dt.tz_localize(None)
        df['age'] = (now - df['created']).dt.days
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
