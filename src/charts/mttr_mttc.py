from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
import sys

import matplotlib.transforms as transforms
import matplotlib.patches as patches
import numpy as np
from matplotlib import pyplot as plt
from pytz import timezone

# Add the project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from config import get_config
from services.xsoar import TicketHandler

config = get_config()
eastern = timezone('US/Eastern')  # Define the Eastern time zone

root_directory = Path(__file__).parent.parent.parent


@dataclass
class TicketSlaTimes:
    time_to_contain_secs: int = 0
    time_to_respond_secs: int = 0
    total_ticket_count: int = 0
    host_ticket_count: int = 0


def get_tickets_by_periods(tickets):
    current_date = datetime.now()

    # Calculate reference dates
    yesterday = (current_date - timedelta(days=1)).date()
    seven_days_ago = (current_date - timedelta(days=7)).date()
    thirty_days_ago = (current_date - timedelta(days=30)).date()

    # Initialize data structure for ticket_times_by_periods
    ticket_times_by_periods = {
        'Yesterday': TicketSlaTimes(),
        'Past 7 days': TicketSlaTimes(),
        'Past 30 days': TicketSlaTimes()
    }

    # Process each ticket
    for ticket in tickets:
        custom_fields = ticket['CustomFields']

        incident_date = datetime.strptime(
            ticket['created'],
            '%Y-%m-%dT%H:%M:%S.%fZ' if '.' in ticket['created'] else '%Y-%m-%dT%H:%M:%SZ'
        ).date()

        response_duration = custom_fields.get('timetorespond', {}).get('totalDuration', custom_fields.get('responsesla', {}).get('totalDuration', 0))

        # Update metrics for each time period
        if incident_date == yesterday:
            ticket_times_by_periods['Yesterday'].time_to_respond_secs += response_duration
            ticket_times_by_periods['Yesterday'].total_ticket_count += 1

        if seven_days_ago <= incident_date <= current_date.date():
            ticket_times_by_periods['Past 7 days'].time_to_respond_secs += response_duration
            ticket_times_by_periods['Past 7 days'].total_ticket_count += 1

        if thirty_days_ago <= incident_date <= current_date.date():
            ticket_times_by_periods['Past 30 days'].time_to_respond_secs += response_duration
            ticket_times_by_periods['Past 30 days'].total_ticket_count += 1

    host_tickets = [ticket for ticket in tickets if ticket['CustomFields'].get('hostname', '')]
    for ticket in host_tickets:
        custom_fields = ticket['CustomFields']

        incident_date = datetime.strptime(
            ticket['created'],
            '%Y-%m-%dT%H:%M:%S.%fZ' if '.' in ticket['created'] else '%Y-%m-%dT%H:%M:%SZ'
        ).date()

        containment_duration = custom_fields.get('timetocontain', {}).get('totalDuration', custom_fields.get('containmentsla', {}).get('totalDuration', 0))

        # Update metrics for each time period
        if incident_date == yesterday:
            ticket_times_by_periods['Yesterday'].time_to_contain_secs += containment_duration
            ticket_times_by_periods['Yesterday'].host_ticket_count += 1

        if seven_days_ago <= incident_date <= current_date.date():
            ticket_times_by_periods['Past 7 days'].time_to_contain_secs += containment_duration
            ticket_times_by_periods['Past 7 days'].host_ticket_count += 1

        if thirty_days_ago <= incident_date <= current_date.date():
            ticket_times_by_periods['Past 30 days'].time_to_contain_secs += containment_duration
            ticket_times_by_periods['Past 30 days'].host_ticket_count += 1

    return ticket_times_by_periods


def save_mttr_mttc_chart(ticket_slas_by_periods):
    # Set up enhanced plot style
    plt.style.use('seaborn-v0_8-whitegrid')

    # Configure matplotlib fonts
    import matplotlib
    matplotlib.rcParams['font.family'] = ['DejaVu Sans', 'Arial Unicode MS', 'Arial']

    # Calculate metrics in minutes for each period
    thirty_days_total_ticket_count = ticket_slas_by_periods['Past 30 days'].total_ticket_count
    seven_days_total_ticket_count = ticket_slas_by_periods['Past 7 days'].total_ticket_count
    yesterday_total_ticket_count = ticket_slas_by_periods['Yesterday'].total_ticket_count

    thirty_days_host_ticket_count = ticket_slas_by_periods['Past 30 days'].host_ticket_count
    seven_days_host_ticket_count = ticket_slas_by_periods['Past 7 days'].host_ticket_count
    yesterday_host_ticket_count = ticket_slas_by_periods['Yesterday'].host_ticket_count

    metrics = {
        'MTTR': {
            'Yesterday': (ticket_slas_by_periods['Yesterday'].time_to_respond_secs / 60 / yesterday_total_ticket_count if yesterday_total_ticket_count > 0 else 0),
            'Past 7 days': (ticket_slas_by_periods['Past 7 days'].time_to_respond_secs / 60 / seven_days_total_ticket_count if seven_days_total_ticket_count > 0 else 0),
            'Past 30 days': (ticket_slas_by_periods['Past 30 days'].time_to_respond_secs / 60 / thirty_days_total_ticket_count if thirty_days_total_ticket_count > 0 else 0)
        },
        'MTTC': {
            'Yesterday': (ticket_slas_by_periods['Yesterday'].time_to_contain_secs / 60 / yesterday_host_ticket_count if yesterday_host_ticket_count > 0 else 0),
            'Past 7 days': (ticket_slas_by_periods['Past 7 days'].time_to_contain_secs / 60 / seven_days_host_ticket_count if seven_days_host_ticket_count > 0 else 0),
            'Past 30 days': (ticket_slas_by_periods['Past 30 days'].time_to_contain_secs / 60 / thirty_days_host_ticket_count if thirty_days_host_ticket_count > 0 else 0)
        }
    }

    # Enhanced figure with better proportions and styling
    fig, ax = plt.subplots(figsize=(12, 8), facecolor='#f8f9fa')
    fig.patch.set_facecolor('#f8f9fa')

    # Width of each bar and positions - make bars narrower
    width = 0.2  # Narrower bars (was 0.25)
    x = np.arange(2)  # Two groups: MTTR and MTTC

    # Vibrant color palette
    colors = {
        '30days': '#00FF80',  # Bright Green for 30 days
        '7days': '#FF6B40',  # Bright Orange for 7 days
        'yesterday': '#4080FF'  # Bright Blue for yesterday
    }

    # Create bars with enhanced styling
    mttr_yesterday = metrics['MTTR']['Yesterday']
    mttr_7days = metrics['MTTR']['Past 7 days']
    mttr_30days = metrics['MTTR']['Past 30 days']
    mttc_yesterday = metrics['MTTC']['Yesterday']
    mttc_7days = metrics['MTTC']['Past 7 days']
    mttc_30days = metrics['MTTC']['Past 30 days']

    bar1 = ax.bar(x - width, [mttr_30days, mttc_30days], width,
                  label=f'Past 30 days ({thirty_days_total_ticket_count})',
                  color=colors['30days'], edgecolor='white', linewidth=1.5, alpha=0.95)
    bar2 = ax.bar(x, [mttr_7days, mttc_7days], width,
                  label=f'Past 7 days ({seven_days_total_ticket_count})',
                  color=colors['7days'], edgecolor='white', linewidth=1.5, alpha=0.95)
    bar3 = ax.bar(x + width, [mttr_yesterday, mttc_yesterday], width,
                  label=f'Yesterday ({yesterday_total_ticket_count})',
                  color=colors['yesterday'], edgecolor='white', linewidth=1.5, alpha=0.95)

    # Enhanced axes styling
    ax.set_facecolor('#ffffff')
    ax.grid(True, alpha=0.2, linestyle='--', linewidth=0.8)
    ax.set_axisbelow(True)

    # Style the spines
    for spine in ax.spines.values():
        spine.set_color('#CCCCCC')
        spine.set_linewidth(1.5)

    # Get x-axis limits for SLA lines
    xmin, xmax = ax.get_xlim()
    midpoint = xmin + (xmax - xmin) / 2

    # Enhanced SLA lines with better colors
    ax.hlines(y=3, xmin=xmin, xmax=midpoint, color='#FF1744', linestyle='-', linewidth=3, label='Response SLA')
    ax.hlines(y=15, xmin=midpoint, xmax=xmax, color='#00C853', linestyle='-', linewidth=3, label='Containment SLA')

    # Enhanced border
    border_width = 4
    fig.patch.set_edgecolor('#1A237E')
    fig.patch.set_linewidth(border_width)

    # Enhanced timestamp with modern styling
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')

    plt.text(0.02, 0.02, f"Generated@ {now_eastern}",
             transform=trans, ha='left', va='bottom',
             fontsize=10, color='#1A237E', fontweight='bold',
             bbox=dict(boxstyle="round,pad=0.4", facecolor='white', alpha=0.9, edgecolor='#1A237E', linewidth=1.5))

    # Enhanced titles and labels
    plt.suptitle('Mean Time To',
                 fontsize=20, fontweight='bold', color='#1A237E', y=0.95)
    ax.set_ylabel('Minutes', fontsize=14, fontweight='bold', color='#1A237E')
    ax.set_xticks(x)
    ax.set_xticklabels(['Respond', 'Contain'], fontsize=12, fontweight='bold', color='#1A237E')

    # Enhanced legend
    legend = ax.legend(loc='upper left', frameon=True, fancybox=True, shadow=True,
                       title_fontsize=12, fontsize=10)
    legend.get_frame().set_facecolor('white')
    legend.get_frame().set_alpha(0.95)
    legend.get_frame().set_edgecolor('#1A237E')
    legend.get_frame().set_linewidth(2)

    # Enhanced y-axis - dynamically scale based on data
    all_values = [mttr_yesterday, mttr_7days, mttr_30days, mttc_yesterday, mttc_7days, mttc_30days]
    max_value = max([v for v in all_values if v > 0], default=15)  # Use 15 as minimum if no data
    max_y = max(max_value * 1.2, 16)  # Add 20% headroom, minimum of 16

    # Create appropriate tick intervals based on the data range
    if max_y <= 20:
        tick_interval = 1
    elif max_y <= 50:
        tick_interval = 2
    elif max_y <= 100:
        tick_interval = 5
    else:
        tick_interval = 10

    ax.set_yticks(np.arange(0, int(max_y) + tick_interval, tick_interval))
    ax.set_ylim(0, max_y)
    ax.tick_params(axis='y', colors='#1A237E', labelsize=10, width=1.5)

    # Enhanced value labels with black circles
    for bars in [bar1, bar2, bar3]:
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width() / 2., height / 2,
                        f'{height:.1f}',
                        ha='center', va='center',
                        fontsize=12, color='white', fontweight='bold',
                        bbox=dict(boxstyle="circle,pad=0.2", facecolor='black', alpha=0.8, edgecolor='white', linewidth=1))

    # Add GS-DnR watermark
    fig.text(0.99, 0.01, 'GS-DnR',
             ha='right', va='bottom', fontsize=10,
             alpha=0.7, color='#3F51B5', style='italic', fontweight='bold')

    # Add explanatory note
    plt.text(0.02, 0.08, '(*) Ticket counts for that period',
             transform=trans, ha='left', va='bottom',
             fontsize=9, color='#666666', style='italic')

    # Enhanced layout
    plt.tight_layout()
    plt.subplots_adjust(top=0.88, bottom=0.15, left=0.08, right=0.95)

    today_date = datetime.now().strftime('%m-%d-%Y')
    OUTPUT_PATH = root_directory / "web" / "static" / "charts" / today_date / "MTTR MTTC.png"
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(OUTPUT_PATH)
    plt.close(fig)


def make_chart():
    query = f' type:{config.team_name} -owner:""'
    period = {
        "byTo": "months",
        "toValue": None,
        "byFrom": "months",
        "fromValue": 1
    }

    incident_fetcher = TicketHandler()
    tickets = incident_fetcher.get_tickets(query=query, period=period)
    tickets_by_periods = get_tickets_by_periods(tickets)
    save_mttr_mttc_chart(tickets_by_periods)


if __name__ == '__main__':
    make_chart()
