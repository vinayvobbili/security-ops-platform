import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib.transforms as transforms
import numpy as np
from matplotlib import pyplot as plt
from pytz import timezone

# Add the project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from my_config import get_config
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
    # Set up enhanced plot style without grids
    plt.style.use('default')

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
    fig, ax1 = plt.subplots(figsize=(12, 8), facecolor='#f8f9fa')
    fig.patch.set_facecolor('#f8f9fa')

    # Create second y-axis for containment
    ax2 = ax1.twinx()

    # Width of each bar and positions - make bars narrower
    width = 0.25
    x = np.array([0])  # Single position since we're plotting separately

    # Vibrant color palette
    colors = {
        '30days': '#4CAF50',  # Muted Green for 30 days (Material Design green)
        '7days': '#FF6B40',  # Bright Orange for 7 days
        'yesterday': '#4080FF'  # Bright Blue for yesterday
    }

    # Extract MTTR values for response (left side)
    mttr_yesterday = metrics['MTTR']['Yesterday']
    mttr_7days = metrics['MTTR']['Past 7 days']
    mttr_30days = metrics['MTTR']['Past 30 days']

    # Extract MTTC values for containment (right side)
    mttc_yesterday = metrics['MTTC']['Yesterday']
    mttc_7days = metrics['MTTC']['Past 7 days']
    mttc_30days = metrics['MTTC']['Past 30 days']

    # Plot MTTR bars on left y-axis (ax1)
    bar1 = ax1.bar(x - width, [mttr_30days], width,
                   label=f'Past 30 days ({thirty_days_total_ticket_count})',
                   color=colors['30days'], edgecolor='white', linewidth=1.5, alpha=0.95)
    bar2 = ax1.bar(x, [mttr_7days], width,
                   label=f'Past 7 days ({seven_days_total_ticket_count})',
                   color=colors['7days'], edgecolor='white', linewidth=1.5, alpha=0.95)
    bar3 = ax1.bar(x + width, [mttr_yesterday], width,
                   label=f'Yesterday ({yesterday_total_ticket_count})',
                   color=colors['yesterday'], edgecolor='white', linewidth=1.5, alpha=0.95)

    # Plot MTTC bars on right y-axis (ax2) - offset to the right
    x_contain = np.array([1.5])  # Separate position for containment
    bar4 = ax2.bar(x_contain - width, [mttc_30days], width,
                   color=colors['30days'], edgecolor='white', linewidth=1.5, alpha=0.95)
    bar5 = ax2.bar(x_contain, [mttc_7days], width,
                   color=colors['7days'], edgecolor='white', linewidth=1.5, alpha=0.95)
    bar6 = ax2.bar(x_contain + width, [mttc_yesterday], width,
                   color=colors['yesterday'], edgecolor='white', linewidth=1.5, alpha=0.95)

    # Enhanced axes styling for both y-axes
    ax1.set_facecolor('#ffffff')
    ax1.grid(False)  # Explicitly disable grid for ax1
    ax1.set_axisbelow(True)

    ax2.grid(False)  # Explicitly disable grid for ax2

    # Style the spines
    for spine in ax1.spines.values():
        spine.set_color('#CCCCCC')
        spine.set_linewidth(1.5)
    for spine in ax2.spines.values():
        spine.set_color('#CCCCCC')
        spine.set_linewidth(1.5)

    # Enhanced SLA lines - each line only in its own section
    # Response SLA line only over the Respond section
    respond_left = -0.4  # Left edge of respond section
    respond_right = 0.4  # Right edge of respond section
    ax1.hlines(y=3, xmin=respond_left, xmax=respond_right, color='#FF1744', linestyle='-', linewidth=3, label='Response SLA (3 min)')

    # Containment SLA line only over the Contain section
    contain_left = 1.1  # Left edge of contain section
    contain_right = 1.9  # Right edge of contain section
    ax2.hlines(y=15, xmin=contain_left, xmax=contain_right, color='#4CAF50', linestyle='-', linewidth=3, label='Containment SLA (15 min)')

    # Enhanced border with rounded corners
    from matplotlib.patches import FancyBboxPatch
    border_width = 4
    fig.patch.set_edgecolor('none')
    fig.patch.set_linewidth(0)

    fancy_box = FancyBboxPatch(
        (0, 0), width=1.0, height=1.0,
        boxstyle="round,pad=0,rounding_size=0.01",
        edgecolor='#1A237E',
        facecolor='none',
        linewidth=border_width,
        transform=fig.transFigure,
        zorder=1000,
        clip_on=False
    )
    fig.patches.append(fancy_box)

    # Enhanced timestamp with modern styling
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')

    plt.text(0.02, 0.02, f"Generated@ {now_eastern}",
             transform=trans, ha='left', va='bottom',
             fontsize=10, color='#1A237E', fontweight='bold',
             bbox=dict(boxstyle="round,pad=0.4", facecolor='white', alpha=0.9, edgecolor='#1A237E', linewidth=1.5))

    # Enhanced titles and labels
    plt.suptitle('Mean Time To Respond & Contain (MTTR MTTC)',
                 fontsize=20, fontweight='bold', color='#1A237E', y=0.95)

    # Set y-axis labels with different colors
    ax1.set_ylabel('Minutes', fontsize=14, fontweight='bold', color='#FF1744')
    ax2.set_ylabel('Minutes', fontsize=14, fontweight='bold', color='#4CAF50')  # Changed to match the muted green

    # Set x-axis
    ax1.set_xticks([0, 1.5])
    ax1.set_xticklabels(['Respond', 'Contain'], fontsize=12, fontweight='bold', color='#1A237E')

    # Dynamic scaling for MTTR (left y-axis)
    mttr_values = [mttr_yesterday, mttr_7days, mttr_30days]
    max_mttr = max([v for v in mttr_values if v > 0], default=5)
    max_y1 = max(max_mttr * 1.3, 6)  # Add 30% headroom, minimum of 6

    if max_y1 <= 10:
        tick_interval1 = 0.5
    elif max_y1 <= 20:
        tick_interval1 = 1
    else:
        tick_interval1 = 2

    ax1.set_yticks(np.arange(0, max_y1 + tick_interval1, tick_interval1))
    ax1.set_ylim(0, max_y1)
    ax1.tick_params(axis='y', colors='#FF1744', labelsize=10, width=1.5)

    # Dynamic scaling for MTTC (right y-axis)
    mttc_values = [mttc_yesterday, mttc_7days, mttc_30days]
    max_mttc = max([v for v in mttc_values if v > 0], default=15)
    max_y2 = max(max_mttc * 1.3, 18)  # Add 30% headroom, minimum of 18

    if max_y2 <= 30:
        tick_interval2 = 2
    elif max_y2 <= 60:
        tick_interval2 = 5
    else:
        tick_interval2 = 10

    ax2.set_yticks(np.arange(0, max_y2 + tick_interval2, tick_interval2))
    ax2.set_ylim(0, max_y2)
    ax2.tick_params(axis='y', colors='#4CAF50', labelsize=10, width=1.5)

    # Enhanced legend combining both axes - positioned outside
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    legend = ax1.legend(lines1 + lines2, labels1 + labels2,
                        loc='upper left', bbox_to_anchor=(1.15, 1),
                        frameon=True, fancybox=True, shadow=True,
                        title_fontsize=12, fontsize=10)
    legend.get_frame().set_facecolor('white')
    legend.get_frame().set_alpha(0.95)
    legend.get_frame().set_edgecolor('#1A237E')
    legend.get_frame().set_linewidth(2)

    # Enhanced value labels with black circles
    for bars in [bar1, bar2, bar3]:
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax1.text(bar.get_x() + bar.get_width() / 2., height / 2,
                         f'{height:.1f}',
                         ha='center', va='center',
                         fontsize=12, color='white', fontweight='bold',
                         bbox=dict(boxstyle="circle,pad=0.2", facecolor='black', alpha=0.8, edgecolor='white', linewidth=1))

    for bars in [bar4, bar5, bar6]:
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax2.text(bar.get_x() + bar.get_width() / 2., height / 2,
                         f'{height:.1f}',
                         ha='center', va='center',
                         fontsize=12, color='white', fontweight='bold',
                         bbox=dict(boxstyle="circle,pad=0.2", facecolor='black', alpha=0.8, edgecolor='white', linewidth=1))

    # Add GS-DnR watermark
    fig.text(0.99, 0.01, 'GS-DnR',
             ha='right', va='bottom', fontsize=10,
             alpha=0.7, color='#3F51B5', style='italic', fontweight='bold')

    # Add explanatory note below legend
    plt.text(1.18, 0.78, 'Ticket counts for that period (*)',
             transform=ax1.transAxes, ha='left', va='top',
             fontsize=9, color='#666666', style='italic')

    # Enhanced layout with space for external legend
    plt.tight_layout()
    plt.subplots_adjust(top=0.88, bottom=0.15, left=0.08, right=0.68)

    today_date = datetime.now().strftime('%m-%d-%Y')
    OUTPUT_PATH = root_directory / "web" / "static" / "charts" / today_date / "MTTR MTTC.png"
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(OUTPUT_PATH, format="png", dpi=300, bbox_inches='tight', pad_inches=0, facecolor='#f8f9fa')
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
