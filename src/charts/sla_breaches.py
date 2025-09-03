from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
import sys

import matplotlib.transforms as transforms
import numpy as np
from matplotlib import pyplot as plt
from pytz import timezone

# Add the project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from my_config import get_config
from services.xsoar import TicketHandler

eastern = timezone('US/Eastern')
config = get_config()

root_directory = Path(__file__).parent.parent.parent


@dataclass
class SlaBreachCounts:
    total_ticket_count: int = 0
    response_sla_breach_count: int = 0
    containment_sla_breach_count: int = 0


def get_tickets_by_periods(tickets):
    current_date = datetime.now()

    # Calculate reference dates
    yesterday = (current_date - timedelta(days=1)).date()
    seven_days_ago = (current_date - timedelta(days=7)).date()
    thirty_days_ago = (current_date - timedelta(days=30)).date()

    # Initialize data structure for sla_breach_counts_by_periods
    sla_breach_counts_by_periods = {
        'Yesterday': SlaBreachCounts(),
        'Past 7 days': SlaBreachCounts(),
        'Past 30 days': SlaBreachCounts()
    }

    # Process each ticket
    for ticket in tickets:
        custom_fields = ticket['CustomFields']
        response_sla_status = custom_fields.get('timetorespond', {}).get('slaStatus', custom_fields.get('responsesla', {}).get('slaStatus'))
        containment_sla_status = custom_fields.get('timetocontain', {}).get('slaStatus', custom_fields.get('containmentsla', {}).get('slaStatus'))

        incident_date = datetime.strptime(
            ticket['created'],
            '%Y-%m-%dT%H:%M:%S.%fZ' if '.' in ticket['created'] else '%Y-%m-%dT%H:%M:%SZ'
        ).date()

        # Update metrics for each time period
        if incident_date == yesterday:
            sla_breach_counts_by_periods['Yesterday'].total_ticket_count += 1

            if response_sla_status == 2:
                sla_breach_counts_by_periods['Yesterday'].response_sla_breach_count += 1
            if containment_sla_status == 2:
                sla_breach_counts_by_periods['Yesterday'].containment_sla_breach_count += 1

        if seven_days_ago <= incident_date <= current_date.date():
            sla_breach_counts_by_periods['Past 7 days'].total_ticket_count += 1

            if response_sla_status == 2:
                sla_breach_counts_by_periods['Past 7 days'].response_sla_breach_count += 1
            if containment_sla_status == 2:
                sla_breach_counts_by_periods['Past 7 days'].containment_sla_breach_count += 1

        if thirty_days_ago <= incident_date <= current_date.date():
            sla_breach_counts_by_periods['Past 30 days'].total_ticket_count += 1

            if response_sla_status == 2:
                sla_breach_counts_by_periods['Past 30 days'].response_sla_breach_count += 1
            if containment_sla_status == 2:
                sla_breach_counts_by_periods['Past 30 days'].containment_sla_breach_count += 1

    return sla_breach_counts_by_periods


def save_sla_breaches_chart(ticket_slas_by_periods):
    # Set up enhanced plot style without grids
    plt.style.use('default')

    # Configure matplotlib fonts
    import matplotlib
    matplotlib.rcParams['font.family'] = ['DejaVu Sans', 'Arial Unicode MS', 'Arial']

    thirty_days_ticket_count = ticket_slas_by_periods['Past 30 days'].total_ticket_count
    seven_days_ticket_count = ticket_slas_by_periods['Past 7 days'].total_ticket_count
    yesterday_ticket_count = ticket_slas_by_periods['Yesterday'].total_ticket_count

    # Prepare data for dual Y-axis grouped bar chart
    response_breaches = [
        ticket_slas_by_periods['Past 30 days'].response_sla_breach_count,
        ticket_slas_by_periods['Past 7 days'].response_sla_breach_count,
        ticket_slas_by_periods['Yesterday'].response_sla_breach_count
    ]

    containment_breaches = [
        ticket_slas_by_periods['Past 30 days'].containment_sla_breach_count,
        ticket_slas_by_periods['Past 7 days'].containment_sla_breach_count,
        ticket_slas_by_periods['Yesterday'].containment_sla_breach_count
    ]

    ticket_counts = [thirty_days_ticket_count, seven_days_ticket_count, yesterday_ticket_count]

    # Enhanced figure with better proportions and styling
    fig, ax1 = plt.subplots(figsize=(12, 8), facecolor='#f8f9fa')
    fig.patch.set_facecolor('#f8f9fa')

    # Create second y-axis
    ax2 = ax1.twinx()

    # Width of each bar and positions
    width = 0.18  # Slightly wider bars
    # Position the groups: Response at x=0, Containment at x=1.0 (closer together)
    x_response = np.array([0])
    x_containment = np.array([1.0])

    # Professional color palette (matching the original)
    colors = {
        '30days': '#4CAF50',  # Green for 30 days
        '7days': '#FF6B40',  # Orange for 7 days
        'yesterday': '#4080FF'  # Blue for yesterday
    }

    # Response SLA bars (left Y-axis)
    bars_resp_30 = ax1.bar(x_response - width, [response_breaches[0]], width,
                           label=f'Past 30 days ({thirty_days_ticket_count})',
                           color=colors['30days'], edgecolor='white', linewidth=1.5, alpha=0.95)
    bars_resp_7 = ax1.bar(x_response, [response_breaches[1]], width,
                          label=f'Past 7 days ({seven_days_ticket_count})',
                          color=colors['7days'], edgecolor='white', linewidth=1.5, alpha=0.95)
    bars_resp_yesterday = ax1.bar(x_response + width, [response_breaches[2]], width,
                                  label=f'Yesterday ({yesterday_ticket_count})',
                                  color=colors['yesterday'], edgecolor='white', linewidth=1.5, alpha=0.95)

    # Containment SLA bars (right Y-axis)
    bars_cont_30 = ax2.bar(x_containment - width, [containment_breaches[0]], width,
                           color=colors['30days'], edgecolor='white', linewidth=1.5, alpha=0.95)
    bars_cont_7 = ax2.bar(x_containment, [containment_breaches[1]], width,
                          color=colors['7days'], edgecolor='white', linewidth=1.5, alpha=0.95)
    bars_cont_yesterday = ax2.bar(x_containment + width, [containment_breaches[2]], width,
                                  color=colors['yesterday'], edgecolor='white', linewidth=1.5, alpha=0.95)

    # Enhanced axes styling
    ax1.set_facecolor('#ffffff')
    ax1.grid(False)
    ax2.grid(False)
    ax1.set_axisbelow(True)

    # Style the spines - make left axis blue, right axis orange
    ax1.spines['left'].set_color('#4080FF')
    ax1.spines['left'].set_linewidth(2)
    ax2.spines['right'].set_color('#FF6B40')
    ax2.spines['right'].set_linewidth(2)

    # Style other spines
    for spine in ['top', 'bottom']:
        ax1.spines[spine].set_color('#CCCCCC')
        ax1.spines[spine].set_linewidth(1.5)

    # Color the y-axis ticks to match the data
    ax1.tick_params(axis='y', colors='#4080FF', labelsize=11, width=2)  # Blue for Response
    ax2.tick_params(axis='y', colors='#FF6B40', labelsize=11, width=2)  # Orange for Containment
    ax1.tick_params(axis='x', colors='#1A237E', labelsize=12)

    # Set Y-axis limits starting from 0 with some padding for better visualization
    max_response = max(response_breaches) if max(response_breaches) > 0 else 1
    max_containment = max(containment_breaches) if max(containment_breaches) > 0 else 1

    ax1.set_ylim(0, max_response * 1.1)  # 10% padding above max value
    ax2.set_ylim(0, max_containment * 1.1)  # 10% padding above max value

    # Enhanced border with rounded corners like MTTR chart
    from matplotlib.patches import FancyBboxPatch
    border_width = 2
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

    # Enhanced timestamp
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')

    plt.text(0.02, 0.02, f"Generated@ {now_eastern}",
             transform=trans, ha='left', va='bottom',
             fontsize=10, color='#1A237E', fontweight='bold',
             bbox=dict(boxstyle="round,pad=0.4", facecolor='white', alpha=0.9, edgecolor='#1A237E', linewidth=1.5))

    # Enhanced titles and labels
    plt.suptitle('SLA Breaches by Response & Containment',
                 fontsize=20, fontweight='bold', color='#1A237E', y=0.95)

    # Y-axis labels with matching colors
    ax1.set_ylabel('Response SLA Breaches', fontsize=14, fontweight='bold', color='#4080FF')
    ax2.set_ylabel('Containment SLA Breaches', fontsize=14, fontweight='bold', color='#FF6B40')

    # X-axis setup
    ax1.set_xticks([0, 1.0])
    ax1.set_xticklabels(['Response', 'Containment'], fontsize=12, fontweight='bold', color='#1A237E')
    ax1.set_xlim(-0.5, 1.5)  # Better spacing around the groups

    # Move legend to top right outside chart area with horizontal gap
    legend = ax1.legend(title='Period (Ticket Count)', loc='upper left',
                        bbox_to_anchor=(1.18, 1),  # increased horizontal offset for gap
                        frameon=True, fancybox=True, shadow=True,
                        title_fontsize=12, fontsize=10)
    legend.get_frame().set_facecolor('white')
    legend.get_frame().set_alpha(0.95)
    legend.get_frame().set_edgecolor('#1A237E')
    legend.get_frame().set_linewidth(2)

    # Enhanced value labels with black circles - separate for each axis
    # Response bars (use ax1 coordinates)
    response_bars = [bars_resp_30, bars_resp_7, bars_resp_yesterday]
    for bars in response_bars:
        for bar in bars:
            height = bar.get_height()
            # Position label in center of bar
            ax1.text(bar.get_x() + bar.get_width() / 2., height / 2 if height > 0 else 0.5,
                     f'{int(height)}',
                     ha='center', va='center',
                     fontsize=12, color='white', fontweight='bold',
                     bbox=dict(boxstyle="circle,pad=0.2", facecolor='black', alpha=0.8, edgecolor='white', linewidth=1))

    # Containment bars (use ax2 coordinates)
    containment_bars = [bars_cont_30, bars_cont_7, bars_cont_yesterday]
    for bars in containment_bars:
        for bar in bars:
            height = bar.get_height()
            # Position label in center of bar using ax2 coordinate system
            ax2.text(bar.get_x() + bar.get_width() / 2., height / 2 if height > 0 else 0.5,
                     f'{int(height)}',
                     ha='center', va='center',
                     fontsize=12, color='white', fontweight='bold',
                     bbox=dict(boxstyle="circle,pad=0.2", facecolor='black', alpha=0.8, edgecolor='white', linewidth=1))

    # Add GS-DnR watermark
    fig.text(0.99, 0.01, 'GS-DnR',
             ha='right', va='bottom', fontsize=10,
             alpha=0.7, color='#3F51B5', style='italic', fontweight='bold')

    # Add explanatory note below legend like MTTR chart
    plt.text(1.18, 0.78, 'Ticket counts for that period (*)',
             transform=ax1.transAxes, ha='left', va='top',
             fontsize=9, color='#666666', style='italic')

    # Enhanced layout with space for external legend and note
    plt.tight_layout()
    plt.subplots_adjust(top=0.88, bottom=0.15, left=0.08, right=0.68)

    today_date = datetime.now().strftime('%m-%d-%Y')
    output_path = root_directory / "web" / "static" / "charts" / today_date / "SLA Breaches.png"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close(fig)


def make_chart():
    query = f'type:{config.team_name} -owner:""'
    period = {
        "byTo": "months",
        "toValue": None,
        "byFrom": "months",
        "fromValue": 1
    }

    incident_fetcher = TicketHandler()
    tickets = incident_fetcher.get_tickets(query=query, period=period)
    tickets_by_periods = get_tickets_by_periods(tickets)
    save_sla_breaches_chart(tickets_by_periods)


if __name__ == '__main__':
    make_chart()
