from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib.transforms as transforms
import numpy as np
from matplotlib import pyplot as plt
from pytz import timezone

from config import get_config
from services.xsoar import IncidentHandler

config = get_config()
eastern = timezone('US/Eastern')  # Define the Eastern time zone

root_directory = Path(__file__).parent.parent.parent
today_date = datetime.now().strftime('%m-%d-%Y')
OUTPUT_PATH = root_directory / "web" / "static" / "charts" / today_date / "MTTR MTTC.png"


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

        response_duration = custom_fields['responsesla']['totalDuration']

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

        containment_duration = custom_fields['containmentsla']['totalDuration']

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

    # Width of each bar and positions of the bars
    width = 0.25
    x = np.arange(2)  # Two groups: MTTR and MTTC

    # Create bars and store their container objects
    mttr_yesterday = metrics['MTTR']['Yesterday']
    mttr_7days = metrics['MTTR']['Past 7 days']
    mttr_30days = metrics['MTTR']['Past 30 days']
    mttc_yesterday = metrics['MTTC']['Yesterday']
    mttc_7days = metrics['MTTC']['Past 7 days']
    mttc_30days = metrics['MTTC']['Past 30 days']

    # Adjust figure size here
    fig, ax = plt.subplots(figsize=(8, 6))

    bar1 = ax.bar(x - width, [mttr_30days, mttc_30days], width, label=f'Past 30 days ({thirty_days_total_ticket_count})', color='#2ca02c')
    bar2 = ax.bar(x, [mttr_7days, mttc_7days], width, label=f'Past 7 days ({seven_days_total_ticket_count})', color='#ff7f0e')
    bar3 = ax.bar(x + width, [mttr_yesterday, mttc_yesterday], width, label=f'Yesterday ({yesterday_total_ticket_count})', color='#1f77b4')

    # Get x-axis limits
    xmin, xmax = ax.get_xlim()
    ymin, ymax = ax.get_ylim()

    # Calculate midpoint for half-width lines
    midpoint = xmin + (xmax - xmin) / 2

    # Draw the hlines from the midpoint to the edges
    ax.hlines(y=3, xmin=xmin, xmax=midpoint, color='r', linestyle='-', label='Response SLA')
    ax.hlines(y=15, xmin=midpoint, xmax=xmax, color='g', linestyle='-', label='Containment SLA')

    # Add a thin black border around the figure
    fig.patch.set_edgecolor('black')
    fig.patch.set_linewidth(5)

    # Transform coordinates to figure coordinates (bottom-left is 0,0)
    trans = transforms.blended_transform_factory(fig.transFigure, ax.transAxes)  # gets transform object
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    plt.text(0.1, -0.15, now_eastern, transform=trans, ha='left', va='bottom', fontsize=10)
    plt.text(0.7, -0.15, '(*) Ticket counts that period', transform=trans, ha='left', va='bottom', fontsize=10)  # uses transform object instead of xmin, ymin

    # Customize the plot
    ax.set_ylabel('Minutes', fontdict={'fontsize': 12, 'fontweight': 'bold'})
    ax.set_title(f'Mean Time To', fontdict={'fontsize': 12, 'fontweight': 'bold'})
    ax.set_xticks(x)
    ax.set_xticklabels(['Respond', 'Contain'], fontdict={'fontsize': 12, 'fontweight': 'bold'})
    ax.legend(loc='upper left')

    ax.set_yticks(np.arange(0, 16, 1))

    # Add value labels on top of each bar using the bar container objects
    for bars in [bar1, bar2, bar3]:
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2., height / 2,
                    f'{height:.1f}',
                    ha='center', va='bottom', fontdict={'fontsize': 14, 'fontweight': 'bold'})

    # Adjust layout to prevent label clipping
    plt.tight_layout()

    plt.savefig(OUTPUT_PATH)
    plt.close(fig)


def make_chart():
    query = f' type:{config.ticket_type_prefix} -owner:""'
    period = {
        "byTo": "months",
        "toValue": None,
        "byFrom": "months",
        "fromValue": 1
    }

    incident_fetcher = IncidentHandler()
    tickets = incident_fetcher.get_tickets(query=query, period=period)
    tickets_by_periods = get_tickets_by_periods(tickets)
    save_mttr_mttc_chart(tickets_by_periods)


if __name__ == '__main__':
    make_chart()
