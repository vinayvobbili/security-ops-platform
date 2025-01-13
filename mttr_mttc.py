from dataclasses import dataclass
from datetime import datetime, timedelta

import matplotlib.transforms as transforms
import numpy as np
from matplotlib import pyplot as plt
from pytz import timezone
from webexteamssdk import WebexTeamsAPI

from config import get_config
from incident_fetcher import IncidentFetcher

config = get_config()
eastern = timezone('US/Eastern')  # Define the Eastern time zone
webex_api = WebexTeamsAPI(access_token=config.webex_bot_access_token_moneyball)


@dataclass
class TicketSlaTimes:
    time_to_contain_secs: int = 0
    time_to_respond_secs: int = 0
    total_ticket_count: int = 0


def get_tickets_by_periods(tickets):
    current_date = datetime.now()

    # Calculate reference dates
    yesterday = (current_date - timedelta(days=1)).date()
    seven_days_ago = (current_date - timedelta(days=7)).date()
    thirty_days_ago = (current_date - timedelta(days=30)).date()

    # Initialize data structure for ticket_slas_by_periods
    ticket_slas_by_periods = {
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

        containment_duration = custom_fields['containmentsla']['totalDuration']
        response_duration = custom_fields['responsesla']['totalDuration']

        # Update metrics for each time period
        if incident_date == yesterday:
            ticket_slas_by_periods['Yesterday'].time_to_contain_secs += containment_duration
            ticket_slas_by_periods['Yesterday'].time_to_respond_secs += response_duration
            ticket_slas_by_periods['Yesterday'].total_ticket_count += 1

        if seven_days_ago <= incident_date <= current_date.date():
            ticket_slas_by_periods['Past 7 days'].time_to_contain_secs += containment_duration
            ticket_slas_by_periods['Past 7 days'].time_to_respond_secs += response_duration
            ticket_slas_by_periods['Past 7 days'].total_ticket_count += 1

        if thirty_days_ago <= incident_date <= current_date.date():
            ticket_slas_by_periods['Past 30 days'].time_to_contain_secs += containment_duration
            ticket_slas_by_periods['Past 30 days'].time_to_respond_secs += response_duration
            ticket_slas_by_periods['Past 30 days'].total_ticket_count += 1

    return ticket_slas_by_periods


def save_mttr_mttc_chart(ticket_slas_by_periods):
    # Calculate metrics in minutes for each period
    thirty_days_ticket_count = ticket_slas_by_periods['Past 30 days'].total_ticket_count
    seven_days_ticket_count = ticket_slas_by_periods['Past 7 days'].total_ticket_count
    yesterday_ticket_count = ticket_slas_by_periods['Yesterday'].total_ticket_count

    metrics = {
        'MTTR': {
            'Yesterday': (ticket_slas_by_periods['Yesterday'].time_to_respond_secs / 60 / yesterday_ticket_count if yesterday_ticket_count > 0 else 0),
            'Past 7 days': (ticket_slas_by_periods['Past 7 days'].time_to_respond_secs / 60 / seven_days_ticket_count if seven_days_ticket_count > 0 else 0),
            'Past 30 days': (ticket_slas_by_periods['Past 30 days'].time_to_respond_secs / 60 / thirty_days_ticket_count if thirty_days_ticket_count > 0 else 0)
        },
        'MTTC': {
            'Yesterday': (ticket_slas_by_periods['Yesterday'].time_to_contain_secs / 60 / yesterday_ticket_count if yesterday_ticket_count > 0 else 0),
            'Past 7 days': (ticket_slas_by_periods['Past 7 days'].time_to_contain_secs / 60 / seven_days_ticket_count if seven_days_ticket_count > 0 else 0),
            'Past 30 days': (ticket_slas_by_periods['Past 30 days'].time_to_contain_secs / 60 / thirty_days_ticket_count if thirty_days_ticket_count > 0 else 0)
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

    bar1 = plt.bar(x - width, [mttr_30days, mttc_30days], width, label=f'Past 30 days ({thirty_days_ticket_count})', color='#2ca02c')
    bar2 = plt.bar(x, [mttr_7days, mttc_7days], width, label=f'Past 7 days ({seven_days_ticket_count})', color='#ff7f0e')
    bar3 = plt.bar(x + width, [mttr_yesterday, mttc_yesterday], width, label=f'Yesterday ({yesterday_ticket_count})', color='#1f77b4')

    # Get x-axis limits
    xmin, xmax = plt.xlim()
    ymin, ymax = plt.ylim()

    # Calculate midpoint for half-width lines
    midpoint = xmin + (xmax - xmin) / 2

    # Draw the hlines from the midpoint to the right edge
    plt.hlines(y=3, xmin=xmin, xmax=midpoint, color='r', linestyle='-', label='Response SLA')
    plt.hlines(y=15, xmin=midpoint, xmax=xmax, color='g', linestyle='-', label='Containment SLA')

    # Get figure and axes objects
    fig = plt.gcf()
    ax = plt.gca()
    # Transform coordinates to figure coordinates (bottom-left is 0,0)
    trans = transforms.blended_transform_factory(fig.transFigure, ax.transAxes)  # gets transform object
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    plt.text(0.1, -0.15, now_eastern, transform=trans, ha='left', va='bottom', fontsize=10)
    plt.text(0.45, -0.15, '(*) Ticket counts that period', transform=trans, ha='left', va='bottom', fontsize=10)  # uses transform object instead of xmin, ymin

    # Customize the plot
    plt.ylabel('Minutes', fontdict={'fontsize': 12, 'fontweight': 'bold'})
    plt.title(f'MTTR & MTTC by Period', fontdict={'fontsize': 12, 'fontweight': 'bold'})
    plt.xticks(x, ['MTTR', 'MTTC'], fontdict={'fontsize': 12, 'fontweight': 'bold'})
    plt.legend(loc='upper left')

    # Add value labels on top of each bar using the bar container objects
    for bars in [bar1, bar2, bar3]:
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width() / 2., height / 2,
                     f'{height:.1f}',
                     ha='center', va='bottom', fontdict={'fontsize': 14, 'fontweight': 'bold'})

    # Add grid for better readability
    plt.grid(True, axis='y', linestyle='--', alpha=0.7)

    # Adjust layout to prevent label clipping
    plt.tight_layout()

    plt.savefig('charts/MTTR MTTC.png')


def make_chart():
    query = f'-category:job type:{config.ticket_type_prefix} -owner:""'
    period = {
        "byTo": "months",
        "toValue": None,
        "byFrom": "months",
        "fromValue": 1
    }

    incident_fetcher = IncidentFetcher()
    tickets = incident_fetcher.get_tickets(query=query, period=period)
    tickets_by_periods = get_tickets_by_periods(tickets)
    save_mttr_mttc_chart(tickets_by_periods)
