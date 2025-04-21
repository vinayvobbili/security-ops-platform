from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib.transforms as transforms
import numpy as np
from matplotlib import pyplot as plt
from pytz import timezone

from config import get_config
from services.xsoar import IncidentHandler

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
    thirty_days_ticket_count = ticket_slas_by_periods['Past 30 days'].total_ticket_count
    seven_days_ticket_count = ticket_slas_by_periods['Past 7 days'].total_ticket_count
    yesterday_ticket_count = ticket_slas_by_periods['Yesterday'].total_ticket_count

    metrics = {
        'Response SLA Breaches': {
            'Yesterday': ticket_slas_by_periods['Yesterday'].response_sla_breach_count,
            'Past 7 days': ticket_slas_by_periods['Past 7 days'].response_sla_breach_count,
            'Past 30 days': ticket_slas_by_periods['Past 30 days'].response_sla_breach_count
        },
        'Containment SLA Breaches': {
            'Yesterday': ticket_slas_by_periods['Yesterday'].containment_sla_breach_count,
            'Past 7 days': ticket_slas_by_periods['Past 7 days'].containment_sla_breach_count,
            'Past 30 days': ticket_slas_by_periods['Past 30 days'].containment_sla_breach_count
        }
    }

    # Width of each bar and positions of the bars
    width = 0.25
    x = np.arange(2)  # Two groups: 'Response SLA Breaches' and 'Containment SLA Breaches'

    # Create bars and store their container objects
    response_breaches_yesterday = metrics['Response SLA Breaches']['Yesterday']
    response_breaches_7days = metrics['Response SLA Breaches']['Past 7 days']
    response_breaches_30days = metrics['Response SLA Breaches']['Past 30 days']
    containment_breaches_yesterday = metrics['Containment SLA Breaches']['Yesterday']
    containment_breaches_7days = metrics['Containment SLA Breaches']['Past 7 days']
    containment_breaches_30days = metrics['Containment SLA Breaches']['Past 30 days']

    # Adjust figure size here
    fig, ax = plt.subplots(figsize=(8, 6))

    bar1 = ax.bar(x - width, [response_breaches_30days, containment_breaches_30days], width, label=f'Past 30 days ({thirty_days_ticket_count})', color='#2ca02c')
    bar2 = ax.bar(x, [response_breaches_7days, containment_breaches_7days], width, label=f'Past 7 days ({seven_days_ticket_count})', color='#ff7f0e')
    bar3 = ax.bar(x + width, [response_breaches_yesterday, containment_breaches_yesterday], width, label=f'Yesterday ({yesterday_ticket_count})', color='#1f77b4')

    # Add a thin black border around the figure
    fig.patch.set_edgecolor('black')
    fig.patch.set_linewidth(5)

    # Transform coordinates to figure coordinates (bottom-left is 0,0)
    trans = transforms.blended_transform_factory(fig.transFigure, ax.transAxes)  # gets transform object
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    plt.text(0.1, -0.15, now_eastern, transform=trans, ha='left', va='bottom', fontsize=10)

    # Customize the plot
    ax.set_ylabel('Counts', fontdict={'fontsize': 12, 'fontweight': 'bold'})
    ax.set_title('SLA Breaches', fontdict={'fontsize': 12, 'fontweight': 'bold'})
    ax.set_xticks(x)
    ax.set_xticklabels(['Response', 'Containment'], fontdict={'fontsize': 12, 'fontweight': 'bold'})
    ax.legend(title='Period (Ticket Count)', loc='upper right')

    # Add value labels on top of each bar using the bar container objects
    for bars in [bar1, bar2, bar3]:
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2., height / 2,
                    f'{height}',
                    ha='center', va='bottom', fontdict={'fontsize': 14, 'fontweight': 'bold'})

    # Adjust layout to prevent label clipping
    plt.tight_layout()

    today_date = datetime.now().strftime('%m-%d-%Y')
    OUTPUT_PATH = root_directory / "web" / "static" / "charts" / today_date / "SLA Breaches.png"
    plt.savefig(OUTPUT_PATH)
    plt.close(fig)


def make_chart():
    query = f'type:{config.ticket_type_prefix} -owner:""'
    period = {
        "byTo": "months",
        "toValue": None,
        "byFrom": "months",
        "fromValue": 1
    }

    incident_fetcher = IncidentHandler()
    tickets = incident_fetcher.get_tickets(query=query, period=period)
    tickets_by_periods = get_tickets_by_periods(tickets)
    save_sla_breaches_chart(tickets_by_periods)


if __name__ == '__main__':
    make_chart()
