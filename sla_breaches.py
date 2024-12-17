import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta

import matplotlib.transforms as transforms
import numpy as np
from matplotlib import pyplot as plt
from pytz import timezone
from webex_bot.models.command import Command
from webexteamssdk import WebexTeamsAPI

from config import get_config
from incident_fetcher import IncidentFetcher

eastern = timezone('US/Eastern')  # Define the Eastern time zone
config = get_config()
webex_api = WebexTeamsAPI(access_token=config.webex_bot_access_token)


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

    # Initialize data structure for ticket_slas_by_periods
    ticket_slas_by_periods = {
        'Yesterday': SlaBreachCounts(),
        'Past 7 days': SlaBreachCounts(),
        'Past 30 days': SlaBreachCounts()
    }

    # Process each ticket
    for ticket in tickets:
        custom_fields = ticket['CustomFields']
        response_sla_status = custom_fields['responsesla']['slaStatus']
        containment_sla_status = custom_fields['containmentsla']['slaStatus']

        incident_date = datetime.strptime(
            ticket['created'],
            '%Y-%m-%dT%H:%M:%S.%fZ' if '.' in ticket['created'] else '%Y-%m-%dT%H:%M:%SZ'
        ).date()

        # Update metrics for each time period
        if incident_date == yesterday:
            ticket_slas_by_periods['Yesterday'].total_ticket_count += 1

            if response_sla_status == 2:
                ticket_slas_by_periods['Yesterday'].response_sla_breach_count += 1
            if containment_sla_status == 2:
                ticket_slas_by_periods['Yesterday'].containment_sla_breach_count += 1

        if seven_days_ago <= incident_date <= current_date.date():
            ticket_slas_by_periods['Past 7 days'].total_ticket_count += 1

            if response_sla_status == 2:
                ticket_slas_by_periods['Past 7 days'].response_sla_breach_count += 1
            if containment_sla_status == 2:
                ticket_slas_by_periods['Past 7 days'].containment_sla_breach_count += 1

        if thirty_days_ago <= incident_date <= current_date.date():
            ticket_slas_by_periods['Past 30 days'].total_ticket_count += 1

            if response_sla_status == 2:
                ticket_slas_by_periods['Past 30 days'].response_sla_breach_count += 1
            if containment_sla_status == 2:
                ticket_slas_by_periods['Past 30 days'].containment_sla_breach_count += 1

    return ticket_slas_by_periods


def get_sla_breaches_chart(ticket_slas_by_periods):
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

    bar1 = plt.bar(x - width, [response_breaches_30days, containment_breaches_30days], width, label=f'Past 30 days ({thirty_days_ticket_count})', color='#2ca02c')
    bar2 = plt.bar(x, [response_breaches_7days, containment_breaches_7days], width, label=f'Past 7 days ({seven_days_ticket_count})', color='#ff7f0e')
    bar3 = plt.bar(x + width, [response_breaches_yesterday, containment_breaches_yesterday], width, label=f'Yesterday ({yesterday_ticket_count})', color='#1f77b4')

    # Get figure and axes objects
    fig = plt.gcf()
    ax = plt.gca()
    # Transform coordinates to figure coordinates (bottom-left is 0,0)
    trans = transforms.blended_transform_factory(fig.transFigure, ax.transAxes)  # gets transform object
    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    plt.text(0.1, -0.15, now_eastern, transform=trans, ha='left', va='bottom', fontsize=10)
    plt.text(0.45, -0.15, '(*) Ticket counts for the period', transform=trans, ha='left', va='bottom', fontsize=10)  # uses transform object instead of xmin, ymin

    # Customize the plot
    plt.ylabel('Counts', fontdict={'fontsize': 12, 'fontweight': 'bold'})
    plt.title('Response and Containment SLA Breaches by Period', fontdict={'fontsize': 12, 'fontweight': 'bold'})
    plt.xticks(x, ['Resp. SLA Breaches', 'Cont. SLA Breaches'], fontdict={'fontsize': 12, 'fontweight': 'bold'})
    plt.legend()

    # Add value labels on top of each bar using the bar container objects
    for bars in [bar1, bar2, bar3]:
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width() / 2., height / 2,
                     f'{height}',
                     ha='center', va='bottom', fontdict={'fontsize': 14, 'fontweight': 'bold'})

    # Add grid for better readability
    plt.grid(True, axis='y', linestyle='--', alpha=0.7)

    # Adjust layout to prevent label clipping
    plt.tight_layout()

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmpfile:
        filepath = tmpfile.name  # Get the full path
        plt.savefig(filepath, format="png", bbox_inches='tight', dpi=600)
        plt.close(fig)

    return filepath  # Return the full path


class SlaBreaches(Command):
    """Webex Bot command to display a graph of mean times to respond and contain."""
    QUERY = f'-category:job type:{config.ticket_type_prefix} -owner:""'
    PERIOD = {
        "byTo": "months",
        "toValue": None,
        "byFrom": "months",
        "fromValue": 1
    }

    def __init__(self):
        super().__init__(command_keyword="sla_breach", help_message="SLA Breaches")

    def execute(self, message, attachment_actions, activity):
        incident_fetcher = IncidentFetcher()
        tickets = incident_fetcher.get_tickets(query=self.QUERY, period=self.PERIOD)
        tickets_by_periods = get_tickets_by_periods(tickets)
        filepath = get_sla_breaches_chart(tickets_by_periods)  # Store the full path

        # Use WebexTeamsAPI to send the file
        webex_api.messages.create(
            roomId=attachment_actions.json_data["roomId"],
            text=f"{activity['actor']['displayName']}, here's the latest SLA Breaches chart!",
            files=[filepath]  # Path to the file
        )
