import base64
import io
import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta

import matplotlib.transforms as transforms
import numpy as np
from matplotlib import pyplot as plt
from pytz import timezone
from webex_bot.models.command import Command
from webex_bot.models.response import response_from_adaptive_card
from webexpythonsdk.models.cards import AdaptiveCard, Image

from incident_fetcher import IncidentFetcher

fun_messages = []
eastern = timezone('US/Eastern')  # Define the Eastern time zone

with open('fun_messages.json', 'r') as f:
    messages_data = json.load(f)
    fun_messages.extend(messages_data.get("messages", []))  # Modify the global list


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
            '%Y-%m-%dT%H:%M:%S.%fZ'
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


def get_sla_breaches_card(ticket_slas_by_periods):
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
    plt.text(0.45, -0.15, '(*) Total tickets received during that period', transform=trans, ha='left', va='bottom', fontsize=10)  # uses transform object instead of xmin, ymin

    # Customize the plot
    plt.ylabel('Counts', fontdict={'fontsize': 12, 'fontweight': 'bold'})
    plt.title('Response and Containment SLA Breaches by Period', fontdict={'fontsize': 12, 'fontweight': 'bold'})
    plt.xticks(x, ['Response SLA (3 mins)', 'Containment SLA (15 mins)'], fontdict={'fontsize': 12, 'fontweight': 'bold'})
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

    # Convert plot to base64 for Adaptive Card
    buf = io.BytesIO()
    plt.savefig(buf, format="png", bbox_inches='tight', dpi=300)  # Adjust dpi as needed
    buf.seek(0)
    image_base64 = base64.b64encode(buf.read()).decode('utf-8')
    plt.close()  # Close the plot to free resources
    buf.close()

    card = AdaptiveCard(
        body=[
            Image(url=f"data:image/png;base64,{image_base64}"),
        ]
    )

    return card


class SlaBreaches(Command):
    """Webex Bot command to display a graph of mean times to respond and contain."""
    QUERY = '-category:job type:METCIRT -owner:""'
    PERIOD = {
        "byTo": "months",
        "toValue": None,
        "byFrom": "months",
        "fromValue": 1
    }

    def __init__(self):
        super().__init__(command_keyword="sla_breach", help_message="SLA Breaches")

    def pre_execute(self, message, attachment_actions, activity):
        return f"{activity['actor']['displayName']}, {random.choice(fun_messages)}"

    def execute(self, message, attachment_actions, activity):
        incident_fetcher = IncidentFetcher()
        tickets = incident_fetcher.get_tickets(query=self.QUERY, period=self.PERIOD)
        tickets_by_periods = get_tickets_by_periods(tickets)
        card = get_sla_breaches_card(tickets_by_periods)

        return response_from_adaptive_card(card)
