from datetime import datetime, timedelta

import pytz
from webex_bot.models.command import Command
from webexteamssdk import WebexTeamsAPI

import chart
from config import get_config
from incident_fetcher import IncidentFetcher

QUERY_TEMPLATE = '-category:job type:{ticket_type_prefix} -owner:"" created:>={start} created:<{end}'

config = get_config()
webex_api = WebexTeamsAPI(access_token=config.webex_bot_access_token)


def plot_inflow() -> str:
    # Calculate fresh values EACH TIME the command is run
    et = pytz.timezone("US/Eastern")

    yesterday_start = datetime.now(et).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
    yesterday_end = yesterday_start + timedelta(days=1)
    yesterday_start_utc = yesterday_start.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    yesterday_end_utc = yesterday_end.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    # Use an f-string or format to create the query dynamically
    query = QUERY_TEMPLATE.format(ticket_type_prefix=config.ticket_type_prefix, start=yesterday_start_utc, end=yesterday_end_utc)
    tickets = IncidentFetcher().get_tickets(query=query)
    filepath = chart.make_pie(tickets, 'Inflow Yesterday')  # Store the full path

    return filepath


class Inflow(Command):

    def __init__(self):
        super().__init__(command_keyword="inflow", help_message="Inflow")

    def execute(self, message, attachment_actions, activity):
        inflow_chart_filepath = plot_inflow()

        webex_api.messages.create(
            roomId=attachment_actions.json_data["roomId"],
            text=f"{activity['actor']['displayName']}, here's the Inflow chart!",
            files=[inflow_chart_filepath]  # Path to the file
        )
