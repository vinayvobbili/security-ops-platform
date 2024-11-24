from datetime import datetime, timedelta

import pytz
from webex_bot.models.command import Command
from webexteamssdk import WebexTeamsAPI

import chart
from config import get_config
from incident_fetcher import IncidentFetcher

config = get_config()
webex_api = WebexTeamsAPI(access_token=config.bot_api_token)

QUERY_TEMPLATE = '-category:job type:METCIRT -owner:"" closed:>={start} closed:<{end}'


def plot_outflow() -> str:
    # Calculate fresh values EACH TIME the command is run
    et = pytz.timezone("US/Eastern")
    yesterday_start = datetime.now(et).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
    yesterday_end = yesterday_start + timedelta(days=1)
    yesterday_start_utc = yesterday_start.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    yesterday_end_utc = yesterday_end.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    # Use an f-string or format to create the query dynamically
    query = QUERY_TEMPLATE.format(start=yesterday_start_utc, end=yesterday_end_utc)
    tickets = IncidentFetcher().get_tickets(query=query)
    filepath = chart.make_pie(tickets, 'Outflow Yesterday')  # Store the full path

    return filepath


class Outflow(Command):

    def __init__(self):
        super().__init__(command_keyword="outflow", help_message="Outflow")

    def execute(self, message, attachment_actions, activity):
        outflow_chart_filepath = plot_outflow()

        webex_api.messages.create(
            roomId=attachment_actions.json_data["roomId"],
            text=f"{activity['actor']['displayName']}, here's the Outflow chart!",
            files=[outflow_chart_filepath]  # Path to the file
        )
