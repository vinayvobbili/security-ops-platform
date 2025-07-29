import json
import logging
import time
import traceback
from datetime import date
from datetime import datetime, timedelta
from pathlib import Path

import requests
import urllib3
from dateutil import parser
from openpyxl import load_workbook
from tabulate import tabulate
from tenacity import retry, stop_after_attempt, wait_exponential, before_sleep_log
from webexpythonsdk import WebexAPI
from webexpythonsdk.models.cards import (
    Colors, TextBlock, FontWeight, FontSize,
    AdaptiveCard, HorizontalAlignment, FactSet, Fact
)

from config import get_config
from services import azdo
from services.xsoar import TicketHandler, ListHandler
from src.components import oncall

# Set up logging for tenacity retries
logger = logging.getLogger("tenacity.retry")
logging.basicConfig(level=logging.INFO)

config = get_config()
webex_api = WebexAPI(config.webex_bot_access_token_soar)
list_handler = ListHandler()
BASE_QUERY = f'type:{config.team_name} -owner:""'
root_directory = Path(__file__).parent.parent

# Load the workbook
excel_path = root_directory / 'data' / 'transient' / 'secOps' / config.secops_shift_staffing_filename
wb = load_workbook(excel_path)
# Select the sheet
sheet = wb['SecOps Roster 2025 Jul Aug']

# get the cell names by shift from the sheet
SECOPS_SHIFT_STAFFING_FILENAME = root_directory / 'data' / 'secOps' / 'cell_names_by_shift.json'
with open(SECOPS_SHIFT_STAFFING_FILENAME, 'r') as f:
    cell_names_by_shift = json.load(f)

MANAGEMENT_NOTES_FILE = root_directory / 'data' / 'transient' / 'secOps' / 'management_notes.json'


def get_open_tickets():
    all_tickets = TicketHandler().get_tickets(query=BASE_QUERY + ' -status:closed')
    total_tickets = len(all_tickets)
    ticket_show_count = min(total_tickets, 5)
    ticket_base_url = config.xsoar_prod_ui_base_url + "/Custom/caseinfoid/"
    open_tickets = [f"[{ticket['id']}]({ticket_base_url}{ticket['id']})" for ticket in all_tickets[0:ticket_show_count]]
    diff = total_tickets - ticket_show_count
    return ', '.join(map(str, open_tickets)) + (f" and {diff} more" if diff > 0 else '')


def get_staffing_data(day_name, shift_name):
    shift_cell_names = cell_names_by_shift[day_name][shift_name]
    staffing_data = {}
    for team, cell_names in shift_cell_names.items():
        staffing_data[team] = [sheet[cell_name].value for cell_name in cell_names if sheet[cell_name].value != '\xa0']
    staffing_data['On-Call'] = [oncall.get_on_call_person()['name'] + ' (' + oncall.get_on_call_person()['phone_number'] + ')']
    return staffing_data


def safe_parse_datetime(dt_string):
    """Parse datetime string safely, ensuring it's timezone naive."""
    try:
        if not dt_string:
            return None
        dt = parser.parse(dt_string)
        return dt.replace(tzinfo=None)
    except Exception as e:
        print(f"Error parsing datetime {dt_string}: {e}")
        return None


def announce_previous_shift_performance(room_id, shift_name):
    """Announce the performance of the previous shift in the Webex room."""
    try:
        # Send previous shift performance to Webex room
        day_name = datetime.now().strftime("%A")
        period = {
            "byFrom": "hours",
            "fromValue": 8,
            "byTo": "hours",
            "toValue": 0
        }
        incident_fetcher = TicketHandler()

        inflow = incident_fetcher.get_tickets(
            query=BASE_QUERY,
            period=period
        )
        outflow = incident_fetcher.get_tickets(
            query=BASE_QUERY + ' status:closed',
            period=period
        )

        malicious_true_positives = incident_fetcher.get_tickets(
            query=BASE_QUERY + ' status:closed impact:"Malicious True Positive"',
            period=period
        )

        response_sla_breaches = incident_fetcher.get_tickets(
            query=BASE_QUERY + ' timetorespond.slaStatus:late',
            period=period
        )
        containment_sla_breaches = incident_fetcher.get_tickets(
            query=BASE_QUERY + ' timetocontain.slaStatus:late',
            period=period
        )
        total_time_to_respond = 0
        total_time_to_contain = 0
        for ticket in inflow:
            if 'timetorespond' in ticket['CustomFields']:
                total_time_to_respond += ticket['CustomFields']['timetorespond']['totalDuration']
            else:
                total_time_to_respond += ticket['CustomFields']['responsesla']['totalDuration']
        mean_time_to_respond = total_time_to_respond / len(inflow) if len(inflow) > 0 else 0

        inflow_tickets_with_host = [ticket for ticket in inflow if ticket.get('CustomFields', {}).get('hostname')]
        for ticket in inflow_tickets_with_host:
            if 'timetocontain' in ticket['CustomFields']:
                total_time_to_contain += ticket['CustomFields']['timetocontain']['totalDuration']
            else:
                total_time_to_contain += ticket['CustomFields']['containmentsla']['totalDuration']
        mean_time_to_contain = 0
        if inflow_tickets_with_host:
            mean_time_to_contain = total_time_to_contain / len(inflow_tickets_with_host)

        previous_shift_mapping = {
            'morning': ((datetime.now() - timedelta(days=1)).strftime("%A"), 'night'),
            'afternoon': (day_name, 'morning'),
            'night': (day_name, 'afternoon'),
        }

        previous_shift_day, previous_shift_name = previous_shift_mapping.get(shift_name, (None, None))

        if previous_shift_name is None:
            print(f"Warning: No previous shift defined for {shift_name}")
            return

        previous_shift_staffing_data = get_staffing_data(previous_shift_day, previous_shift_name)

        total_staff_count = sum(len(staff) for staff in previous_shift_staffing_data.values())
        tickets_closed_per_analyst = len(outflow) / total_staff_count if total_staff_count > 0 else 0

        # Use naive datetime for comparison
        eight_hours_ago = datetime.now() - timedelta(hours=8)

        # Process domains blocked
        all_domains = list_handler.get_list_data_by_name(f'{config.team_name} Blocked Domains')
        domains_blocked = []
        for item in all_domains:
            if 'blocked_at' in item:
                item_datetime = safe_parse_datetime(item['blocked_at'])
                if item_datetime and item_datetime >= eight_hours_ago:
                    domains_blocked.append(item['domain'])

        # Process IP addresses blocked
        all_ips = list_handler.get_list_data_by_name(f'{config.team_name} Blocked IP Addresses')
        ip_addresses_blocked = []
        for item in all_ips:
            if 'blocked_at' in item:
                item_datetime = safe_parse_datetime(item['blocked_at'])
                if item_datetime and item_datetime >= eight_hours_ago:
                    ip_addresses_blocked.append(item['ip_address'])

        # Process hosts contained
        all_hosts = list_handler.get_list_data_by_name(f'{config.team_name} Contained Hosts')
        hosts_contained_list = []
        for item in all_hosts:
            if 'contained_at' in item:
                item_datetime = safe_parse_datetime(item['contained_at'])
                if item_datetime and item_datetime >= eight_hours_ago:
                    hosts_contained_list.append(item['hostname'])

        hosts_contained = ', '.join(hosts_contained_list)
        iocs_blocked = ', '.join(domains_blocked + ip_addresses_blocked)

        tuning_requests_submitted = azdo.get_tuning_requests_submitted_by_last_shift()

        shift_performance = AdaptiveCard(
            body=[
                TextBlock(
                    text="Previous Shift Performance",
                    weight=FontWeight.BOLDER,
                    color=Colors.ACCENT,
                    size=FontSize.DEFAULT,
                    horizontalAlignment=HorizontalAlignment.CENTER,
                ),
                FactSet(
                    facts=[
                        Fact(title="Shift Lead", value=previous_shift_staffing_data['SA'][0]),
                        Fact(title="Tickets ack'ed", value=str(len(inflow))),
                        Fact(title="Tickets closed",
                             value=f"{len(outflow)} ({tickets_closed_per_analyst:.2f}/analyst)"),
                        Fact(title="MTPs",
                             value=', '.join([ticket.get('id') for ticket in malicious_true_positives])),
                        Fact(title="SLA Breaches",
                             value=f"Resp- {len(response_sla_breaches)} [{', '.join(['X#' + breach.get('id') for breach in response_sla_breaches])}]\n"
                                   f"Cont- {len(containment_sla_breaches)} [{', '.join(['X#' + breach.get('id') for breach in containment_sla_breaches])}]"),
                        Fact(title="MTT (min:sec)",
                             value=f"Respond- {int(mean_time_to_respond // 60)}:{int(mean_time_to_respond % 60):02d} \n"
                                   f"Contain- {int(mean_time_to_contain // 60)}:{int(mean_time_to_contain % 60):02d}"),
                        Fact(title="IOCs blocked", value=iocs_blocked or ""),
                        Fact(title="Hosts contained", value=hosts_contained or ""),
                        Fact(title="Tuning requests", value=', '.join(tuning_requests_submitted) or "")
                    ]
                )
            ]
        )
        webex_api.messages.create(
            roomId=room_id,
            text="Previous Shift Performance!",
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": shift_performance.to_dict()}]
        )
    except Exception as e:
        print(f"Error in announce_previous_shift_performance: {e}")
        traceback.print_exc()


@retry(
    reraise=True,
    stop=stop_after_attempt(3),  # Retry up to 3 times
    wait=wait_exponential(multiplier=2, min=2, max=10),  # Exponential backoff
    before_sleep=before_sleep_log(logger, logging.WARNING),
)
def announce_shift_change(shift_name, room_id, sleep_time=30):
    """Announce the change of shift in the Webex room."""
    try:
        day_name = datetime.now().strftime("%A")
        staffing_data = get_staffing_data(day_name, shift_name)
        staffing_data['SA'][0] = staffing_data['SA'][0] + ' (Lead)'

        # Pad staffing_data lists to the same length
        max_len = max(len(v) for v in staffing_data.values())
        for k, v in staffing_data.items():
            staffing_data[k] = [(i if i is not None else '') for i in v] + [''] * (max_len - len(v))

        # Convert staffing_data to a table with the first column as headers
        headers = list(staffing_data.keys())
        shift_data_table = list(zip(*staffing_data.values()))
        shift_data_table = tabulate(shift_data_table, headers=headers, tablefmt="simple")

        note = ''
        with open(MANAGEMENT_NOTES_FILE, "r") as file:
            management_notes = json.loads(file.read())
            keep_until = datetime.strptime(management_notes['keep_until'], '%Y-%m-%d').date()
            if date.today() <= keep_until:
                note = management_notes['note']

        hosts_in_containment = list_handler.get_list_data_by_name(f'{config.team_name} Contained Hosts')
        for item in hosts_in_containment:
            contained_at = safe_parse_datetime(item.get("contained_at"))
            if contained_at:
                time_under_containment_delta = datetime.now() - contained_at
                days = time_under_containment_delta.days
                hours = time_under_containment_delta.seconds // 3600
                item["time_under_containment"] = f"{days} D, {hours} H"
            else:
                item["time_under_containment"] = "Unknown"

        hosts_in_containment = [
            'X#' + item.get('ticket#', 'N/A') + ' | ' +
            item["hostname"] + ' | ' +
            item['time_under_containment']
            for item in hosts_in_containment
        ]

        # Send a new shift starting message to Webex room
        webex_api.messages.create(
            roomId=room_id,
            text=f"Shift Change Notice!",
            markdown=f"Good **{shift_name.upper()}**! A new shift's starting now!\n"
                     f"Timings: {sheet[cell_names_by_shift['shift_timings'][shift_name]].value}\n"
                     f"Open {config.team_name}* tickets: {get_open_tickets()}\n"
                     f"Hosts in Containment (TUC): \n {'\n'.join(hosts_in_containment) if hosts_in_containment else ''}\n\n"
                     f"**Management Notes**: {note}\n"
                     f"Staffing:\n"
                     f"```\n{shift_data_table}\n```"
        )

        time.sleep(sleep_time)  # give time to digest the shift change message before sending the performance message

        announce_previous_shift_performance(shift_name=shift_name, room_id=room_id)
    except (requests.exceptions.ConnectionError, urllib3.exceptions.ProtocolError) as net_err:
        print(f"Network error in announce_shift_change: {net_err}")
        traceback.print_exc()
        raise  # Reraise to trigger retry
    except Exception as e:
        print(f"Error in announce_shift_change: {e}")
        traceback.print_exc()  # Print the full traceback for better debugging


def main():
    """
    Main function to run the scheduled jobs.
    """
    room_id = config.webex_room_id_vinay_test_space
    announce_shift_change('afternoon', room_id, sleep_time=0)
    # announce_previous_shift_performance(room_id, 'night')


if __name__ == "__main__":
    main()
