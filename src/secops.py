import json
import time
from datetime import datetime, timedelta
from pathlib import Path

from dateutil.utils import today
from openpyxl import load_workbook
from tabulate import tabulate
from webexpythonsdk import WebexAPI
from webexpythonsdk.models.cards import (
    Colors, TextBlock, FontWeight, FontSize,
    AdaptiveCard, HorizontalAlignment, FactSet, Fact
)

from config import get_config  # If you still use a CONFIG file for the path
from services.xsoar import IncidentHandler

config = get_config()
webex_api = WebexAPI(config.webex_bot_access_token_soar)

BASE_QUERY = f'type:{config.ticket_type_prefix} -owner:""'
root_directory = Path(__file__).parent.parent

# Load the workbook
wb = load_workbook(root_directory / 'data' / 'transient' / config.secops_shift_staffing_filename)
# Select the sheet
sheet = wb['March-April 2025']

# get the cell names by shift from the sheet
SECOPS_SHIFT_STAFFING_FILENAME = root_directory / 'data' / 'cell_names_by_shift.json'
with open(SECOPS_SHIFT_STAFFING_FILENAME, 'r') as f:
    cell_names_by_shift = json.load(f)

MANAGEMENT_NOTES_FILE = root_directory / 'data' / 'transient' / 'secOps' / 'management_notes.json'


def get_open_tickets():
    all_tickets = IncidentHandler().get_tickets(query=BASE_QUERY + ' -status:closed')
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
    return staffing_data


def announce_previous_shift_performance(room_id, shift_name):
    # Send previous shift performance to Webex room

    day_name = datetime.now().strftime("%A")
    period = {
        "byFrom": "hours",
        "fromValue": 8,
        "byTo": "hours",
        "toValue": 0
    }
    incident_fetcher = IncidentHandler()

    inflow = incident_fetcher.get_tickets(
        query=BASE_QUERY,
        period=period
    )
    outflow = incident_fetcher.get_tickets(
        query=BASE_QUERY + ' -status:closed',
        period=period
    )
    response_sla_breaches = incident_fetcher.get_tickets(
        query=BASE_QUERY + ' responsesla.slaStatus:late',
        period=period
    )
    containment_sla_breaches = incident_fetcher.get_tickets(
        query=BASE_QUERY + ' containmentsla.slaStatus:late',
        period=period
    )
    total_time_to_respond = 0
    total_time_to_contain = 0
    for ticket in inflow:
        total_time_to_respond += ticket['CustomFields']['responsesla']['totalDuration']
    mean_time_to_respond = total_time_to_respond / len(inflow)

    inflow_tickets_with_host = [ticket for ticket in inflow if ticket.get('CustomFields', {}).get('hostname')]
    for ticket in inflow_tickets_with_host:
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
    tickets_closed_per_analyst = len(outflow) / total_staff_count

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
                    Fact(title="New Tickets ack'ed", value=str(len(inflow))),
                    Fact(title="Tickets closed out", value=f"{len(outflow)} ({tickets_closed_per_analyst:.2f}/analyst)"),
                    Fact(title="Resp. SLA Breaches", value=str(len(response_sla_breaches))),
                    Fact(title="Cont. SLA Breaches", value=str(len(containment_sla_breaches))),
                    Fact(title="MTTR (min:sec)", value=f"{int(mean_time_to_respond // 60)}:{int(mean_time_to_respond % 60):02d}"),
                    Fact(title="MTTC (min:sec)", value=f"{int(mean_time_to_contain // 60)}:{int(mean_time_to_contain % 60):02d}"),
                    Fact(title="IOCs blocked", value="1.2.3.4, 5.6.7.8, example.com"),
                    Fact(title="Hosts contained", value="US123, IN456, AU789"),
                    Fact(title="Tuning requests submitted", value="US321")
                ]
            )
        ]
    )
    webex_api.messages.create(
        roomId=room_id,
        text="Previous Shift Performance!",
        attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": shift_performance.to_dict()}]
    )


def announce_shift_change(shift_name, room_id, sleep_time=30):
    day_name = datetime.now().strftime("%A")
    staffing_data = get_staffing_data(day_name, shift_name)
    staffing_data['SA'][0] = staffing_data['SA'][0] + ' (Lead)'

    # Convert staffing_data to a table with the first column as headers
    headers = list(staffing_data.keys())
    shift_data_table = list(zip(*staffing_data.values()))
    shift_data_table = tabulate(shift_data_table, headers=headers, tablefmt="simple")

    note = 'None'
    with open(MANAGEMENT_NOTES_FILE, "r") as file:
        management_notes = file.read()
        management_notes = json.loads(management_notes)
        keep_until = datetime.strptime(management_notes['keep_until'], '%Y-%m-%d').date()
        if today().date() <= keep_until:
            note = management_notes['note']

    # Send a new shift starting message to Webex room
    webex_api.messages.create(
        roomId=room_id,
        text=f"Shift Change Notice!",
        markdown=f"Good **{shift_name.upper()}**! A new shift's starting now!\n"
                 f"Timings: {sheet[cell_names_by_shift['shift_timings'][shift_name]].value}\n"
                 f"Open METCIRT* tickets: {get_open_tickets()}\n"
                 f"Hosts in Containment: US123, IN456, AU789\n"
                 f"**Management Notes**: {note}\n"
                 f"Staffing:\n"
                 f"```\n{shift_data_table}\n```"
    )

    time.sleep(sleep_time)  # give time to digest the shift change message before sending the performance message

    announce_previous_shift_performance(shift_name=shift_name, room_id=room_id)


def main():
    """
    Main function to run the scheduled jobs.
    """
    room_id = config.webex_room_id_vinay_test_space
    announce_shift_change('night', room_id, sleep_time=0)
    # announce_shift_change('afternoon')
    # announce_shift_change('night')


if __name__ == "__main__":
    main()
