import json
import time
from datetime import datetime

from openpyxl import load_workbook
from tabulate import tabulate
from webexpythonsdk import WebexAPI

from config import get_config  # If you still use a config file for the path
from incident_fetcher import IncidentFetcher

config = get_config()
webex_api = WebexAPI(config.webex_bot_access_token_soar)

base_query = f'type:{config.ticket_type_prefix} -owner:""'

# Load the workbook
wb = load_workbook('data/' + config.secops_shift_staffing_filename)
# Select the sheet
sheet = wb['Jan - Feb 2025']

# get the cell names by shift from the sheet
with open('data/cell_names_by_shift.json', 'r') as f:
    cell_names_by_shift = json.load(f)


def get_open_tickets():
    all_tickets = IncidentFetcher().get_tickets(query=base_query + ' -status:closed')
    total_tickets = len(all_tickets)
    ticket_show_count = min(total_tickets, 30)
    ticket_base_url = config.xsoar_ui_base_url + "/Custom/caseinfoid/"
    open_tickets = [f"[{ticket['id']}]({ticket_base_url}{ticket['id']})" for ticket in all_tickets[0:ticket_show_count]]
    diff = total_tickets - ticket_show_count
    return ', '.join(map(str, open_tickets)) + (f" and {diff} more" if diff > 0 else '')


def announce_shift_change(shift, room_id):
    day_name = datetime.now().strftime("%A")
    shift_cell_names = cell_names_by_shift[day_name][shift]
    staffing_data = {}
    for team, cell_names in shift_cell_names.items():
        staffing_data[team] = [sheet[cell_name].value for cell_name in cell_names if sheet[cell_name].value != '\xa0']

    # Convert staffing_data to a table with the first column as headers
    headers = list(staffing_data.keys())
    shift_data_table = list(zip(*staffing_data.values()))
    shift_data_table = tabulate(shift_data_table, headers=headers, tablefmt="simple")

    # print(f"{shift.upper()} Shift Staffing:\n{table}")

    # Send new shift starting message to Webex room
    webex_api.messages.create(
        roomId=room_id,
        text=f"Shift Change Notice!",
        markdown=f"Good **{shift.upper()}**! A new shift's starting now!\n"
                 f"Timings: {sheet[cell_names_by_shift['shift_timings'][shift]].value}\n"
                 f"Open METCIRT* tickets: {get_open_tickets()}\n"
                 f"Hosts in Containment: US123, IN456, AU789\n"
                 f"**Management Notes**: Lorem Ipsum Dolor Sit Amet Consectetur Adipiscing Elit.\n"
                 f"Staffing:\n"
                 f"```\n{shift_data_table}\n```"
    )

    time.sleep(300)  # give time to digest the shift change message before sending the performance message

    # Send previous shift performance to Webex room
    period = {
        "byFrom": "hours",
        "fromValue": 8,
        "byTo": "hours",
        "toValue": 0
    }
    incident_fetcher = IncidentFetcher()

    inflow = incident_fetcher.get_tickets(
        query=base_query,
        period=period
    )
    outflow = incident_fetcher.get_tickets(
        query=base_query + ' -status:closed',
        period=period
    )
    response_sla_breaches = incident_fetcher.get_tickets(
        query=base_query + ' responsesla.slaStatus:late',
        period=period
    )
    containment_sla_breaches = incident_fetcher.get_tickets(
        query=base_query + ' containmentsla.slaStatus:late',
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

    shift_performance = {
        'Shift Lead': 'John Doe',
        'New Tickets ack\'ed': len(inflow),
        'Tickets closed out': len(outflow),
        'Resp. SLA Breaches': len(response_sla_breaches),
        'Cont. SLA Breaches': len(containment_sla_breaches),
        'MTTR': f"{int(mean_time_to_respond // 60)}:{int(mean_time_to_respond % 60):02d}",
        'MTTC': f"{int(mean_time_to_contain // 60)}:{int(mean_time_to_contain % 60):02d}",
        'IOCs blocked': '1.2.3.4, 5.6.7.8, example.com',
        'Hosts contained': 'US123, IN456, AU789',
        'Tuning requests submitted:': 'US321',
    }
    shift_performance = tabulate(shift_performance.items(), tablefmt="simple")
    webex_api.messages.create(
        roomId=room_id,
        text=f"Previous Shift Performance!",
        markdown=f"**Previous Shift Performance**:\n"
                 f"```\n{shift_performance}\n```"
    )


def main():
    """
    Main function to run the scheduled jobs.
    """
    room_id = config.webex_room_id_vinay_test_space
    announce_shift_change('night', room_id)
    # announce_shift_change('afternoon')
    # announce_shift_change('night')


if __name__ == "__main__":
    main()
