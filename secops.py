import json
from datetime import datetime

from openpyxl import load_workbook
from tabulate import tabulate
from webexpythonsdk import WebexAPI

from config import get_config  # If you still use a config file for the path
from incident_fetcher import IncidentFetcher

config = get_config()
webex_api = WebexAPI(config.webex_bot_access_token_soar)
room_id = config.webex_room_id_soc_shift_updates

# Load the workbook
wb = load_workbook('data/' + config.secops_shift_staffing_filename)
# Select the sheet
sheet = wb['Jan - Feb 2025']

# get the cell names by shift from the sheet
with open('data/cell_names_by_shift.json', 'r') as f:
    cell_names_by_shift = json.load(f)


def get_open_tickets():
    all_tickets = IncidentFetcher().get_tickets(query=f'-category:job -status:Closed type:{config.ticket_type_prefix}')
    total_tickets = len(all_tickets)
    ticket_show_count = min(total_tickets, 30)
    ticket_base_url = config.xsoar_ui_base_url + "/Custom/caseinfoid/"
    open_tickets = [f"[{ticket['id']}]({ticket_base_url}{ticket['id']})" for ticket in all_tickets[0:ticket_show_count]]
    return ', '.join(map(str, open_tickets)) + (f" and {total_tickets - ticket_show_count} more" if total_tickets > ticket_show_count else '')


def announce_shift_change(shift):
    day_name = datetime.now().strftime("%A")
    shift_cell_names = cell_names_by_shift[day_name][shift]
    staffing_data = {}
    for team, cell_names in shift_cell_names.items():
        staffing_data[team] = [sheet[cell_name].value for cell_name in cell_names if sheet[cell_name].value != '\xa0']

    # Convert staffing_data to a table with the first column as headers
    headers = list(staffing_data.keys())
    table_data = list(zip(*staffing_data.values()))
    table = tabulate(table_data, headers=headers, tablefmt="simple")

    # print(f"{shift.upper()} Shift Staffing:\n{table}")

    # Send message to Webex room
    webex_api.messages.create(
        roomId=room_id,
        text=f"Shift Staffing Update!",
        markdown=f"Good {shift.upper()}! A new shift's starting now!\n"
                 f"Timings: {sheet[cell_names_by_shift['shift_timings'][shift]].value}\n"
                 f"Open METCIRT* tickets: {get_open_tickets()}\n"
                 f"Staffing:\n"
                 f"```\n{table}\n```"
    )


def main():
    announce_shift_change('morning')
    # announce_shift_change('afternoon')
    # announce_shift_change('night')


if __name__ == "__main__":
    main()
