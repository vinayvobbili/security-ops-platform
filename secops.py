import json
from datetime import datetime

from openpyxl import load_workbook
from tabulate import tabulate
from webexpythonsdk import WebexAPI

from config import get_config  # If you still use a config file for the path

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

    print(f"{shift.upper()} Shift Staffing:\n{table}")

    # Send message to Webex room
    webex_api.messages.create(
        roomId=room_id,
        text=f"Shift Staffing Update!",
        markdown=f"{shift.upper()} shift's now starting!\n```\n{table}\n```"
    )


def main():
    announce_shift_change('morning')
    announce_shift_change('afternoon')
    announce_shift_change('night')


if __name__ == "__main__":
    main()
