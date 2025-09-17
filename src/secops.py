import json
import logging
import time
import traceback
from datetime import date
from datetime import datetime, timedelta
from pathlib import Path

import pytz
from dateutil import parser
from openpyxl import load_workbook
from requests import exceptions as requests_exceptions
from tabulate import tabulate
from tenacity import retry, stop_after_attempt, wait_exponential, before_sleep_log
from urllib3 import exceptions as urllib3_exceptions
from webexpythonsdk import WebexAPI
from webexpythonsdk.models.cards import (
    Colors, TextBlock, FontWeight, FontSize,
    AdaptiveCard, HorizontalAlignment, FactSet, Fact
)

from my_config import get_config
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

# Load the workbook with error handling
excel_path = root_directory / 'data' / 'transient' / 'secOps' / config.secops_shift_staffing_filename
try:
    wb = load_workbook(excel_path)
    # Select the sheet
    sheet = wb['SecOps Roster 2025 SEP-OCT']
    EXCEL_AVAILABLE = True
except FileNotFoundError:
    logger.warning(f"Excel file not found: {excel_path}. Staffing data will be unavailable.")
    wb = None
    sheet = None
    EXCEL_AVAILABLE = False
except Exception as e:
    logger.error(f"Error loading Excel file: {e}. Staffing data will be unavailable.")
    wb = None
    sheet = None
    EXCEL_AVAILABLE = False

# get the cell names by shift from the sheet
SECOPS_SHIFT_STAFFING_FILENAME = root_directory / 'data' / 'secOps' / 'cell_names_by_shift.json'
with open(SECOPS_SHIFT_STAFFING_FILENAME, 'r') as f:
    cell_names_by_shift = json.load(f)

MANAGEMENT_NOTES_FILE = root_directory / 'data' / 'transient' / 'secOps' / 'management_notes.json'


# Constants
class ShiftConstants:
    MORNING_START = 270  # 04:30
    AFTERNOON_START = 750  # 12:30
    NIGHT_START = 1230  # 20:30
    TICKET_SHOW_COUNT = 5
    SHIFT_DURATION_HOURS = 8
    EASTERN_TZ = 'US/Eastern'


def get_current_shift():
    """Determine current shift based on Eastern time."""
    eastern = pytz.timezone(ShiftConstants.EASTERN_TZ)
    now = datetime.now(eastern)
    total_minutes = now.hour * 60 + now.minute

    if ShiftConstants.MORNING_START <= total_minutes < ShiftConstants.AFTERNOON_START:
        return 'morning'
    elif ShiftConstants.AFTERNOON_START <= total_minutes < ShiftConstants.NIGHT_START:
        return 'afternoon'
    else:
        return 'night'


def get_open_tickets():
    """Get formatted string of open tickets with links."""
    all_tickets = TicketHandler().get_tickets(query=BASE_QUERY + ' -status:closed')
    total_tickets = len(all_tickets)
    ticket_show_count = min(total_tickets, ShiftConstants.TICKET_SHOW_COUNT)

    ticket_base_url = f"{config.xsoar_prod_ui_base_url}/Custom/caseinfoid/"
    open_tickets = [
        f"[{ticket['id']}]({ticket_base_url}{ticket['id']})"
        for ticket in all_tickets[:ticket_show_count]
    ]

    tickets_text = ', '.join(open_tickets)
    remaining = total_tickets - ticket_show_count
    return f"{tickets_text}{f' and {remaining} more' if remaining > 0 else ''}"


class ExcelStaffingReader:
    """Handles reading staffing data from Excel sheet."""

    @staticmethod
    def get_oncall_info():
        """Get formatted on-call person info."""
        person = oncall.get_on_call_person()
        return f"{person['name']} ({person['phone_number']})"

    @staticmethod
    def get_fallback_data():
        """Get fallback staffing data when Excel is unavailable."""
        return {
            'senior_analysts': ['N/A (Excel file missing)'],
            'On-Call': [ExcelStaffingReader.get_oncall_info()]
        }

    @staticmethod
    def get_error_data():
        """Get error fallback staffing data."""
        return {
            'senior_analysts': ['N/A (Error occurred)'],
            'On-Call': ['N/A (Error occurred)']
        }

    @staticmethod
    def is_valid_cell_value(value):
        """Check if cell value is valid and not empty."""
        return (value is not None and
                str(value).strip() != '' and
                value != '\xa0')

    @staticmethod
    def read_team_staffing(cell_names):
        """Read staffing data for a specific team."""
        team_staff = []
        for cell_name in cell_names:
            cell = sheet[cell_name] if sheet else None
            if cell is not None:
                value = getattr(cell, 'value', None)
                if ExcelStaffingReader.is_valid_cell_value(value):
                    team_staff.append(value)
        return team_staff


def get_staffing_data(day_name=None, shift_name=None):
    """Get staffing data for a specific day and shift."""
    if day_name is None:
        day_name = datetime.now(pytz.timezone(ShiftConstants.EASTERN_TZ)).strftime('%A')
    if shift_name is None:
        shift_name = get_current_shift()

    try:
        if not EXCEL_AVAILABLE or sheet is None:
            logger.warning("Excel file not available, returning minimal staffing data")
            return ExcelStaffingReader.get_fallback_data()

        shift_cell_names = cell_names_by_shift[day_name][shift_name]
        staffing_data = {}

        for team, cell_names in shift_cell_names.items():
            staffing_data[team] = ExcelStaffingReader.read_team_staffing(cell_names)

        staffing_data['On-Call'] = [ExcelStaffingReader.get_oncall_info()]
        return staffing_data

    except Exception as e:
        logger.error(f"Error in get_staffing_data: {e}")
        return ExcelStaffingReader.get_error_data()


def safe_parse_datetime(dt_string):
    """Parse datetime string safely, ensuring it's timezone naive."""
    if not dt_string:
        return None

    try:
        dt = parser.parse(dt_string)
        return dt.replace(tzinfo=None)
    except Exception as e:
        logger.error(f"Error parsing datetime {dt_string}: {e}")
        return None


def get_shift_lead(day_name, shift_name):
    """Get the shift lead for a specific day and shift."""
    if not EXCEL_AVAILABLE or sheet is None:
        return "N/A (Excel file missing)"

    try:
        shift_cell_names = cell_names_by_shift[day_name][shift_name]
        if 'Lead' not in shift_cell_names:
            return "No Lead Assigned"

        for cell_name in shift_cell_names['Lead']:
            cell = sheet[cell_name]
            if cell is not None:
                value = getattr(cell, 'value', None)
                if ExcelStaffingReader.is_valid_cell_value(value):
                    return str(value)

        return "No Lead Assigned"
    except (KeyError, IndexError, AttributeError) as e:
        logger.error(f"Error getting shift lead: {e}")
        return "N/A"


def get_basic_shift_staffing(day_name, shift_name):
    """Get basic staffing count for a shift without detailed data."""
    if not EXCEL_AVAILABLE or sheet is None:
        return {'total_staff': 0, 'teams': {}}

    try:
        shift_cell_names = cell_names_by_shift[day_name][shift_name]
        teams = {}

        for team, cell_names in shift_cell_names.items():
            team_count = sum(
                1 for cell_name in cell_names
                if sheet[cell_name] is not None and
                ExcelStaffingReader.is_valid_cell_value(getattr(sheet[cell_name], 'value', None))
            )
            teams[team] = team_count

        total_staff = sum(teams.values())
        return {'total_staff': total_staff, 'teams': teams}

    except (KeyError, IndexError, AttributeError) as e:
        logger.error(f"Error getting basic staffing: {e}")
        return {'total_staff': 0, 'teams': {}}


class TicketMetricsCalculator:
    """Handles ticket metrics calculations."""

    @staticmethod
    def create_shift_period(days_back, shift_start_hour):
        """Create time period dict for shift."""
        return {
            "byFrom": "hours",
            "fromValue": (days_back * 24) + (24 - shift_start_hour),
            "byTo": "hours",
            "toValue": (days_back * 24) + (16 - shift_start_hour)
        }

    @staticmethod
    def calculate_response_times(tickets):
        """Calculate total response time and count from tickets."""
        total_time = 0
        count = 0

        for ticket in tickets:
            custom_fields = ticket.get('CustomFields', {})
            duration = None

            if 'timetorespond' in custom_fields:
                duration = custom_fields['timetorespond']['totalDuration']
            elif 'responsesla' in custom_fields:
                duration = custom_fields['responsesla']['totalDuration']

            if duration is not None:
                total_time += duration
                count += 1

        return total_time, count

    @staticmethod
    def calculate_containment_times(tickets):
        """Calculate containment times for tickets with hostnames."""
        tickets_with_host = [
            t for t in tickets
            if t.get('CustomFields', {}).get('hostname')
        ]

        total_time = 0
        count = 0

        for ticket in tickets_with_host:
            custom_fields = ticket.get('CustomFields', {})
            duration = None

            if 'timetocontain' in custom_fields:
                duration = custom_fields['timetocontain']['totalDuration']
            elif 'containmentsla' in custom_fields:
                duration = custom_fields['containmentsla']['totalDuration']

            if duration is not None:
                total_time += duration
                count += 1

        return total_time, count

    @staticmethod
    def safe_divide(numerator, denominator):
        """Safely divide, returning 0 if denominator is 0."""
        return numerator / denominator if denominator > 0 else 0

    @staticmethod
    def convert_to_minutes(milliseconds):
        """Convert milliseconds to minutes, rounded to 1 decimal."""
        return round(milliseconds / 60000, 1)


def get_shift_ticket_metrics(days_back, shift_start_hour):
    """Get ticket metrics for a specific shift period."""
    try:
        period = TicketMetricsCalculator.create_shift_period(days_back, shift_start_hour)
        incident_fetcher = TicketHandler()

        # Get tickets
        inflow = incident_fetcher.get_tickets(query=BASE_QUERY, period=period)
        outflow = incident_fetcher.get_tickets(query=BASE_QUERY + ' status:closed', period=period)

        # Calculate metrics
        total_response_time, response_count = TicketMetricsCalculator.calculate_response_times(inflow)
        total_contain_time, contain_count = TicketMetricsCalculator.calculate_containment_times(inflow)

        return {
            'tickets_inflow': len(inflow),
            'tickets_closed': len(outflow),
            'mean_response_time': TicketMetricsCalculator.safe_divide(total_response_time, response_count),
            'mean_contain_time': TicketMetricsCalculator.safe_divide(total_contain_time, contain_count),
            'response_time_minutes': TicketMetricsCalculator.convert_to_minutes(
                TicketMetricsCalculator.safe_divide(total_response_time, response_count)
            ),
            'contain_time_minutes': TicketMetricsCalculator.convert_to_minutes(
                TicketMetricsCalculator.safe_divide(total_contain_time, contain_count)
            )
        }
    except Exception as e:
        logger.error(f"Error getting ticket metrics: {e}")
        return {
            'tickets_inflow': 0,
            'tickets_closed': 0,
            'mean_response_time': 0,
            'mean_contain_time': 0,
            'response_time_minutes': 0,
            'contain_time_minutes': 0
        }


class SecurityActionsCalculator:
    """Handles security actions calculations."""

    @staticmethod
    def count_domains_in_period(start_time, end_time):
        """Count domains blocked during a specific time period."""
        try:
            domain_list = list_handler.get_list_data_by_name(config.xsoar_domain_blocking_list_name)
            if not domain_list:
                return 0

            count = 0
            for item in domain_list:
                if 'modified' not in item:
                    continue

                modified_time = safe_parse_datetime(item['modified'])
                if modified_time and start_time <= modified_time <= end_time:
                    count += 1

            return count
        except Exception as e:
            logger.error(f"Error counting domain blocks: {e}")
            return 0

    @staticmethod
    def calculate_shift_time_bounds(days_back, shift_start_hour):
        """Calculate start and end times for a shift period."""
        shift_start = datetime.now() - timedelta(hours=(days_back * 24) + (24 - shift_start_hour))
        shift_end = datetime.now() - timedelta(hours=(days_back * 24) + (16 - shift_start_hour))
        return shift_start, shift_end


def get_shift_security_actions(days_back, shift_start_hour):
    """Get security actions data for a specific shift period."""
    try:
        period = TicketMetricsCalculator.create_shift_period(days_back, shift_start_hour)
        incident_fetcher = TicketHandler()

        # Get malicious true positives
        malicious_tp = incident_fetcher.get_tickets(
            query=BASE_QUERY + ' status:closed impact:"Malicious True Positive"',
            period=period
        )

        # Count domain blocks during shift
        shift_start, shift_end = SecurityActionsCalculator.calculate_shift_time_bounds(
            days_back, shift_start_hour
        )
        domain_blocks = SecurityActionsCalculator.count_domains_in_period(shift_start, shift_end)

        return {
            'malicious_true_positives': len(malicious_tp),
            'domains_blocked': domain_blocks,
            'iocs_blocked': domain_blocks  # For now, using domain blocks as IOCs
        }
    except Exception as e:
        logger.error(f"Error getting security actions: {e}")
        return {
            'malicious_true_positives': 0,
            'domains_blocked': 0,
            'iocs_blocked': 0
        }


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
                        Fact(title="Shift Lead", value=previous_shift_staffing_data['senior_analysts'][0]),
                        Fact(title="Tickets ack'ed", value=str(len(inflow))),
                        Fact(title="Tickets closed",
                             value=f"{len(outflow)} ({tickets_closed_per_analyst:.2f}/analyst)"),
                        Fact(title="MTPs",
                             value=', '.join([ticket['id'] for ticket in malicious_true_positives])),
                        Fact(title="SLA Breaches",
                             value=f"Resp- {len(response_sla_breaches)} [{', '.join(['X#' + breach['id'] for breach in response_sla_breaches])}]\n"
                                   f"Cont- {len(containment_sla_breaches)} [{', '.join(['X#' + breach['id'] for breach in containment_sla_breaches])}]"),
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


class ShiftChangeFormatter:
    """Handles formatting and data preparation for shift change announcements."""

    @staticmethod
    def mark_shift_lead(staffing_data):
        """Mark the first senior analyst as shift lead."""
        if 'senior_analysts' in staffing_data and staffing_data['senior_analysts']:
            staffing_data['senior_analysts'][0] += ' (Lead)'
        return staffing_data

    @staticmethod
    def pad_staffing_data(staffing_data):
        """Pad all staffing lists to same length for table formatting."""
        max_len = max(len(v) for v in staffing_data.values()) if staffing_data else 0

        for k, v in staffing_data.items():
            padded_list = [(i if i is not None else '') for i in v]
            padded_list.extend([''] * (max_len - len(padded_list)))
            staffing_data[k] = padded_list

        return staffing_data

    @staticmethod
    def create_staffing_table(staffing_data):
        """Create a formatted table from staffing data."""
        headers = list(staffing_data.keys())
        data_rows = list(zip(*staffing_data.values()))
        return tabulate(data_rows, headers=headers, tablefmt="simple")

    @staticmethod
    def get_management_notes():
        """Get current management notes if still valid."""
        try:
            with open(MANAGEMENT_NOTES_FILE, "r") as file:
                management_notes = json.loads(file.read())
                keep_until = datetime.strptime(management_notes['keep_until'], '%Y-%m-%d').date()
                if date.today() <= keep_until:
                    return management_notes['note']
        except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Error reading management notes: {e}")
        return ''

    @staticmethod
    def format_containment_duration(contained_at):
        """Format time under containment as 'X D, Y H'."""
        if not contained_at:
            return "Unknown"

        time_delta = datetime.now() - contained_at
        days = time_delta.days
        hours = time_delta.seconds // 3600
        return f"{days} D, {hours} H"

    @staticmethod
    def get_hosts_in_containment():
        """Get formatted list of hosts currently in containment."""
        hosts_data = list_handler.get_list_data_by_name(f'{config.team_name} Contained Hosts')

        formatted_hosts = []
        for item in hosts_data:
            contained_at = safe_parse_datetime(item.get("contained_at"))
            time_under_containment = ShiftChangeFormatter.format_containment_duration(contained_at)

            formatted_host = (
                f"X#{item.get('ticket#', 'N/A')} | "
                f"{item.get('hostname', 'Unknown')} | "
                f"{time_under_containment}"
            )
            formatted_hosts.append(formatted_host)

        return formatted_hosts

    @staticmethod
    def get_shift_timings(shift_name):
        """Get shift timing information from Excel."""
        if not EXCEL_AVAILABLE or sheet is None:
            return "N/A (Excel file missing)"

        try:
            cell = sheet[cell_names_by_shift['shift_timings'][shift_name]]
            return getattr(cell, 'value', "N/A (Excel cell missing)") if cell else "N/A (Excel cell missing)"
        except (KeyError, TypeError):
            return "N/A (Excel file issue)"

    @staticmethod
    def prepare_shift_data(shift_name):
        """Prepare all data needed for shift change announcement."""
        day_name = datetime.now().strftime("%A")

        # Get and format staffing data
        staffing_data = get_staffing_data(day_name, shift_name)
        staffing_data = ShiftChangeFormatter.mark_shift_lead(staffing_data)
        staffing_data = ShiftChangeFormatter.pad_staffing_data(staffing_data)
        staffing_table = ShiftChangeFormatter.create_staffing_table(staffing_data)

        return {
            'shift_timings': ShiftChangeFormatter.get_shift_timings(shift_name),
            'management_notes': ShiftChangeFormatter.get_management_notes(),
            'hosts_in_containment': ShiftChangeFormatter.get_hosts_in_containment(),
            'staffing_table': staffing_table
        }


def _create_shift_change_message(shift_name, shift_data):
    """Create the markdown message for shift change announcement."""
    hosts_text = '\n'.join(shift_data['hosts_in_containment']) if shift_data['hosts_in_containment'] else ''

    return (
        f"Good **{shift_name.upper()}**! A new shift's starting now!\n"
        f"Timings: {shift_data['shift_timings']}\n"
        f"Open {config.team_name}* tickets: {get_open_tickets()}\n"
        f"Hosts in Containment (TUC): \n{hosts_text}\n\n"
        f"**Management Notes**: {shift_data['management_notes']}\n"
        f"Staffing:\n"
        f"```\n{shift_data['staffing_table']}\n```"
    )


@retry(
    reraise=True,
    stop=stop_after_attempt(3),  # Retry up to 3 times
    wait=wait_exponential(multiplier=2, min=2, max=10),  # Exponential backoff
    before_sleep=before_sleep_log(logger, logging.WARNING),
)
def announce_shift_change(shift_name, room_id, sleep_time=30):
    """Announce the change of shift in the Webex room."""
    try:
        # Prepare all shift data
        shift_data = ShiftChangeFormatter.prepare_shift_data(shift_name)

        # Create and send message
        message_text = _create_shift_change_message(shift_name, shift_data)
        webex_api.messages.create(
            roomId=room_id,
            text="Shift Change Notice!",
            markdown=message_text
        )

        # Wait before sending performance message
        time.sleep(sleep_time)
        announce_previous_shift_performance(shift_name=shift_name, room_id=room_id)

    except (requests_exceptions.ConnectionError, urllib3_exceptions.ProtocolError) as net_err:
        logger.error(f"Network error in announce_shift_change: {net_err}")
        raise  # Reraise to trigger retry
    except Exception as e:
        logger.error(f"Error in announce_shift_change: {e}")
        traceback.print_exc()


def main():
    """Main function to run the scheduled jobs."""
    room_id = config.webex_room_id_vinay_test_space
    announce_shift_change('night', room_id, sleep_time=0)
    print(get_staffing_data())


if __name__ == "__main__":
    main()
