"""
SecOps Announcements

Handles Webex announcements for shift changes, performance reports, and daily charts.
"""
import json
import logging
import random
import time
import traceback
from datetime import date, datetime, timedelta
from typing import Any, Dict, List

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
from services.xsoar import TicketHandler, ListHandler, XsoarEnvironment
from src.charts.threatcon_level import load_threatcon_data, THREAT_CON_FILE
from .constants import (
    config,
    root_directory,
    MANAGEMENT_NOTES_FILE,
    DOR_CHART_MESSAGES,
    SHIFT_PERFORMANCE_MESSAGES,
    SHIFT_CHANGE_MESSAGES,
    CHART_NOT_FOUND_MESSAGES,
)
from .metrics import get_open_tickets, BASE_QUERY
from .shift_utils import safe_parse_datetime, get_eastern_timezone
from .staffing import get_staffing_data, get_shift_timings

logger = logging.getLogger(__name__)
CONFIG = get_config()
ROOM_ID = CONFIG.webex_room_id_vinay_test_space


def get_region_wise_ticket_counts() -> str:
    """
    Generate a formatted table of region-wise ticket counts.

    Returns:
        ASCII table formatted with texttable, wrapped in code blocks for Webex
    """
    from texttable import Texttable

    try:
        ticket_handler = TicketHandler(XsoarEnvironment.PROD)

        # Get all open tickets (not closed)
        open_tickets = ticket_handler.get_tickets(query=BASE_QUERY + ' -status:closed')

        # Get closed incidents with MTP impact (yesterday)
        yesterday = datetime.now() - timedelta(days=1)
        start_of_yesterday = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)
        end_of_yesterday = yesterday.replace(hour=23, minute=59, second=59, microsecond=0)
        time_format = '%Y-%m-%dT%H:%M:%S'
        closed_filter = f'closed:>="{start_of_yesterday.strftime(time_format)}" closed:<="{end_of_yesterday.strftime(time_format)}"'

        closed_mtp = ticket_handler.get_tickets(
            query=BASE_QUERY + f' status:closed CustomFields.impact:"Malicious True Positive" {closed_filter}'
        )

        # Define regions in display order
        regions = ['AMERICAS', 'APAC', 'EMEA', 'GLOBAL', 'LATAM']

        # Count open tickets by region
        open_by_region = {r: 0 for r in regions}
        for ticket in open_tickets:
            region = ticket.get('CustomFields', {}).get('affectedregion', '').upper()
            if region in open_by_region:
                open_by_region[region] += 1

        # Count closed MTP incidents by region
        closed_by_region = {r: 0 for r in regions}
        for ticket in closed_mtp:
            region = ticket.get('CustomFields', {}).get('affectedregion', '').upper()
            if region in closed_by_region:
                closed_by_region[region] += 1

        # Calculate totals
        total_open = sum(open_by_region.values())
        total_closed = sum(closed_by_region.values())

        # Determine max digit width for each column (including total)
        all_open = list(open_by_region.values()) + [total_open]
        all_closed = list(closed_by_region.values()) + [total_closed]
        open_width = len(str(max(all_open)))
        closed_width = len(str(max(all_closed)))

        # Build table using texttable
        table = Texttable()
        table.set_deco(Texttable.HEADER | Texttable.VLINES)
        table.set_cols_align(['l', 'c', 'c'])
        table.set_cols_width([10, 14, 18])
        table.header(['Region', 'Open Tickets', 'Closed Incidents'])

        for region in regions:
            open_count = str(open_by_region[region]).zfill(open_width)
            closed_count = str(closed_by_region[region]).zfill(closed_width)
            table.add_row([region, open_count, closed_count])

        table.add_row(['Total', str(total_open).zfill(open_width), str(total_closed).zfill(closed_width)])

        return f"```\n{table.draw()}\n```"

    except Exception as e:
        logger.error(f"Error generating region-wise ticket counts: {e}")
        return "Unable to generate region-wise ticket counts"

# Webex API client
webex_api = WebexAPI(config.webex_bot_access_token_moneyball, disable_ssl_verify=True, single_request_timeout=180)

# Production list handler
prod_list_handler = ListHandler(XsoarEnvironment.PROD)


class ShiftChangeFormatter:
    """Handles formatting and data preparation for shift change announcements."""

    @staticmethod
    def mark_shift_lead(staffing_data: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """Mark the first senior analyst as shift lead."""
        if 'senior_analysts' in staffing_data and staffing_data['senior_analysts']:
            staffing_data['senior_analysts'][0] += ' (Lead)'
        return staffing_data

    @staticmethod
    def pad_staffing_data(staffing_data: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """Pad all staffing lists to same length for table formatting."""
        max_len = max(len(v) for v in staffing_data.values()) if staffing_data else 0

        for k, v in staffing_data.items():
            padded_list = [(i if i is not None else '') for i in v]
            padded_list.extend([''] * (max_len - len(padded_list)))
            staffing_data[k] = padded_list

        return staffing_data

    @staticmethod
    def create_staffing_table(staffing_data: Dict[str, List[str]]) -> str:
        """Create a formatted table from staffing data."""
        headers = list(staffing_data.keys())
        data_rows = list(zip(*staffing_data.values()))
        return tabulate(data_rows, headers=headers, tablefmt="simple")

    @staticmethod
    def get_management_notes() -> str:
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
    def format_containment_duration(contained_at: datetime) -> str:
        """Format time under containment as 'X D, Y H'."""
        if not contained_at:
            return "Unknown"

        time_delta = datetime.now() - contained_at
        days = time_delta.days
        hours = time_delta.seconds // 3600
        return f"{days} D, {hours} H"

    @staticmethod
    def get_hosts_in_containment() -> List[str]:
        """Get formatted list of hosts currently in containment."""
        hosts_data = prod_list_handler.get_list_data_by_name(f'{config.team_name} Contained Hosts')

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
    def prepare_shift_data(shift_name: str) -> Dict[str, Any]:
        """Prepare all data needed for shift change announcement."""
        eastern = get_eastern_timezone()
        day_name = datetime.now(eastern).strftime("%A")

        # Get and format staffing data
        staffing_data = get_staffing_data(day_name, shift_name)
        staffing_data = ShiftChangeFormatter.mark_shift_lead(staffing_data)
        staffing_data = ShiftChangeFormatter.pad_staffing_data(staffing_data)
        staffing_table = ShiftChangeFormatter.create_staffing_table(staffing_data)

        return {
            'shift_timings': get_shift_timings(shift_name),
            'management_notes': ShiftChangeFormatter.get_management_notes(),
            'hosts_in_containment': ShiftChangeFormatter.get_hosts_in_containment(),
            'staffing_table': staffing_table
        }


def _create_shift_change_message(shift_name: str, shift_data: Dict[str, Any]) -> str:
    """Create the Markdown message for shift change announcement."""
    try:
        hosts_text = '\n'.join(shift_data.get('hosts_in_containment', [])) if shift_data.get('hosts_in_containment') else ''

        return (
            f"Good **{shift_name.upper()}**! A new shift's starting now!\n"
            f"Timings: {shift_data['shift_timings']}\n"
            f"Open {config.team_name}* tickets: {get_open_tickets()}\n"
            f"Hosts in Containment (TUC): \n{hosts_text}\n\n"
            f"**Management Notes**: {shift_data['management_notes']}\n"
            f"Scheduled Staffing:\n"
            f"```\n{shift_data['staffing_table']}\n```"
        )
    except Exception as e:
        logger.error(f"Error in _create_shift_change_message: {e}")
        return f"Good **{shift_name.upper()}**! A new shift's starting now!\n\nUnable to fetch shift details due to an error."


@retry(
    reraise=False,  # Don't crash the caller - log and continue
    stop=stop_after_attempt(3),  # Retry up to 3 times
    wait=wait_exponential(multiplier=2, min=2, max=10),  # Exponential backoff
    before_sleep=before_sleep_log(logger, logging.WARNING),
)
def announce_previous_shift_performance(room_id: str, shift_name: str) -> None:
    """Announce the performance of the previous shift in the Webex room using EXACT timestamps."""
    try:
        # Determine previous shift
        previous_shift_mapping = {
            'morning': ('night', 1),  # Previous night (yesterday)
            'afternoon': ('morning', 0),  # This morning
            'night': ('afternoon', 0),  # This afternoon
        }

        if shift_name not in previous_shift_mapping:
            logger.error(f"Invalid shift_name: {shift_name}")
            return

        prev_shift_name, days_back = previous_shift_mapping[shift_name]
        eastern = get_eastern_timezone()
        target_date = datetime.now(eastern) - timedelta(days=days_back)
        day_name = target_date.strftime("%A")

        # Get shift metrics using the component
        incident_fetcher = TicketHandler(XsoarEnvironment.PROD)
        base_date = datetime(target_date.year, target_date.month, target_date.day)

        # Calculate exact shift window for additional queries
        shift_hour_map = {'morning': 4.5, 'afternoon': 12.5, 'night': 20.5}
        shift_start_hour = shift_hour_map[prev_shift_name]
        start_hour_int = int(shift_start_hour)
        start_minute = int((shift_start_hour % 1) * 60)

        start_dt_naive = datetime(base_date.year, base_date.month, base_date.day, start_hour_int, start_minute)
        start_dt = eastern.localize(start_dt_naive)
        end_dt = start_dt + timedelta(hours=8)

        time_format = '%Y-%m-%dT%H:%M:%S %z'
        start_str = start_dt.strftime(time_format)
        end_str = end_dt.strftime(time_format)
        time_filter = f'created:>="{start_str}" created:<="{end_str}"'

        # Get tickets with exact timestamps
        inflow = incident_fetcher.get_tickets(query=f'{BASE_QUERY} {time_filter}')
        outflow = incident_fetcher.get_tickets(query=f'{BASE_QUERY} {time_filter} status:closed')
        malicious_true_positives = incident_fetcher.get_tickets(
            query=f'{BASE_QUERY} {time_filter} impact:"Malicious True Positive"'
        )
        response_sla_breaches = incident_fetcher.get_tickets(
            query=f'{BASE_QUERY} {time_filter} timetorespond.slaStatus:late'
        )
        containment_sla_breaches = incident_fetcher.get_tickets(
            query=f'{BASE_QUERY} {time_filter} timetocontain.slaStatus:late'
        )

        # Calculate mean times
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

        # Get staffing data for previous shift
        previous_shift_staffing_data = get_staffing_data(day_name, prev_shift_name)

        # Use exact shift window for IOCs/domains/hosts comparison (naive datetime)
        shift_start_naive = start_dt.replace(tzinfo=None)
        shift_end_naive = end_dt.replace(tzinfo=None)

        # Process domains blocked during shift window
        all_domains = prod_list_handler.get_list_data_by_name(f'{config.team_name} Blocked Domains')
        domains_blocked = []
        for item in all_domains:
            if 'blocked_at' in item:
                item_datetime = safe_parse_datetime(item['blocked_at'])
                if item_datetime and shift_start_naive <= item_datetime <= shift_end_naive:
                    domains_blocked.append(item['domain'])

        # Process IP addresses blocked during shift window
        all_ips = prod_list_handler.get_list_data_by_name(f'{config.team_name} Blocked IP Addresses')
        ip_addresses_blocked = []
        for item in all_ips:
            if 'blocked_at' in item:
                item_datetime = safe_parse_datetime(item['blocked_at'])
                if item_datetime and shift_start_naive <= item_datetime <= shift_end_naive:
                    ip_addresses_blocked.append(item['ip_address'])

        # Process hosts contained during shift window
        all_hosts = prod_list_handler.get_list_data_by_name(f'{config.team_name} Contained Hosts')
        hosts_contained_list = []
        for item in all_hosts:
            if 'contained_at' in item:
                item_datetime = safe_parse_datetime(item['contained_at'])
                if item_datetime and shift_start_naive <= item_datetime <= shift_end_naive:
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
                             value=f"{len(outflow)}"),
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
        fun_message = random.choice(SHIFT_PERFORMANCE_MESSAGES)
        webex_api.messages.create(
            roomId=room_id,
            text=fun_message,
            attachments=[{"contentType": "application/vnd.microsoft.card.adaptive", "content": shift_performance.to_dict()}]
        )
    except Exception as e:
        print(f"Error in announce_previous_shift_performance: {e}")
        traceback.print_exc()


@retry(
    reraise=False,  # Don't crash the caller - log and continue
    stop=stop_after_attempt(3),  # Retry up to 3 times
    wait=wait_exponential(multiplier=2, min=2, max=10),  # Exponential backoff
    before_sleep=before_sleep_log(logger, logging.WARNING),
)
def announce_shift_change(shift_name: str, room_id: str, sleep_time: int = 30) -> None:
    """Announce the change of shift in the Webex room."""
    try:
        # Prepare all shift data
        shift_data = ShiftChangeFormatter.prepare_shift_data(shift_name)

        # Create and send message
        message_text = _create_shift_change_message(shift_name, shift_data)
        fun_message = random.choice(SHIFT_CHANGE_MESSAGES)
        webex_api.messages.create(
            roomId=room_id,
            text=fun_message,
            markdown=message_text
        )

        # Wait before sending performance message
        time.sleep(sleep_time)
        announce_previous_shift_performance(shift_name=shift_name, room_id=room_id)

    except (requests_exceptions.ConnectionError, urllib3_exceptions.ProtocolError, requests_exceptions.ReadTimeout) as net_err:
        logger.error(f"Network error in announce_shift_change: {net_err}")
        raise  # Reraise to trigger retry (tenacity will catch and handle)
    except Exception as e:
        logger.error(f"Error in announce_shift_change: {e}")
        traceback.print_exc()
        raise  # Reraise to trigger retry for non-network errors too


def send_daily_operational_report_charts(room_id: str = None) -> None:
    """Send daily operational report charts to Webex room with retry logic for VM network timeouts."""
    if room_id is None:
        room_id = ROOM_ID

    logger.info("📊 Starting daily operational report chart distribution")

    def send_chart_with_retry(room_id: str, text: str, markdown: str, files: List[str] = None, max_retries: int = 3):
        """Send chart with exponential backoff retry for network timeout errors"""
        from requests.exceptions import ConnectionError, Timeout

        for attempt in range(max_retries):
            try:
                webex_api.messages.create(
                    roomId=room_id,
                    text=text,
                    markdown=markdown,
                    files=files if files else None
                )
                return  # Success
            except (ConnectionError, Timeout, TimeoutError) as e:
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
                    logger.warning(f"⚠️  Chart upload timeout (attempt {attempt+1}/{max_retries}): {e}. Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    logger.error(f"❌ Chart upload failed after {max_retries} attempts: {e}")
                    raise

    try:
        today = datetime.today()
        charts_dir = root_directory / 'web' / 'static' / 'charts'
        date_str = today.strftime('%m-%d-%Y')
        secops_charts_path = charts_dir / date_str
        dor_charts = [
            'Aging Tickets.png',
            'MTTR MTTC.png',
            'SLA Breaches.png',
            'Inflow Yesterday.png',
            'Outflow Yesterday.png',
            'Open vs Closed - Past 60 Days.png',
            'Open vs Closed - 12 Month Trend.png',
        ]

        # Add ThreatCon chart only if level is not green
        try:
            threatcon_data = load_threatcon_data(THREAT_CON_FILE)
            if threatcon_data.get('level', 'green').lower() != 'green':
                dor_charts.append('Threatcon Level.png')
                logger.info(f"🚨 ThreatCon level is {threatcon_data['level'].upper()} - including chart")
        except Exception as tc_err:
            logger.warning(f"Could not check ThreatCon level: {tc_err}")

        for chart in dor_charts:
            chart_path = secops_charts_path / chart
            if chart_path.exists():
                fun_message = random.choice(DOR_CHART_MESSAGES)
                chart_title = chart.replace('.png', '')
                send_chart_with_retry(
                    room_id=room_id,
                    text=f"{fun_message} - {chart_title}",
                    markdown=f"{fun_message}\n\n📊 **{chart_title}**",
                    files=[str(chart_path)]
                )
                logger.info(f"✅ Sent chart: {chart_title}")
            else:
                logger.warning(f"Chart file not found: {chart_path}")
                ouch_message = random.choice(CHART_NOT_FOUND_MESSAGES)
                chart_title = chart.replace('.png', '')
                send_chart_with_retry(
                    room_id=room_id,
                    text=f"{ouch_message} - Missing: {chart_title}",
                    markdown=f"{ouch_message}\n\n**Missing:** {chart_title}"
                )

        logger.info(f"📊 Completed daily operational report chart distribution ({len(dor_charts)} charts processed)")

        # Send region-wise ticket count table
        try:
            region_table = get_region_wise_ticket_counts()
            send_chart_with_retry(
                room_id=room_id,
                text="Region-wise Ticket Count",
                markdown=f"📋 **Region-wise Ticket Count**\n\n{region_table}"
            )
            logger.info("✅ Sent region-wise ticket count table")
        except Exception as table_error:
            logger.error(f"Error sending region-wise table: {table_error}")

    except Exception as e:
        logger.error(f"Error in send_daily_operational_report_charts: {e}")
        traceback.print_exc()


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Test announcements to Vinay test space')
    parser.add_argument('--dor', action='store_true', help='Send DOR charts and region table')
    args = parser.parse_args()

    if not args.dor:
        print("Usage: python -m src.secops.announcements --dor")
        print("\nTests will be sent to Vinay test space (ROOM_ID)")
        exit(1)

    print(f"🧪 Testing announcements to test space...")
    print("\n📊 Sending DOR charts and region table...")
    send_daily_operational_report_charts()
