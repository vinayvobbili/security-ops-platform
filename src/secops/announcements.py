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
    AdaptiveCard, HorizontalAlignment, VerticalContentAlignment,
    FactSet, Fact, Container, ColumnSet, Column, options
)
from webexpythonsdk.models.cards.actions import OpenUrl

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
    ShiftConstants,
)
from .metrics import get_open_tickets, BASE_QUERY
from .shift_utils import safe_parse_datetime, get_eastern_timezone
from .staffing import get_staffing_data, get_shift_timings

logger = logging.getLogger(__name__)
CONFIG = get_config()
ROOM_ID = CONFIG.webex_room_id_dev_test_space


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
webex_api = WebexAPI(config.webex_bot_access_token_oracle, disable_ssl_verify=True, single_request_timeout=180)

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
    def get_hosts_in_containment_raw() -> List[Dict[str, str]]:
        """Get raw host data for Adaptive Card display with hyperlinks."""
        hosts_data = prod_list_handler.get_list_data_by_name(f'{config.team_name} Contained Hosts')

        hosts = []
        for item in hosts_data:
            contained_at = safe_parse_datetime(item.get("contained_at"))
            ticket_id = item.get('ticket#', 'N/A')
            hosts.append({
                'ticket_id': ticket_id,
                'ticket_url': f"{config.xsoar_prod_ui_base_url}/Custom/caseinfoid/{ticket_id}",
                'hostname': item.get('hostname', 'Unknown'),
                'duration': ShiftChangeFormatter.format_containment_duration(contained_at),
            })
        return hosts

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
            'hosts_raw': ShiftChangeFormatter.get_hosts_in_containment_raw(),
            'staffing_table': staffing_table,
            'staffing_data': staffing_data,
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


def _get_open_ticket_summary() -> Dict[str, Any]:
    """Get open ticket count and first N IDs for Adaptive Card display."""
    try:
        all_tickets = TicketHandler(XsoarEnvironment.PROD).get_tickets(query=BASE_QUERY + ' -status:closed')
        total = len(all_tickets)
        show_count = min(total, ShiftConstants.TICKET_SHOW_COUNT)
        ids = [ticket['id'] for ticket in all_tickets[:show_count]]
        remaining = total - show_count
        ids_text = ', '.join(ids)
        if remaining > 0:
            ids_text += f" and {remaining} more"
        return {'total': total, 'ids_text': ids_text}
    except Exception as e:
        logger.error(f"Error in _get_open_ticket_summary: {e}")
        return {'total': 0, 'ids_text': 'Unable to fetch'}


def _create_shift_change_card(shift_name: str, shift_data: Dict[str, Any]) -> AdaptiveCard:
    """Create an Adaptive Card for the shift change announcement."""
    shift_emojis = {'morning': '☀️', 'afternoon': '🌤️', 'night': '🌙'}
    shift_greetings = {'morning': 'Good Morning', 'afternoon': 'Good Afternoon', 'night': 'Good Night'}
    shift_emoji = shift_emojis.get(shift_name, '🔔')
    greeting = shift_greetings.get(shift_name, 'Shift Change')

    eastern = get_eastern_timezone()
    today_str = datetime.now(eastern).strftime('%b %d, %Y')

    # ── Header ─────────────────────────────────────────────────
    header = Container(
        style=options.ContainerStyle.ACCENT,
        bleed=True,
        items=[
            TextBlock(
                text=f"{shift_emoji} {greeting}!",
                weight=FontWeight.BOLDER,
                size=FontSize.LARGE,
                color=Colors.LIGHT,
                horizontalAlignment=HorizontalAlignment.CENTER,
            ),
            TextBlock(
                text=f"A new shift's starting now! · {today_str}",
                size=FontSize.SMALL,
                color=Colors.LIGHT,
                horizontalAlignment=HorizontalAlignment.CENTER,
                spacing=options.Spacing.NONE,
            ),
        ]
    )

    # ── Shift Info ─────────────────────────────────────────────
    info_section = FactSet(
        separator=True,
        facts=[
            Fact(title="⏰ Timings", value=shift_data['shift_timings']),
        ]
    )

    # ── Open Tickets & Containment (big numbers) ───────────────
    ticket_summary = _get_open_ticket_summary()
    hosts_raw = shift_data.get('hosts_raw', [])

    stats = ColumnSet(
        spacing=options.Spacing.MEDIUM,
        columns=[
            Column(
                width="stretch",
                verticalContentAlignment=VerticalContentAlignment.CENTER,
                items=[
                    TextBlock(
                        text=str(ticket_summary['total']),
                        size=FontSize.EXTRA_LARGE,
                        weight=FontWeight.BOLDER,
                        color=Colors.ACCENT,
                        horizontalAlignment=HorizontalAlignment.CENTER,
                    ),
                    TextBlock(
                        text="Open Tickets",
                        size=FontSize.SMALL,
                        weight=FontWeight.BOLDER,
                        horizontalAlignment=HorizontalAlignment.CENTER,
                        spacing=options.Spacing.NONE,
                    ),
                ],
            ),
            Column(
                width="stretch",
                verticalContentAlignment=VerticalContentAlignment.CENTER,
                items=[
                    TextBlock(
                        text=str(len(hosts_raw)),
                        size=FontSize.EXTRA_LARGE,
                        weight=FontWeight.BOLDER,
                        color=Colors.ATTENTION if hosts_raw else Colors.GOOD,
                        horizontalAlignment=HorizontalAlignment.CENTER,
                    ),
                    TextBlock(
                        text="In Containment",
                        size=FontSize.SMALL,
                        weight=FontWeight.BOLDER,
                        horizontalAlignment=HorizontalAlignment.CENTER,
                        spacing=options.Spacing.NONE,
                    ),
                ],
            ),
        ]
    )

    body = [header, info_section, stats]

    # ── Hosts in Containment detail ────────────────────────────
    hosts_raw = shift_data.get('hosts_raw', [])
    if hosts_raw:
        containment_header = TextBlock(
            text="🔒 Hosts in Containment (TUC)",
            weight=FontWeight.BOLDER,
            size=FontSize.SMALL,
            separator=True,
        )
        body.append(containment_header)

        # Column headers
        col_widths = ("2", "3", "2")  # fixed weights so headers align with data rows
        body.append(ColumnSet(
            spacing=options.Spacing.SMALL,
            columns=[
                Column(width=col_widths[0], items=[
                    TextBlock(text="Ticket", weight=FontWeight.BOLDER, size=FontSize.SMALL, color=Colors.ACCENT),
                ]),
                Column(width=col_widths[1], items=[
                    TextBlock(text="Hostname", weight=FontWeight.BOLDER, size=FontSize.SMALL, color=Colors.ACCENT),
                ]),
                Column(width=col_widths[2], items=[
                    TextBlock(text="Duration", weight=FontWeight.BOLDER, size=FontSize.SMALL, color=Colors.ACCENT),
                ]),
            ]
        ))

        # One row per host — ticket column is clickable
        for host in hosts_raw:
            body.append(ColumnSet(
                spacing=options.Spacing.NONE,
                columns=[
                    Column(
                        width=col_widths[0],
                        selectAction=OpenUrl(url=host['ticket_url']),
                        items=[
                            TextBlock(
                                text=f"X#{host['ticket_id']}",
                                size=FontSize.SMALL,
                                color=Colors.ACCENT,
                            ),
                        ]
                    ),
                    Column(width=col_widths[1], items=[
                        TextBlock(text=host['hostname'], size=FontSize.SMALL),
                    ]),
                    Column(width=col_widths[2], items=[
                        TextBlock(text=host['duration'], size=FontSize.SMALL, isSubtle=True),
                    ]),
                ]
            ))

    # ── Management Notes ───────────────────────────────────────
    notes = shift_data.get('management_notes', '')
    if notes:
        notes_section = Container(
            separator=True,
            items=[
                TextBlock(
                    text="📋 Management Notes",
                    weight=FontWeight.BOLDER,
                    size=FontSize.SMALL,
                ),
                TextBlock(
                    text=notes,
                    size=FontSize.SMALL,
                    wrap=True,
                    spacing=options.Spacing.SMALL,
                ),
            ]
        )
        body.append(notes_section)

    # ── Staffing ───────────────────────────────────────────────
    staffing_data = shift_data.get('staffing_data', {})
    if staffing_data:
        role_labels = {
            'monitoring_analysts': '🖥️ Monitoring',
            'response_analysts': '🔍 Response',
            'senior_analysts': '⭐ Senior',
            'On-Call': '📱 On-Call',
        }
        staffing_columns = []
        for role, members in staffing_data.items():
            display_role = role_labels.get(role, role.replace('_', ' ').title())
            members_text = '\n'.join(m for m in members if m)
            staffing_columns.append(
                Column(
                    width="stretch",
                    items=[
                        TextBlock(
                            text=display_role,
                            weight=FontWeight.BOLDER,
                            size=FontSize.SMALL,
                            color=Colors.ACCENT,
                        ),
                        TextBlock(
                            text=members_text or "—",
                            size=FontSize.SMALL,
                            wrap=True,
                            spacing=options.Spacing.SMALL,
                        ),
                    ]
                )
            )

        staffing_header = TextBlock(
            text="👥 Scheduled Staffing",
            weight=FontWeight.BOLDER,
            size=FontSize.SMALL,
            separator=True,
        )
        staffing_grid = ColumnSet(
            columns=staffing_columns,
            spacing=options.Spacing.SMALL,
        )
        body.append(staffing_header)
        body.append(staffing_grid)

    return AdaptiveCard(body=body)


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

        # Extract per-analyst ack/closed counts from ticket owners
        ack_counts = {}
        closed_counts = {}
        all_owners = set()
        for ticket in inflow:
            owner = ticket.get('owner', '').strip()
            if owner and owner.lower() not in ('', 'unassigned', 'admin'):
                name = owner.split('@')[0]
                all_owners.add(name)
                ack_counts[name] = ack_counts.get(name, 0) + 1
        for ticket in outflow:
            owner = ticket.get('owner', '').strip()
            if owner and owner.lower() not in ('', 'unassigned', 'admin'):
                name = owner.split('@')[0]
                all_owners.add(name)
                closed_counts[name] = closed_counts.get(name, 0) + 1
        analysts_str = '\n'.join(
            f"{name} (Ack:{ack_counts.get(name, 0)}, Closed:{closed_counts.get(name, 0)})"
            for name in sorted(all_owners)
        ) if all_owners else ''
        analyst_count = len(all_owners)
        acked_per = f" ({round(len(inflow) / analyst_count, 1)}/analyst)" if analyst_count else ''
        closed_per = f" ({round(len(outflow) / analyst_count, 1)}/analyst)" if analyst_count else ''

        # ── Performance Score ─────────────────────────────────────
        from src.components.secops_shift_metrics import calculate_performance_score, extract_sla_metrics
        sla_metrics = extract_sla_metrics(inflow)
        score = calculate_performance_score(
            len(inflow), len(outflow), sla_metrics, analyst_count
        )

        # ── Header ─────────────────────────────────────────────────
        header = Container(
            style=options.ContainerStyle.ACCENT,
            bleed=True,
            items=[
                TextBlock(
                    text="📊 Previous Shift Performance",
                    weight=FontWeight.BOLDER,
                    size=FontSize.LARGE,
                    color=Colors.LIGHT,
                    horizontalAlignment=HorizontalAlignment.CENTER,
                ),
                TextBlock(
                    text=f"{prev_shift_name.capitalize()} Shift · {target_date.strftime('%b %d, %Y')} · Score: [{score}/10](http://gdnr.the-company.com/shift-performance?shift_id={target_date.strftime('%Y-%m-%d')}_{prev_shift_name})",
                    size=FontSize.SMALL,
                    color=Colors.LIGHT,
                    horizontalAlignment=HorizontalAlignment.CENTER,
                    spacing=options.Spacing.NONE,
                ),
            ]
        )

        # ── Team ──────────────────────────────────────────────────
        seniors = previous_shift_staffing_data.get('senior_analysts') or []
        shift_lead_value = seniors[0] if seniors else "No Lead Assigned"
        team_section = FactSet(
            separator=True,
            facts=[
                Fact(title="👤 Shift Lead", value=shift_lead_value),
                Fact(title="👥 Analysts", value=analysts_str),
            ]
        )

        # ── Key metrics (big numbers) ────────────────────────────
        mtp_ids = ', '.join([
            f"[{ticket['id']}]({config.xsoar_prod_ui_base_url}/Custom/caseinfoid/{ticket['id']})"
            for ticket in malicious_true_positives
        ])
        ticket_stats = ColumnSet(
            separator=True,
            spacing=options.Spacing.MEDIUM,
            columns=[
                Column(
                    width="stretch",
                    verticalContentAlignment=VerticalContentAlignment.CENTER,
                    items=[
                        TextBlock(
                            text=str(len(inflow)),
                            size=FontSize.EXTRA_LARGE,
                            weight=FontWeight.BOLDER,
                            color=Colors.ACCENT,
                            horizontalAlignment=HorizontalAlignment.CENTER,
                        ),
                        TextBlock(
                            text="Ack'ed",
                            size=FontSize.SMALL,
                            weight=FontWeight.BOLDER,
                            horizontalAlignment=HorizontalAlignment.CENTER,
                            spacing=options.Spacing.NONE,
                        ),
                        TextBlock(
                            text=acked_per.strip(),
                            size=FontSize.SMALL,
                            isSubtle=True,
                            horizontalAlignment=HorizontalAlignment.CENTER,
                            spacing=options.Spacing.NONE,
                        ),
                    ],
                ),
                Column(
                    width="stretch",
                    verticalContentAlignment=VerticalContentAlignment.CENTER,
                    items=[
                        TextBlock(
                            text=str(len(outflow)),
                            size=FontSize.EXTRA_LARGE,
                            weight=FontWeight.BOLDER,
                            color=Colors.GOOD,
                            horizontalAlignment=HorizontalAlignment.CENTER,
                        ),
                        TextBlock(
                            text="Closed",
                            size=FontSize.SMALL,
                            weight=FontWeight.BOLDER,
                            horizontalAlignment=HorizontalAlignment.CENTER,
                            spacing=options.Spacing.NONE,
                        ),
                        TextBlock(
                            text=closed_per.strip(),
                            size=FontSize.SMALL,
                            isSubtle=True,
                            horizontalAlignment=HorizontalAlignment.CENTER,
                            spacing=options.Spacing.NONE,
                        ),
                    ],
                ),
                Column(
                    width="stretch",
                    verticalContentAlignment=VerticalContentAlignment.CENTER,
                    items=[
                        TextBlock(
                            text=str(len(malicious_true_positives)),
                            size=FontSize.EXTRA_LARGE,
                            weight=FontWeight.BOLDER,
                            color=Colors.ATTENTION if malicious_true_positives else Colors.DEFAULT,
                            horizontalAlignment=HorizontalAlignment.CENTER,
                        ),
                        TextBlock(
                            text="MTPs",
                            size=FontSize.SMALL,
                            weight=FontWeight.BOLDER,
                            horizontalAlignment=HorizontalAlignment.CENTER,
                            spacing=options.Spacing.NONE,
                        ),
                        TextBlock(
                            text=mtp_ids,
                            size=FontSize.SMALL,
                            isSubtle=True,
                            horizontalAlignment=HorizontalAlignment.CENTER,
                            spacing=options.Spacing.NONE,
                            wrap=True,
                        ),
                    ],
                ),
            ]
        )

        # ── SLA & Response Times ─────────────────────────────────
        sla_emoji = "🔴" if (response_sla_breaches or containment_sla_breaches) else "✅"
        performance_section = FactSet(
            separator=True,
            facts=[
                Fact(
                    title=f"{sla_emoji} SLA Breaches",
                    value=f"Resp- {len(response_sla_breaches)} [{', '.join(['X#' + b['id'] for b in response_sla_breaches])}]\n"
                          f"Cont- {len(containment_sla_breaches)} [{', '.join(['X#' + b['id'] for b in containment_sla_breaches])}]"
                ),
                Fact(
                    title="⏱️ MTT (min:sec)",
                    value=f"Respond- {int(mean_time_to_respond // 60)}:{int(mean_time_to_respond % 60):02d}\n"
                          f"Contain- {int(mean_time_to_contain // 60)}:{int(mean_time_to_contain % 60):02d}"
                ),
            ]
        )

        # ── Actions & Indicators ─────────────────────────────────
        actions_section = FactSet(
            separator=True,
            facts=[
                Fact(title="🛡️ IOCs blocked", value=iocs_blocked or "—"),
                Fact(title="💻 Hosts contained", value=hosts_contained or "—"),
                Fact(title="🔧 Tuning requests", value=', '.join(tuning_requests_submitted) or "—"),
            ]
        )

        shift_performance = AdaptiveCard(
            body=[header, team_section, ticket_stats, performance_section, actions_section]
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

        # Create and send Adaptive Card
        shift_card = _create_shift_change_card(shift_name, shift_data)
        fun_message = random.choice(SHIFT_CHANGE_MESSAGES)
        webex_api.messages.create(
            roomId=room_id,
            text=fun_message,
            attachments=[{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": shift_card.to_dict()
            }]
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

    parser = argparse.ArgumentParser(description='Test announcements to dev test space')
    parser.add_argument('--dor', action='store_true', help='Send DOR charts and region table')
    parser.add_argument('--shift-change', choices=['morning', 'afternoon', 'night'],
                        help='Send shift change card for given shift')
    args = parser.parse_args()

    if not args.dor and not args.shift_change:
        print("Usage: python -m src.secops.announcements --dor | --shift-change {morning,afternoon,night}")
        print("\nTests will be sent to dev test space (ROOM_ID)")
        exit(1)

    print(f"🧪 Testing announcements to test space...")

    if args.shift_change:
        print(f"\n🔔 Sending shift change card for '{args.shift_change}' shift...")
        shift_data = ShiftChangeFormatter.prepare_shift_data(args.shift_change)
        shift_card = _create_shift_change_card(args.shift_change, shift_data)
        fun_message = random.choice(SHIFT_CHANGE_MESSAGES)
        webex_api.messages.create(
            roomId=ROOM_ID,
            text=fun_message,
            attachments=[{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": shift_card.to_dict()
            }]
        )
        print("✅ Shift change card sent!")

    if args.dor:
        print("\n📊 Sending DOR charts and region table...")
        send_daily_operational_report_charts()
