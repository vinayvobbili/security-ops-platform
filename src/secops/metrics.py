"""
SecOps Metrics Calculators

Handles ticket metrics and security actions calculations.
"""
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List

import pytz

from services.xsoar import TicketHandler, ListHandler, XsoarEnvironment
from .constants import ShiftConstants, config
from .shift_utils import safe_parse_datetime

logger = logging.getLogger(__name__)

# Module-level handlers (initialized lazily)
_prod_list_handler = None

BASE_QUERY = f'type:{config.team_name} -owner:""'


def _get_prod_list_handler() -> ListHandler:
    """Get or create the production list handler."""
    global _prod_list_handler
    if _prod_list_handler is None:
        _prod_list_handler = ListHandler(XsoarEnvironment.PROD)
    return _prod_list_handler


class TicketMetricsCalculator:
    """Handles ticket metrics calculations."""

    @staticmethod
    def create_shift_period(days_back: int, shift_start_hour: float) -> Dict[str, Any]:
        """
        Create time period dict for shift.

        The XSOAR incidents/search period hours must be integers. Some shift offsets
        (e.g. 4.5, 12.5, 20.5) produce half-hour values (19.5, 11.5). We truncate to int
        to satisfy API requirements (API rejects floats like 19.5 with unmarshalling error).

        Args:
            days_back: Number of days back from today
            shift_start_hour: Shift start time in decimal hours

        Returns:
            Period dictionary for XSOAR API
        """
        start_hours = (days_back * 24) + (24 - shift_start_hour)
        end_hours = (days_back * 24) + (16 - shift_start_hour)
        return {
            "byFrom": "hours",
            "fromValue": int(start_hours),
            "byTo": "hours",
            "toValue": int(end_hours)
        }

    @staticmethod
    def calculate_response_times(tickets: List[Dict[str, Any]]) -> tuple[int, int]:
        """
        Calculate total response time and count from tickets.

        Args:
            tickets: List of ticket dictionaries

        Returns:
            Tuple of (total_time_ms, count)
        """
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
    def calculate_containment_times(tickets: List[Dict[str, Any]]) -> tuple[int, int]:
        """
        Calculate containment times for tickets with hostnames.

        Args:
            tickets: List of ticket dictionaries

        Returns:
            Tuple of (total_time_ms, count)
        """
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
    def safe_divide(numerator: float, denominator: float) -> float:
        """Safely divide, returning 0 if denominator is 0."""
        return numerator / denominator if denominator > 0 else 0

    @staticmethod
    def convert_to_minutes(milliseconds: int) -> float:
        """Convert milliseconds to minutes, rounded to 1 decimal."""
        return round(milliseconds / 60000, 1)


class SecurityActionsCalculator:
    """Handles security actions calculations."""

    @staticmethod
    def count_domains_blocked_in_period(start_time: datetime, end_time: datetime) -> int:
        """
        Count domains blocked during a specific time period.

        Args:
            start_time: Start of the period (naive datetime)
            end_time: End of the period (naive datetime)

        Returns:
            Count of domains blocked
        """
        try:
            domain_list = _get_prod_list_handler().get_list_data_by_name(f'{config.team_name} Blocked Domains')
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
    def calculate_shift_time_bounds(days_back: int, shift_start_hour: float) -> tuple[datetime, datetime]:
        """
        Calculate start and end times for a shift period.

        Args:
            days_back: Number of days back
            shift_start_hour: Shift start hour in decimal

        Returns:
            Tuple of (shift_start, shift_end) as naive datetimes
        """
        shift_start = datetime.now() - timedelta(hours=(days_back * 24) + (24 - shift_start_hour))
        shift_end = datetime.now() - timedelta(hours=(days_back * 24) + (16 - shift_start_hour))
        return shift_start, shift_end


def get_shift_ticket_metrics(days_back: int, shift_start_hour: float) -> Dict[str, Any]:
    """
    Get ticket metrics for a specific shift period using EXACT timestamps.

    Uses the secops_shift_metrics component for consistent metric calculation
    across all interfaces (web API, chatbot, CLI).

    Args:
        days_back: Number of days back from today (0 = today, 1 = yesterday)
        shift_start_hour: Shift start time in decimal hours (4.5 = 4:30 AM, 12.5 = 12:30 PM, 20.5 = 8:30 PM)

    Returns:
        Dict with ticket counts and metrics using exact shift windows:
        - tickets_acknowledged: Number of tickets acknowledged/worked by analysts
        - tickets_closed: Number of tickets closed
        - mean_response_time: Average response time in milliseconds
        - mean_contain_time: Average containment time in milliseconds
        - response_time_minutes: Average response time in minutes
        - contain_time_minutes: Average containment time in minutes
    """
    try:
        from src.components import secops_shift_metrics

        eastern = pytz.timezone(ShiftConstants.EASTERN_TZ)
        incident_fetcher = TicketHandler(XsoarEnvironment.PROD)

        # Calculate target date
        target_date = datetime.now(eastern) - timedelta(days=days_back)

        # Determine shift name from shift_start_hour
        shift_name_map = {4.5: 'morning', 12.5: 'afternoon', 20.5: 'night'}
        shift_name = shift_name_map.get(shift_start_hour, 'morning')

        # Use component to get metrics
        base_date = datetime(target_date.year, target_date.month, target_date.day)
        metrics = secops_shift_metrics.get_shift_metrics(
            date_obj=base_date,
            shift_name=shift_name,
            ticket_handler=incident_fetcher
        )

        # Convert to legacy format for backward compatibility
        # Note: response/contain times are already in minutes in the new component
        return {
            'tickets_acknowledged': metrics['tickets_acknowledged'],
            'tickets_closed': metrics['tickets_closed'],
            'mean_response_time': metrics['response_time_minutes'] * 60000,  # Convert back to ms
            'mean_contain_time': metrics['contain_time_minutes'] * 60000,  # Convert back to ms
            'response_time_minutes': metrics['response_time_minutes'],
            'contain_time_minutes': metrics['contain_time_minutes']
        }
    except Exception as e:
        logger.error(f"Error getting ticket metrics: {e}")
        return {
            'tickets_acknowledged': 0,
            'tickets_closed': 0,
            'mean_response_time': 0,
            'mean_contain_time': 0,
            'response_time_minutes': 0,
            'contain_time_minutes': 0
        }


def get_shift_security_actions(days_back: int, shift_start_hour: float) -> Dict[str, int]:
    """
    Get security actions data for a specific shift period using EXACT timestamps.

    Args:
        days_back: Number of days back from today (0 = today, 1 = yesterday)
        shift_start_hour: Shift start time in decimal hours (4.5 = 4:30 AM)

    Returns:
        Dict with malicious_true_positives, domains_blocked, iocs_blocked counts
    """
    try:
        eastern = pytz.timezone(ShiftConstants.EASTERN_TZ)
        incident_fetcher = TicketHandler(XsoarEnvironment.PROD)

        # Calculate exact shift window
        target_date = datetime.now(eastern) - timedelta(days=days_back)
        start_hour_int = int(shift_start_hour)
        start_minute = int((shift_start_hour % 1) * 60)

        start_dt_naive = datetime(
            target_date.year,
            target_date.month,
            target_date.day,
            start_hour_int,
            start_minute
        )
        start_dt = eastern.localize(start_dt_naive)
        end_dt = start_dt + timedelta(hours=8)

        # Build query with exact timestamps
        time_format = '%Y-%m-%dT%H:%M:%S %z'
        start_str = start_dt.strftime(time_format)
        end_str = end_dt.strftime(time_format)
        time_filter = f'created:>="{start_str}" created:<="{end_str}"'

        # Get malicious true positives
        mtp_query = f'{BASE_QUERY} {time_filter} status:closed impact:"Malicious True Positive"'
        malicious_tp = incident_fetcher.get_tickets(query=mtp_query)

        # Count domain blocks during shift (using naive datetime for list comparison)
        shift_start_naive = start_dt.replace(tzinfo=None)
        shift_end_naive = end_dt.replace(tzinfo=None)
        domain_blocks = SecurityActionsCalculator.count_domains_blocked_in_period(
            shift_start_naive, shift_end_naive
        )

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


def get_open_tickets() -> str:
    """Get formatted string of open tickets with links."""
    try:
        all_tickets = TicketHandler(XsoarEnvironment.PROD).get_tickets(query=BASE_QUERY + ' -status:closed')
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
    except Exception as e:
        logger.error(f"Error in get_open_tickets: {e}")
        return "Unable to fetch open tickets"
