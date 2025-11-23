"""Shift Performance Handler for Web Dashboard."""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List

import pytz
from services.xsoar import TicketHandler
from src import secops
from src.components import secops_shift_metrics

logger = logging.getLogger(__name__)


def _shift_has_passed(shift_name: str, current_shift: str) -> bool:
    """Check if a shift has already passed based on current shift.

    Args:
        shift_name: Name of shift to check ('morning', 'afternoon', 'night')
        current_shift: Current shift name

    Returns:
        True if shift has passed
    """
    shift_order = ['morning', 'afternoon', 'night']
    try:
        shift_index = shift_order.index(shift_name)
        current_index = shift_order.index(current_shift)
        return shift_index < current_index
    except ValueError:
        return False


def get_shift_list_data(
    ticket_handler: TicketHandler,
    eastern: pytz.tzinfo.BaseTzInfo
) -> List[Dict[str, Any]]:
    """Single source of truth for shift performance data.

    Returns comprehensive shift data for the past week including:
    - Ticket counts (inflow/outflow)
    - Full ticket details (inflow_tickets, outflow_tickets arrays)
    - Metrics (MTTR, MTTC, SLA breaches)
    - Staffing info
    - Performance scores

    Args:
        ticket_handler: XSOAR ticket handler instance
        eastern: Pytz timezone object for US/Eastern

    Returns:
        List of shift data dictionaries
    """
    logger.info("Generating shift list data")

    shift_data = []
    shifts = ['morning', 'afternoon', 'night']

    for days_back in range(7):
        target_date = datetime.now(eastern) - timedelta(days=days_back)
        day_name = target_date.strftime('%A')
        date_str = target_date.strftime('%Y-%m-%d')

        for shift_name in shifts:
            # Special handling for night shift date
            shift_date = target_date
            shift_day_name = day_name
            shift_date_str = date_str

            if shift_name == 'night' and days_back == 0:
                now = datetime.now(eastern)
                if now.hour < 4 or (now.hour == 4 and now.minute < 30):
                    shift_date = target_date - timedelta(days=1)
                    shift_day_name = shift_date.strftime('%A')
                    shift_date_str = shift_date.strftime('%Y-%m-%d')

            try:
                staffing = secops.get_staffing_data(shift_day_name, shift_name)
                total_staff = sum(
                    len(staff) for team, staff in staffing.items()
                    if team != 'On-Call' and staff != ['N/A (Excel file missing)']
                )

                shift_id = f"{shift_date_str}_{shift_name}"
                current_shift = secops.get_current_shift()

                # Determine if we should show this shift
                if days_back > 0:
                    status = 'completed'
                    show_shift = True
                elif days_back == 0:
                    if shift_name.lower() == current_shift:
                        status = 'active'
                        show_shift = True
                    elif _shift_has_passed(shift_name.lower(), current_shift):
                        status = 'completed'
                        show_shift = True
                    else:
                        show_shift = False
                else:
                    show_shift = False

                if show_shift:
                    # Get staffing and security actions
                    shift_hour_map = {'morning': 4.5, 'afternoon': 12.5, 'night': 20.5}
                    shift_start_hour = shift_hour_map.get(shift_name.lower(), 4.5)

                    # Adjust days_back for night shift metrics
                    adjusted_days_back = days_back
                    if shift_name == 'night' and days_back == 0:
                        now = datetime.now(eastern)
                        if now.hour < 4 or (now.hour == 4 and now.minute < 30):
                            adjusted_days_back = 1

                    security_actions = secops.get_shift_security_actions(
                        adjusted_days_back,
                        shift_start_hour
                    )

                    detailed_staffing = secops.get_staffing_data(shift_day_name, shift_name)
                    basic_staffing = secops.get_basic_shift_staffing(shift_day_name, shift_name.lower())

                    # Determine shift lead
                    sa_list = detailed_staffing.get('SA') or detailed_staffing.get('senior_analysts') or []
                    shift_lead = None
                    if isinstance(sa_list, list) and sa_list:
                        first_sa = sa_list[0]
                        if first_sa and 'N/A' not in str(first_sa):
                            shift_lead = str(first_sa)
                    if not shift_lead:
                        shift_lead = secops.get_shift_lead(shift_day_name, shift_name)
                    if not shift_lead or 'N/A' in str(shift_lead):
                        shift_lead = 'N/A'

                    # Calculate all shift metrics
                    base_date = datetime(shift_date.year, shift_date.month, shift_date.day)
                    metrics = secops_shift_metrics.get_shift_metrics(
                        date_obj=base_date,
                        shift_name=shift_name,
                        ticket_handler=ticket_handler,
                        day_name=shift_day_name,
                        total_staff=total_staff,
                        security_actions=security_actions,
                        shift_lead=shift_lead,
                        basic_staffing=basic_staffing,
                        detailed_staffing=detailed_staffing
                    )

                    shift_data.append({
                        'id': shift_id,
                        'date': shift_date_str,
                        'day': metrics['day'],
                        'shift': shift_name.title(),
                        'total_staff': metrics['total_staff'],
                        'actual_staff': metrics['actual_staff'],
                        'status': status,
                        'tickets_acknowledged': metrics['tickets_acknowledged'],
                        'tickets_closed': metrics['tickets_closed'],
                        'response_time_minutes': metrics['response_time_minutes'],
                        'contain_time_minutes': metrics['contain_time_minutes'],
                        'response_sla_breaches': metrics['response_sla_breaches'],
                        'containment_sla_breaches': metrics['containment_sla_breaches'],
                        'security_actions': metrics['security_actions'],
                        'mtp_ticket_ids': metrics['mtp_ticket_ids'],
                        'inflow_tickets': metrics['inflow_tickets'],
                        'outflow_tickets': metrics['outflow_tickets'],
                        'shift_lead': metrics['shift_lead'],
                        'basic_staffing': metrics['basic_staffing'],
                        'detailed_staffing': metrics['detailed_staffing'],
                        'score': metrics['score']
                    })

            except Exception as metrics_err:
                logger.error(
                    f"Error getting staffing or metrics for {shift_day_name} {shift_name}: {metrics_err}"
                )

                current_shift = secops.get_current_shift()
                if days_back > 0:
                    show_shift = True
                    status = 'error'
                elif days_back == 0:
                    if shift_name.lower() == current_shift:
                        show_shift = True
                        status = 'error'
                    elif _shift_has_passed(shift_name.lower(), current_shift):
                        show_shift = True
                        status = 'error'
                    else:
                        show_shift = False
                else:
                    show_shift = False

                if show_shift:
                    shift_id = f"{shift_date_str}_{shift_name}"
                    shift_data.append({
                        'id': shift_id,
                        'date': shift_date_str,
                        'day': shift_day_name,
                        'shift': shift_name.title(),
                        'total_staff': 0,
                        'actual_staff': 0,
                        'status': status,
                        'tickets_acknowledged': 0,
                        'tickets_closed': 0,
                        'response_time_minutes': 0,
                        'contain_time_minutes': 0,
                        'response_sla_breaches': 0,
                        'containment_sla_breaches': 0,
                        'mtp_ticket_ids': '',
                        'inflow_tickets': [],
                        'outflow_tickets': [],
                        'shift_lead': 'N/A',
                        'basic_staffing': {'total_staff': 0, 'teams': {}},
                        'detailed_staffing': {},
                        'security_actions': {
                            'iocs_blocked': 0,
                            'domains_blocked': 0,
                            'malicious_true_positives': 0
                        },
                        'score': 0
                    })

    return shift_data
