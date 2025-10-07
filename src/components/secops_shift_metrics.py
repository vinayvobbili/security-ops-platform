"""
SecOps Shift Metrics Component

This module contains business logic for calculating shift performance metrics including:
- Inflow/Outflow ticket counts
- MTTR (Mean Time to Respond) and MTTC (Mean Time to Contain)
- SLA breaches (response and containment)
- Malicious True Positives (MTPs)
- Performance scores
- Staffing metrics

The functions here are independent of the web framework and can be reused across
different interfaces (API endpoints, CLI tools, scheduled jobs, etc.)
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple, Optional, Any

import pytz

from src import secops

logger = logging.getLogger(__name__)
eastern = pytz.timezone('US/Eastern')

# Simple in-memory cache for inflow queries (query -> (timestamp, tickets))
SHIFT_INFLOW_CACHE = {}
SHIFT_INFLOW_CACHE_TTL_SECONDS = 300  # 5 minutes


def _get_cached_inflow(query: str) -> Optional[List[Dict]]:
    """Get cached inflow tickets if available and not expired."""
    now = datetime.now(timezone.utc).timestamp()
    entry = SHIFT_INFLOW_CACHE.get(query)
    if entry:
        ts, tickets = entry
        if now - ts < SHIFT_INFLOW_CACHE_TTL_SECONDS:
            return tickets
        else:
            SHIFT_INFLOW_CACHE.pop(query, None)
    return None


def _set_cached_inflow(query: str, tickets: List[Dict]):
    """Cache inflow tickets with timestamp."""
    SHIFT_INFLOW_CACHE[query] = (datetime.now(timezone.utc).timestamp(), tickets)


def compute_shift_window(date_obj: datetime, shift_name: str) -> Tuple[datetime, datetime, str, str]:
    """
    Compute the time window for a given shift.

    Args:
        date_obj: Date object for the shift
        shift_name: Name of the shift ('morning', 'afternoon', 'night')

    Returns:
        Tuple of (start_dt_eastern, end_dt_eastern, start_str, end_str)
    """
    if shift_name.lower() == 'morning':
        shift_start_hour = 4.5
    elif shift_name.lower() == 'afternoon':
        shift_start_hour = 12.5
    else:
        shift_start_hour = 20.5

    start_hour_int = int(shift_start_hour)
    start_minute = int((shift_start_hour % 1) * 60)
    start_dt_naive = datetime(date_obj.year, date_obj.month, date_obj.day, start_hour_int, start_minute)
    start_dt = eastern.localize(start_dt_naive)
    end_dt = start_dt + timedelta(hours=8)
    time_format = '%Y-%m-%dT%H:%M:%S %z'

    return start_dt, end_dt, start_dt.strftime(time_format), end_dt.strftime(time_format)


def fetch_inflow_tickets(date_obj: datetime, shift_name: str, ticket_handler) -> Tuple[str, List[Dict], Tuple[datetime, datetime]]:
    """
    Fetch inflow tickets for a shift window with caching.

    Args:
        date_obj: Date object for the shift
        shift_name: Name of the shift
        ticket_handler: Instance of TicketHandler for querying tickets

    Returns:
        Tuple of (query_string, tickets_list, (start_dt, end_dt))
    """
    start_dt, end_dt, start_str, end_str = compute_shift_window(date_obj, shift_name)
    time_filter = f'created:>="{start_str}" created:<="{end_str}"'
    inflow_query = f'{secops.BASE_QUERY} {time_filter}'

    cached = _get_cached_inflow(inflow_query)
    if cached is not None:
        return inflow_query, cached, (start_dt, end_dt)

    tickets = ticket_handler.get_tickets(query=inflow_query)
    _set_cached_inflow(inflow_query, tickets)

    return inflow_query, tickets, (start_dt, end_dt)


def fetch_outflow_tickets(start_dt: datetime, end_dt: datetime, ticket_handler) -> List[Dict]:
    """
    Fetch outflow (closed) tickets for a time window.

    Args:
        start_dt: Start datetime of the window
        end_dt: End datetime of the window
        ticket_handler: Instance of TicketHandler for querying tickets

    Returns:
        List of closed tickets
    """
    time_format = '%Y-%m-%dT%H:%M:%S %z'
    start_str = start_dt.strftime(time_format)
    end_str = end_dt.strftime(time_format)
    time_filter = f'created:>="{start_str}" created:<="{end_str}"'
    outflow_query = f'{secops.BASE_QUERY} {time_filter} status:closed'

    return ticket_handler.get_tickets(query=outflow_query)


def extract_sla_metrics(tickets: List[Dict]) -> Dict[str, float]:
    """
    Compute SLA metrics (MTTR / MTTC averages & breach counts) from tickets.

    Args:
        tickets: List of ticket dictionaries

    Returns:
        Dictionary with avg_response, avg_containment, response_breaches, containment_breaches
    """

    def _duration_to_minutes(raw):
        """Convert duration to minutes, handling both seconds and milliseconds."""
        if not isinstance(raw, (int, float)) or raw <= 0:
            return None, None
        # Detect millisecond values (very large and divisible by 1000)
        if raw >= 3_600_000 and raw % 1000 == 0:  # >= 1 hour expressed in ms
            minutes = raw / 1000.0 / 60.0
            unit = 'ms'
        else:
            minutes = raw / 60.0  # treat as seconds
            unit = 's'
        return minutes, unit

    response_total_min = 0.0
    response_count = 0
    response_breaches = 0
    contain_total_min = 0.0
    contain_count = 0
    contain_breaches = 0

    for t in tickets:
        cf = t.get('CustomFields', {}) or {}
        ticket_id = t.get('id', 'UNKNOWN')

        # Prefer explicit timetorespond but allow legacy responsesla fallback
        resp_obj = cf.get('timetorespond') or cf.get('responsesla')
        cont_obj = None
        # Only evaluate containment for host-based tickets
        if cf.get('hostname'):
            cont_obj = cf.get('timetocontain') or cf.get('containmentsla')

        raw_resp = raw_cont = None
        resp_min = cont_min = None
        resp_unit = cont_unit = None

        if isinstance(resp_obj, dict):
            raw_resp = resp_obj.get('totalDuration')
            resp_min, resp_unit = _duration_to_minutes(raw_resp)
            if resp_min is not None:
                response_total_min += resp_min
                response_count += 1
            if str(resp_obj.get('breachTriggered')).lower() == 'true':
                response_breaches += 1

        if isinstance(cont_obj, dict):
            raw_cont = cont_obj.get('totalDuration')
            cont_min, cont_unit = _duration_to_minutes(raw_cont)
            if cont_min is not None:
                contain_total_min += cont_min
                contain_count += 1
            if str(cont_obj.get('breachTriggered')).lower() == 'true':
                contain_breaches += 1

        # Debug logging per ticket
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "SLA_METRICS ticket=%s resp_raw=%s%s resp_min=%.3f cont_raw=%s%s cont_min=%.3f has_hostname=%s resp_breach=%s cont_breach=%s",
                ticket_id,
                raw_resp if raw_resp is not None else '-',
                f"{resp_unit}" if resp_unit else '',
                resp_min if resp_min is not None else -1,
                raw_cont if raw_cont is not None else '-',
                f"{cont_unit}" if cont_unit else '',
                cont_min if cont_min is not None else -1,
                bool(cf.get('hostname')),
                str(resp_obj.get('breachTriggered')) if isinstance(resp_obj, dict) else '-',
                str(cont_obj.get('breachTriggered')) if isinstance(cont_obj, dict) else '-'
            )

    avg_response = round(response_total_min / response_count, 2) if response_count else 0.0
    avg_contain = round(contain_total_min / contain_count, 2) if contain_count else 0.0

    # Final aggregate debug summary
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "SLA_METRICS_SUMMARY resp_count=%d resp_total_min=%.3f avg_resp=%.2f cont_count=%d cont_total_min=%.3f avg_cont=%.2f resp_breaches=%d cont_breaches=%d",
            response_count, response_total_min, avg_response,
            contain_count, contain_total_min, avg_contain,
            response_breaches, contain_breaches
        )

    return {
        'avg_response': avg_response,  # MTTR in minutes
        'avg_containment': avg_contain,  # MTTC in minutes
        'response_breaches': response_breaches,
        'containment_breaches': contain_breaches
    }


def serialize_inflow_tickets(tickets: List[Dict]) -> List[Dict[str, Any]]:
    """
    Serialize inflow tickets to a simplified format for API responses.

    Args:
        tickets: List of raw ticket dictionaries

    Returns:
        List of serialized ticket dictionaries
    """
    inflow_list = []

    for ticket in tickets:
        custom_fields = ticket.get('CustomFields', {})
        ttr_minutes = None
        ttc_minutes = None

        if 'timetorespond' in custom_fields and custom_fields['timetorespond']:
            ttr_minutes = round(custom_fields['timetorespond'].get('totalDuration', 0) / 60, 2)
        if 'timetocontain' in custom_fields and custom_fields['timetocontain']:
            ttc_minutes = round(custom_fields['timetocontain'].get('totalDuration', 0) / 60, 2)

        created_str = ticket.get('created', '')
        created_et = ''
        if created_str:
            try:
                created_dt = datetime.fromisoformat(created_str.replace('Z', '+00:00'))
                created_et = created_dt.astimezone(eastern).strftime('%Y-%m-%d %H:%M:%S %Z')
            except:
                created_et = created_str

        inflow_list.append({
            'id': ticket.get('id', ''),
            'name': ticket.get('name', ''),
            'type': ticket.get('type', ''),
            'owner': ticket.get('owner', ''),
            'ttr': ttr_minutes,
            'ttc': ttc_minutes,
            'created': created_et
        })

    return inflow_list


def serialize_outflow_tickets(tickets: List[Dict]) -> List[Dict[str, Any]]:
    """
    Serialize outflow tickets to a simplified format for API responses.

    Args:
        tickets: List of raw ticket dictionaries

    Returns:
        List of serialized ticket dictionaries
    """
    outflow_list = []

    for ticket in tickets:
        custom_fields = ticket.get('CustomFields', {})
        closed_str = ticket.get('closed', '')
        closed_et = ''

        if closed_str:
            try:
                closed_dt = datetime.fromisoformat(closed_str.replace('Z', '+00:00'))
                closed_et = closed_dt.astimezone(eastern).strftime('%Y-%m-%d %H:%M:%S %Z')
            except:
                closed_et = closed_str

        impact = custom_fields.get('impact', {}).get('simple', 'Unknown') if isinstance(custom_fields.get('impact'), dict) else custom_fields.get('impact', 'Unknown')

        outflow_list.append({
            'id': ticket.get('id', ''),
            'name': ticket.get('name', ''),
            'type': ticket.get('type', ''),
            'owner': ticket.get('owner', ''),
            'closed': closed_et,
            'impact': impact
        })

    return outflow_list


def extract_mtp_ids(tickets: List[Dict]) -> List[str]:
    """
    Extract IDs of Malicious True Positive tickets.

    Args:
        tickets: List of ticket dictionaries

    Returns:
        List of ticket IDs that are MTPs
    """
    return [
        t.get('id')
        for t in tickets
        if t.get('CustomFields', {}).get('impact') == 'Malicious True Positive'
    ]


def calculate_actual_staff(inflow_tickets: List[Dict]) -> int:
    """
    Calculate actual staff count from distinct ticket owners.

    Args:
        inflow_tickets: List of inflow ticket dictionaries

    Returns:
        Count of distinct owners (excluding unassigned/admin)
    """
    distinct_owners = set()
    for ticket in inflow_tickets:
        owner = ticket.get('owner', '').strip()
        if owner and owner.lower() not in ['', 'unassigned', 'admin']:
            distinct_owners.add(owner)
    return len(distinct_owners)


def calculate_performance_score(
    tickets_inflow_count: int,
    tickets_closed_count: int,
    sla_metrics: Dict[str, float],
    staff_count: int
) -> int:
    """
    Calculate shift performance score (1-10 scale).

    Only measures what analysts control: closed tickets, response/containment times, SLA compliance.

    Args:
        tickets_inflow_count: Number of tickets acknowledged
        tickets_closed_count: Number of tickets closed
        sla_metrics: Dictionary with avg_response, avg_containment, response_breaches, containment_breaches
        staff_count: Number of staff members

    Returns:
        Performance score (1-10)
    """
    staff_count = max(staff_count, 1)  # Avoid division by zero
    score = 0

    # 1. Tickets Closed Productivity (up to 20 points)
    tickets_closed_per_analyst = tickets_closed_count / staff_count
    score += min(tickets_closed_per_analyst * 10, 20)

    # 2. Backlog Clearing (+10 bonus or -10 penalty)
    if tickets_closed_count >= tickets_inflow_count:
        score += 10  # Cleared backlog or kept up
    else:
        score -= 10  # Failed to keep up

    # 3. Response Time Quality (up to 25 points)
    avg_response = sla_metrics['avg_response']
    if avg_response <= 5:  # Excellent: under 5 min
        score += 25
    elif avg_response <= 15:  # Good: under 15 min
        score += 18
    elif avg_response <= 30:  # Acceptable: under 30 min
        score += 10
    # Bad: >30 min gets 0 points

    # 4. Containment Time Quality (up to 25 points)
    avg_containment = sla_metrics['avg_containment']
    if avg_containment <= 30:  # Excellent: under 30 min
        score += 25
    elif avg_containment <= 60:  # Good: under 60 min
        score += 18
    elif avg_containment <= 120:  # Acceptable: under 2 hours
        score += 10
    # Bad: >2 hours gets 0 points

    # 5. Response SLA Compliance (up to 10 points, -2pts per breach)
    response_sla_score = 10 - (sla_metrics['response_breaches'] * 2)
    score += max(0, response_sla_score)

    # 6. Containment SLA Compliance (up to 10 points, -2pts per breach)
    containment_sla_score = 10 - (sla_metrics['containment_breaches'] * 2)
    score += max(0, containment_sla_score)

    # Cap score between 0 and 100, then convert to 1-10 scale
    score = max(0, min(100, score))
    score = max(1, min(10, int(round(score / 10))))

    return score


def get_shift_metrics(
    date_obj: datetime,
    shift_name: str,
    ticket_handler,
    day_name: str = None,
    total_staff: int = None,
    security_actions: Dict = None,
    shift_lead: str = None,
    basic_staffing: Dict = None,
    detailed_staffing: Dict = None
) -> Dict[str, Any]:
    """
    Calculate comprehensive metrics for a specific shift.

    This is the main entry point for getting all shift metrics. It orchestrates
    fetching tickets, calculating SLA metrics, performance scores, etc.

    Args:
        date_obj: Date object for the shift
        shift_name: Name of the shift ('morning', 'afternoon', 'night')
        ticket_handler: Instance of TicketHandler for querying tickets
        day_name: Day of week name (optional, for returned data)
        total_staff: Total scheduled staff count (optional)
        security_actions: Security actions dict (optional)
        shift_lead: Shift lead name (optional)
        basic_staffing: Basic staffing info (optional)
        detailed_staffing: Detailed staffing info (optional)

    Returns:
        Dictionary containing all shift metrics including:
        - inflow_tickets: Serialized list of inflow tickets
        - outflow_tickets: Serialized list of outflow tickets
        - tickets_acknowledged: Count of tickets acknowledged/worked by analysts
        - tickets_closed: Count of closed tickets
        - response_time_minutes: Average response time
        - contain_time_minutes: Average containment time
        - response_sla_breaches: Count of response SLA breaches
        - containment_sla_breaches: Count of containment SLA breaches
        - mtp_ticket_ids: Comma-separated string of MTP ticket IDs
        - actual_staff: Count of distinct ticket owners
        - score: Performance score (1-10)
        - Plus any optional parameters passed in (day_name, total_staff, etc.)
    """
    # Fetch inflow tickets
    _, inflow_tickets, (start_dt, end_dt) = fetch_inflow_tickets(date_obj, shift_name, ticket_handler)

    # Fetch outflow tickets
    outflow_tickets = fetch_outflow_tickets(start_dt, end_dt, ticket_handler)

    # Calculate SLA metrics
    sla_metrics = extract_sla_metrics(inflow_tickets)

    # Extract MTP IDs
    mtp_ids = extract_mtp_ids(inflow_tickets)

    # Serialize tickets
    inflow_list = serialize_inflow_tickets(inflow_tickets)
    outflow_list = serialize_outflow_tickets(outflow_tickets)

    # Calculate actual staff
    actual_staff = calculate_actual_staff(inflow_tickets)

    # Calculate performance score
    score = calculate_performance_score(
        len(inflow_list),
        len(outflow_list),
        sla_metrics,
        actual_staff
    )

    # Build result dictionary
    result = {
        'inflow_tickets': inflow_list,
        'outflow_tickets': outflow_list,
        'tickets_acknowledged': len(inflow_list),
        'tickets_closed': len(outflow_list),
        'response_time_minutes': sla_metrics['avg_response'],
        'contain_time_minutes': sla_metrics['avg_containment'],
        'response_sla_breaches': sla_metrics['response_breaches'],
        'containment_sla_breaches': sla_metrics['containment_breaches'],
        'mtp_ticket_ids': ', '.join(map(str, mtp_ids)),
        'actual_staff': actual_staff,
        'score': score
    }

    # Add optional parameters if provided
    if day_name is not None:
        result['day'] = day_name
    if total_staff is not None:
        result['total_staff'] = total_staff
    if security_actions is not None:
        result['security_actions'] = security_actions
    if shift_lead is not None:
        result['shift_lead'] = shift_lead
    if basic_staffing is not None:
        result['basic_staffing'] = basic_staffing
    if detailed_staffing is not None:
        result['detailed_staffing'] = detailed_staffing

    return result
