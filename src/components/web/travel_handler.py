"""Travel Records Handler for Web Dashboard."""

import logging
from typing import Dict, Any, List
from datetime import datetime

import pytz
from services.xsoar import ListHandler

logger = logging.getLogger(__name__)


def parse_date(date_str: str) -> datetime:
    """Parses a date string in multiple formats and returns a datetime object.

    Args:
        date_str: Date string to parse

    Returns:
        Datetime object

    Raises:
        ValueError: If date format not recognized
    """
    for fmt in ('%Y-%m-%d', '%m/%d/%Y'):
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    raise ValueError(f"Date format not recognized: {date_str}")


def get_current_upcoming_travel_records(list_handler: ListHandler) -> List[Dict[str, Any]]:
    """Fetches current and upcoming travel records.

    Args:
        list_handler: XSOAR list handler instance

    Returns:
        List of travel records with future end dates
    """
    logger.info("Fetching upcoming travel records")
    return [
        record for record in list_handler.get_list_data_by_name('SecOps_Upcoming_Travel')
        if parse_date(record['vacation_end_date']) >= datetime.now()
    ]


def submit_travel_form(
    form_data: Dict[str, Any],
    list_handler: ListHandler,
    eastern: pytz.tzinfo.BaseTzInfo,
    submitter_ip: str
) -> Dict[str, Any]:
    """Handles travel form submissions.

    Args:
        form_data: Form data from request
        list_handler: XSOAR list handler instance
        eastern: Pytz timezone object for US/Eastern
        submitter_ip: IP address of submitter

    Returns:
        Response from list handler
    """
    logger.info("Processing travel form submission")

    return list_handler.add_item_to_list('SecOps_Upcoming_Travel', {
        "traveller_email_address": form_data.get('traveller_email_address'),
        "work_location": form_data.get('work_location'),
        "vacation_location": form_data.get('vacation_location'),
        "vacation_start_date": form_data.get('vacation_start_date'),
        "vacation_end_date": form_data.get('vacation_end_date'),
        "is_working_during_vacation": form_data.get('will_work_during_vacation'),
        "comments": form_data.get('comments'),
        "submitted_at": datetime.now(eastern).strftime("%m/%d/%Y %I:%M %p %Z"),
        "submitted_by_ip_address": submitter_ip
    })
