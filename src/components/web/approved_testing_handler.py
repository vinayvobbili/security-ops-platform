"""Approved Testing Handler for Web Dashboard."""

import logging
from typing import Dict, Any
from datetime import datetime, timedelta

import pytz
from services.xsoar import ListHandler
from services.approved_testing_utils import add_approved_testing_entry

logger = logging.getLogger(__name__)


def get_approved_testing_entries(list_handler: ListHandler, team_name: str) -> Dict[str, Any]:
    """Fetches approved testing records.

    Args:
        list_handler: XSOAR list handler instance
        team_name: Name of the team (e.g., 'SecOps')

    Returns:
        Dictionary with ENDPOINTS, USERNAMES, IP_ADDRESSES, CIDR_BLOCKS lists
    """
    logger.info("Fetching approved testing entries")
    return list_handler.get_list_data_by_name(f'{team_name}_Approved_Testing')


def submit_red_team_testing_form(
    form_data: Dict[str, Any],
    list_handler: ListHandler,
    team_name: str,
    company_email_domain: str,
    eastern: pytz.tzinfo.BaseTzInfo,
    submitter_ip: str
) -> None:
    """Handles Red Team Testing form submissions.

    Args:
        form_data: Form data from request
        list_handler: XSOAR list handler instance
        team_name: Name of the team (e.g., 'SecOps')
        company_email_domain: Email domain (e.g., '@company.com')
        eastern: Pytz timezone object for US/Eastern
        submitter_ip: IP address of submitter

    Raises:
        ValueError: If validation fails
    """
    logger.info("Processing red team testing form submission")

    usernames = form_data.get('usernames', '').strip()
    tester_hosts = form_data.get('tester_hosts', '').strip()
    targets = form_data.get('targets', '').strip()
    description = form_data.get('description', '').strip()
    notes_scope = form_data.get('notes_scope', '').strip()
    keep_until = form_data.get('keep_until', '')
    submitter_email_address = form_data.get('email_local', '') + company_email_domain
    submit_date = datetime.now(eastern).strftime("%m/%d/%Y")

    approved_testing_list_name = f"{team_name}_Approved_Testing"
    approved_testing_master_list_name = f"{team_name}_Approved_Testing_MASTER"

    add_approved_testing_entry(
        list_handler,
        approved_testing_list_name,
        approved_testing_master_list_name,
        usernames,
        tester_hosts,
        targets,
        description,
        notes_scope,
        submitter_email_address,
        keep_until,
        submit_date,
        submitter_ip
    )


def submit_toodles_approved_testing(
    form_data: Dict[str, Any],
    list_handler: ListHandler,
    team_name: str,
    eastern: pytz.tzinfo.BaseTzInfo,
    submitter_ip: str
) -> str:
    """Handles Toodles approved testing submissions.

    Args:
        form_data: Form data from request
        list_handler: XSOAR list handler instance
        team_name: Name of the team (e.g., 'SecOps')
        eastern: Pytz timezone object for US/Eastern
        submitter_ip: IP address of submitter

    Returns:
        Success message

    Raises:
        ValueError: If validation fails
    """
    logger.info("Processing Toodles approved testing submission")

    usernames = form_data.get('usernames', '').strip()
    tester_hosts = form_data.get('tester_hosts', '').strip()
    targets = form_data.get('targets', '').strip()
    description = form_data.get('description', '').strip()
    notes_scope = form_data.get('notes_scope', '').strip()
    keep_until = form_data.get('keep_until', '')
    user_email = form_data.get('user_email', '').strip()

    # Default to tomorrow if no date provided
    if not keep_until:
        keep_until = (datetime.now(eastern) + timedelta(days=1)).strftime("%Y-%m-%d")
    submit_date = datetime.now(eastern).strftime("%m/%d/%Y")

    # Use user email if provided, otherwise use IP-based identifier
    submitter_email = user_email if user_email else f"web_user@{submitter_ip}"

    approved_testing_list_name = f"{team_name}_Approved_Testing"
    approved_testing_master_list_name = f"{team_name}_Approved_Testing_MASTER"

    add_approved_testing_entry(
        list_handler,
        approved_testing_list_name,
        approved_testing_master_list_name,
        usernames,
        tester_hosts,
        targets,
        description,
        notes_scope,
        submitter_email,
        keep_until,
        submit_date,
        submitter_ip
    )

    return f'Your approved testing entry has been added. Expires at 5 PM ET on {keep_until}.'
