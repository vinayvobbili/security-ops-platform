"""
SecOps Package

Security operations utilities for shift management, staffing, metrics, and announcements.

This package provides:
- Shift determination and timing utilities
- Excel-based staffing data reading
- Ticket and security metrics calculations
- Webex announcement functions for shift changes and reports

Usage:
    from src.secops import get_current_shift, get_staffing_data, announce_shift_change

    # Get current shift
    shift = get_current_shift()

    # Get staffing data
    staffing = get_staffing_data('Monday', 'morning')

    # Announce shift change
    announce_shift_change('morning', room_id)
"""

# Constants
from .constants import (
    ShiftConstants,
    DOR_CHART_MESSAGES,
    SHIFT_PERFORMANCE_MESSAGES,
    SHIFT_CHANGE_MESSAGES,
    CHART_NOT_FOUND_MESSAGES,
    cell_names_by_shift,
    config,
    root_directory,
)

# Shift utilities
from .shift_utils import (
    get_current_shift,
    safe_parse_datetime,
    get_shift_start_hour,
    get_previous_shift_info,
    get_eastern_timezone,
)

# Staffing
from .staffing import (
    ExcelStaffingReader,
    get_excel_sheet,
    get_staffing_data,
    get_shift_lead,
    get_basic_shift_staffing,
    get_shift_timings,
)

# Metrics
from .metrics import (
    TicketMetricsCalculator,
    SecurityActionsCalculator,
    get_shift_ticket_metrics,
    get_shift_security_actions,
    get_open_tickets,
    BASE_QUERY,
)

# Announcements
from .announcements import (
    ShiftChangeFormatter,
    announce_previous_shift_performance,
    announce_shift_change,
    send_daily_operational_report_charts,
    webex_api,
    prod_list_handler,
)

__all__ = [
    # Constants
    'ShiftConstants',
    'DOR_CHART_MESSAGES',
    'SHIFT_PERFORMANCE_MESSAGES',
    'SHIFT_CHANGE_MESSAGES',
    'CHART_NOT_FOUND_MESSAGES',
    'cell_names_by_shift',
    'config',
    'root_directory',

    # Shift utilities
    'get_current_shift',
    'safe_parse_datetime',
    'get_shift_start_hour',
    'get_previous_shift_info',
    'get_eastern_timezone',

    # Staffing
    'ExcelStaffingReader',
    'get_excel_sheet',
    'get_staffing_data',
    'get_shift_lead',
    'get_basic_shift_staffing',
    'get_shift_timings',

    # Metrics
    'TicketMetricsCalculator',
    'SecurityActionsCalculator',
    'get_shift_ticket_metrics',
    'get_shift_security_actions',
    'get_open_tickets',
    'BASE_QUERY',

    # Announcements
    'ShiftChangeFormatter',
    'announce_previous_shift_performance',
    'announce_shift_change',
    'send_daily_operational_report_charts',
    'webex_api',
    'prod_list_handler',
]
