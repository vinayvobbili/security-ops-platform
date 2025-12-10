"""
XSOAR Service using official demisto-py SDK

This module provides a wrapper around the official demisto-py SDK
to maintain backward compatibility with existing code while leveraging
the official Palo Alto Networks XSOAR Python client.

Usage:
    from services.xsoar import TicketHandler, ListHandler, XsoarEnvironment

    # Use prod environment (default)
    prod_handler = TicketHandler()
    prod_handler = TicketHandler(XsoarEnvironment.PROD)

    # Use dev environment
    dev_handler = TicketHandler(XsoarEnvironment.DEV)

    # Same for ListHandler
    prod_list = ListHandler()
    dev_list = ListHandler(XsoarEnvironment.DEV)

Migration Date: 2024-10-31
Original: services/xsoar.py.backup
Refactored: 2025-01-09
"""

# Import main classes
from .ticket_handler import TicketHandler
from .list_handler import ListHandler

# Import utilities
from ._utils import import_ticket

# Import client exports
from ._client import ApiException, DISABLE_SSL_VERIFY, get_config

# CONFIG for backward compatibility
CONFIG = get_config()

# Import enums
from src.utils.xsoar_enums import XsoarEnvironment

# Public API - these are the exports that external code should use
__all__ = [
    # Main handlers
    'TicketHandler',
    'ListHandler',

    # Enums
    'XsoarEnvironment',

    # Utilities
    'import_ticket',

    # Exceptions
    'ApiException',

    # Configuration
    'CONFIG',
    'DISABLE_SSL_VERIFY',
]
