"""Varonis DatAlert integration.

Fetches user alert evidence and data access activity via the Varonis
XSOAR integration — XSOAR holds the Varonis credentials and connection.
Internally uses TicketHandler.run_command_and_read_context() to fire the
war room command and read the structured results back from the incident context.
"""

import logging
from typing import Any, Dict, List, Optional

from services.xsoar.ticket_handler import TicketHandler

logger = logging.getLogger(__name__)

# XSOAR integration instance name for Varonis DatAlert.
# Update this to match the instance name configured in your XSOAR environment.
_XSOAR_INSTANCE = "Varonis_instance_1"


class VaronisClient:
    """Client for Varonis DatAlert data via XSOAR integration commands."""

    def __init__(self):
        self._handler = TicketHandler()
        self._using = _XSOAR_INSTANCE

    def get_user_alerts(
        self,
        username: str,
        ticket_id: str,
    ) -> Optional[List[Dict[str, Any]]]:
        """Fetch active Varonis alerts involving a user.

        Args:
            username: The username to look up (domain prefix stripped automatically)
            ticket_id: XSOAR incident ID to run the command against

        Returns:
            List of alert dicts, or None if no alerts or command failed.
        """
        short = username.split("\\")[-1].split("@")[0]
        result = self._handler.run_command_and_read_context(
            incident_id=ticket_id,
            command="!varonis-get-alert-evidence",
            args={"username": short},
            context_path="Varonis.Alert",
            wait_seconds=15,
            using=self._using,
        )
        if result is None:
            return None
        return result if isinstance(result, list) else [result]

    def get_data_activity(
        self,
        hostname: str,
        ticket_id: str,
    ) -> Optional[List[Dict[str, Any]]]:
        """Fetch Varonis data access activity for a host.

        Args:
            hostname: The hostname to look up (domain suffix stripped automatically)
            ticket_id: XSOAR incident ID to run the command against

        Returns:
            List of data activity records, or None if none found or command failed.
        """
        short = hostname.split(".")[0]
        result = self._handler.run_command_and_read_context(
            incident_id=ticket_id,
            command="!varonis-get-data-activity",
            args={"hostname": short},
            context_path="Varonis.DataActivity",
            wait_seconds=15,
            using=self._using,
        )
        if result is None:
            return None
        return result if isinstance(result, list) else [result]
