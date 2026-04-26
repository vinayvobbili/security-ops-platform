"""Active Directory integration via XSOAR.

Fetches user and computer details from Active Directory using the AD XSOAR
integration — XSOAR holds the AD credentials and LDAP connection.
Internally uses TicketHandler.run_command_and_read_context() to fire the
war room command and read the structured results back from the incident context.
"""

import logging
from typing import Any, Dict, Optional

from services.xsoar.ticket_handler import TicketHandler

logger = logging.getLogger(__name__)

# XSOAR integration instance name for Active Directory.
# Update this to match the instance name configured in your XSOAR environment.
_XSOAR_INSTANCE = "ActiveDirectoryV2_instance_1"


class ActiveDirectoryClient:
    """Client for Active Directory queries via XSOAR integration commands."""

    def __init__(self):
        self._handler = TicketHandler()
        self._using = _XSOAR_INSTANCE

    def get_user(
        self,
        username: str,
        ticket_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Fetch AD user object details.

        Useful for checking account status, group memberships, OU placement,
        and last logon — whether observed activity matches the account's role.

        Args:
            username: sAMAccountName or UPN (domain prefix stripped automatically)
            ticket_id: XSOAR incident ID to run the command against

        Returns:
            Dict of user attributes, or None if not found or command failed.
        """
        short = username.split("\\")[-1].split("@")[0]
        result = self._handler.run_command_and_read_context(
            incident_id=ticket_id,
            command="!ad-get-user",
            args={"username": short},
            context_path="ActiveDirectory.Users",
            wait_seconds=10,
            using=self._using,
        )
        if result is None:
            return None
        # AD integration may return a list (multiple matches) — take first
        if isinstance(result, list):
            return result[0] if result else None
        return result if isinstance(result, dict) else None

    def get_computer(
        self,
        hostname: str,
        ticket_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Fetch AD computer object details.

        Useful for checking OU (workstation vs server), OS version, and last
        logon — helps assess whether the alert matches the host's expected role.

        Args:
            hostname: Computer name (domain suffix stripped automatically)
            ticket_id: XSOAR incident ID to run the command against

        Returns:
            Dict of computer attributes, or None if not found or command failed.
        """
        short = hostname.split(".")[0]
        result = self._handler.run_command_and_read_context(
            incident_id=ticket_id,
            command="!ad-get-computer",
            args={"hostname": short},
            context_path="ActiveDirectory.Computers",
            wait_seconds=10,
            using=self._using,
        )
        if result is None:
            return None
        if isinstance(result, list):
            return result[0] if result else None
        return result if isinstance(result, dict) else None
