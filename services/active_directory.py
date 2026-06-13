"""Active Directory integration via XSOAR.

Fetches user and computer details from Active Directory using the AD XSOAR
integration — XSOAR holds the AD credentials and LDAP connection.
Internally uses TicketHandler.run_command_and_read_context() to fire the
war room command and read the structured results back from the incident context.
"""

import logging
import os
from typing import Any, Dict, Literal, Optional

from services.xsoar.ticket_handler import TicketHandler

logger = logging.getLogger(__name__)

# XSOAR integration instance name for Active Directory.
# Update this to match the instance name configured in your XSOAR environment.
_XSOAR_INSTANCE = "ActiveDirectoryV2_instance_1"


# --- Email existence check (signup directory validation) -------------------
#
# Unlike the methods above (which read structured context from an async war
# room command), this runs `!ad-get-user email=<addr>` SYNCHRONOUSLY via
# /entry/execute/sync — the same proven path services/xsoar_email.py uses to
# send mail. The async /xsoar/entry path 400s on this XSOAR, and pinning a
# `using=<instance>` arg also 400s (the configured instance names differ), so
# we deliberately run against ALL Active Directory Query v2 instances (every
# the company forest) and treat a hit in *any* forest as "exists".
#
# Each forest returns a markdown "### Active Directory - Get Users" entry that
# either contains a result table or the literal "No entries." — that's the
# signal we key on.

AdEmailStatus = Literal["found", "not_found", "unknown"]

_AD_GET_USERS_HEADER = "Active Directory - Get Users"
_AD_NO_ENTRIES = "No entries."


def email_exists_in_ad(email: str) -> AdEmailStatus:
    """Check whether ``email`` resolves to a real Active Directory account.

    Returns:
        "found"      — at least one forest returned a matching user.
        "not_found"  — every queried forest cleanly returned "No entries.".
        "unknown"    — the lookup could not be completed (XSOAR/command error,
                       no usable entries). Callers should FAIL OPEN on this.

    Designed to be cheap to call and never raise — any failure maps to
    "unknown" so signup can fall back to email-verification gating alone.
    """
    email = (email or "").strip()
    if not email:
        return "unknown"

    # Imported here to keep module import light and avoid a hard XSOAR
    # dependency for callers that only use the AD client methods above.
    from services.xsoar._client import get_prod_client
    from services.xsoar._utils import _parse_generic_response
    from services.xsoar_email import MAIL_ROBOT_INCIDENT_ID

    incident_id = os.environ.get("AD_LOOKUP_INCIDENT_ID") or MAIL_ROBOT_INCIDENT_ID

    try:
        resp = get_prod_client().generic_request(
            path="/entry/execute/sync",
            method="POST",
            body={
                "investigationId": incident_id,
                "data": "!ad-get-user",
                "args": {"email": {"simple": email}},
            },
        )
    except Exception as e:  # network/API/closed-incident — fail open
        logger.warning("AD email lookup failed for %r: %s", email, e)
        return "unknown"

    parsed = _parse_generic_response(resp)
    entries = parsed if isinstance(parsed, list) else [parsed]

    saw_clean_answer = False
    for ent in entries:
        if not isinstance(ent, dict):
            continue
        # type 4 == error entry; skip (counts as inconclusive for that forest)
        if ent.get("type") == 4 or ent.get("errorSource"):
            continue
        contents = ent.get("contents")
        if not isinstance(contents, str) or _AD_GET_USERS_HEADER not in contents:
            continue
        saw_clean_answer = True
        if _AD_NO_ENTRIES not in contents:
            return "found"  # a forest returned an actual user row

    return "not_found" if saw_clean_answer else "unknown"


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
