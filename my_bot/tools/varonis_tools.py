"""
Varonis DatAlert Tools Module

Provides Varonis data security integration via XSOAR war room commands.
Supports querying user alerts and host data access activity.
"""

import logging
from typing import Optional

from langchain_core.tools import tool

from services.varonis import VaronisClient
from src.utils.tool_decorator import log_tool_call

# Lazy-initialized Varonis client
_varonis_client: Optional[VaronisClient] = None


def _get_varonis_client() -> Optional[VaronisClient]:
    """Get Varonis client (lazy initialization)."""
    global _varonis_client
    if _varonis_client is None:
        try:
            _varonis_client = VaronisClient()
        except Exception as e:
            logging.error(f"Failed to initialize Varonis client: {e}")
    return _varonis_client


@tool
@log_tool_call
def get_varonis_user_alerts(username: str, ticket_id: str) -> str:
    """Fetch active Varonis DatAlert alerts involving a user.

    Use this tool when:
    - User asks about Varonis alerts for a specific username
    - User wants to know if a user has triggered any data security alerts
    - User is investigating insider threat or data exfiltration activity
    - User asks "any Varonis alerts for user X?"

    Fires the !varonis-get-alert-evidence command via XSOAR and reads the result
    from the incident context. Requires a valid XSOAR ticket ID to run the command.

    Args:
        username: The username to look up (sAMAccountName, UPN, or domain\\user)
        ticket_id: XSOAR incident ID to run the command against
    """
    client = _get_varonis_client()
    if not client:
        return "Error: Varonis service is not available."

    if not username or not ticket_id:
        return "Error: Both username and ticket_id are required."

    logging.info(f"Fetching Varonis alerts for user '{username}' via ticket {ticket_id}")

    alerts = client.get_user_alerts(username=username, ticket_id=ticket_id)

    if alerts is None:
        return f"No Varonis alerts found for user `{username}`."

    lines = [
        f"## Varonis Alerts for `{username}`",
        f"**Alert Count:** {len(alerts)}",
        "",
    ]

    for i, alert in enumerate(alerts, 1):
        alert_lines = [f"### Alert {i}"]
        for key, value in alert.items():
            if value not in (None, "", [], {}):
                alert_lines.append(f"**{key}:** {value}")
        lines.append("\n".join(alert_lines))

    return "\n\n".join(lines)


@tool
@log_tool_call
def get_varonis_data_activity(hostname: str, ticket_id: str) -> str:
    """Fetch Varonis data access activity for a host.

    Use this tool when:
    - User asks about data activity on a specific host
    - User wants to see what files or shares were accessed from a host
    - User is investigating lateral movement or data staging on an endpoint
    - User asks "any Varonis activity from host X?" or "what data was accessed?"

    Fires the !varonis-get-data-activity command via XSOAR and reads the result
    from the incident context. Requires a valid XSOAR ticket ID to run the command.

    Args:
        hostname: The hostname to look up (FQDN or short name)
        ticket_id: XSOAR incident ID to run the command against
    """
    client = _get_varonis_client()
    if not client:
        return "Error: Varonis service is not available."

    if not hostname or not ticket_id:
        return "Error: Both hostname and ticket_id are required."

    logging.info(f"Fetching Varonis data activity for host '{hostname}' via ticket {ticket_id}")

    activity = client.get_data_activity(hostname=hostname, ticket_id=ticket_id)

    if activity is None:
        return f"No Varonis data activity found for host `{hostname}`."

    lines = [
        f"## Varonis Data Activity for `{hostname}`",
        f"**Record Count:** {len(activity)}",
        "",
    ]

    for i, record in enumerate(activity, 1):
        record_lines = [f"### Record {i}"]
        for key, value in record.items():
            if value not in (None, "", [], {}):
                record_lines.append(f"**{key}:** {value}")
        lines.append("\n".join(record_lines))

    return "\n\n".join(lines)
