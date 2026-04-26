"""Escalation contacts lookup tools."""

import logging

from mcp_server.server import mcp

logger = logging.getLogger(__name__)


@mcp.tool()
def contacts_lookup(query: str) -> str:
    """Search for escalation contacts, teams, or points of contact.

    Searches the SOC contacts database for relevant contacts based on
    the query. Returns names, roles, email addresses, and contact details
    for matching teams, regions, or services.

    Use this when asked: who to contact for X, escalation path for Y,
    point of contact for Z, on-call for team W, etc.

    Args:
        query: Natural language query describing who or what to find
               (e.g. 'network team', 'CISO', 'EMEA on-call', 'ransomware escalation')
    """
    from src.components.contacts_lookup import search_contacts_with_llm
    return search_contacts_with_llm(query)
