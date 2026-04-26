# /my_bot/tools/contacts_tools.py
"""
Contacts Lookup Tools

This module provides escalation contact lookup tools for the security operations bot.
"""

from langchain_core.tools import tool
from src.utils.tool_decorator import log_tool_call


@tool
@log_tool_call
def lookup_escalation_contacts(query: str) -> str:
    """ALWAYS call this tool when the user asks about contacts, escalation, or who to contact.
    Do NOT ask clarifying questions — call this tool immediately with the user's query as-is.
    The tool searches a contacts database and returns matching results for any query about
    escalation contacts, incident response contacts, points of contact, teams, regions, or services."""
    from src.components.contacts_lookup import search_contacts_with_llm
    return search_contacts_with_llm(query)
