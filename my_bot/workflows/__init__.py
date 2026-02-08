"""
LangGraph Workflows Module

Provides multi-step investigation workflows using LangGraph state machines.
These workflows orchestrate complex investigations that require multiple tool calls
in a specific sequence with conditional branching.

Workflows available:
- IOC Investigation: Full threat intel enrichment across multiple sources
- Incident Response: XSOAR ticket investigation with IOC enrichment and reporting

Usage:
    workflow investigate 1.2.3.4 and add results to XSOAR ticket 12345
    workflow full analysis of evil-domain.com
    workflow incident response for ticket 929947

If not using the workflow command, the LLM handles queries through normal tool calling.
"""

from my_bot.workflows.router import (
    is_workflow_command,
    parse_workflow_request,
    get_workflow_help,
    extract_ioc_from_query,
    extract_ticket_id_from_query,
    detect_workflow_type,
    strip_workflow_prefix,
)
from my_bot.workflows.ioc_investigation import run_ioc_investigation
from my_bot.workflows.incident_response import run_incident_response

__all__ = [
    "is_workflow_command",
    "parse_workflow_request",
    "get_workflow_help",
    "extract_ioc_from_query",
    "extract_ticket_id_from_query",
    "detect_workflow_type",
    "strip_workflow_prefix",
    "run_ioc_investigation",
    "run_incident_response",
]
