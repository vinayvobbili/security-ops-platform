"""
QRadar Tools Module

Provides QRadar SIEM integration for security event searches and offense management.
Supports AQL queries, event searches, and offense lookups.
"""

import logging
from typing import Optional

from langchain_core.tools import tool

from services.qradar import QRadarClient
from src.utils.tool_decorator import log_tool_call

# Initialize QRadar client once
_qradar_client: Optional[QRadarClient] = None

try:
    logging.info("Initializing QRadar client...")
    _qradar_client = QRadarClient()

    if _qradar_client.is_configured():
        logging.info("QRadar client initialized successfully.")
    else:
        logging.warning("QRadar client not configured (missing API URL or key). Tools will be disabled.")
        _qradar_client = None

except Exception as e:
    logging.error(f"Failed to initialize QRadar client: {e}")
    _qradar_client = None


def _format_events_for_display(events: list, max_events: int = 10) -> str:
    """Format a list of events for display."""
    if not events:
        return "No events found"

    lines = [f"**Total Events:** {len(events)}", ""]

    for i, event in enumerate(events[:max_events], 1):
        event_lines = [f"### Event {i}"]

        # Source/Destination IPs
        if "sourceip" in event:
            event_lines.append(f"**Source IP:** {event['sourceip']}")
        if "prenatsourceip" in event and event["prenatsourceip"]:
            event_lines.append(f"**Pre-NAT Source IP:** {event['prenatsourceip']}")
        if "destinationip" in event:
            event_lines.append(f"**Destination IP:** {event['destinationip']}")
        if "prenatdestinationip" in event and event["prenatdestinationip"]:
            event_lines.append(f"**Pre-NAT Dest IP:** {event['prenatdestinationip']}")

        # URL/Path/File fields
        if "URL" in event and event["URL"]:
            event_lines.append(f"**URL:** {event['URL']}")
        if "URL Path" in event and event["URL Path"]:
            event_lines.append(f"**Path:** {event['URL Path']}")
        if "Referer URL" in event and event["Referer URL"]:
            event_lines.append(f"**Referer:** {event['Referer URL']}")
        if "File Name" in event and event["File Name"]:
            event_lines.append(f"**File Name:** {event['File Name']}")
        if "Destination Domain Name" in event and event["Destination Domain Name"]:
            event_lines.append(f"**Dest Domain:** {event['Destination Domain Name']}")

        # Threat fields
        if "Threat Name" in event and event["Threat Name"]:
            event_lines.append(f"**Threat Name:** {event['Threat Name']}")
        if "Threat Type" in event and event["Threat Type"]:
            event_lines.append(f"**Threat Type:** {event['Threat Type']}")

        # Event metadata
        if "eventname" in event:
            event_lines.append(f"**Event Name:** {event['eventname']}")
        if "magnitude" in event:
            event_lines.append(f"**Magnitude:** {event['magnitude']}/10")

        # Format timestamp
        if "starttime" in event:
            try:
                from datetime import datetime
                ts = event["starttime"]
                if ts > 1e12:  # milliseconds
                    ts = ts / 1000
                dt = datetime.fromtimestamp(ts)
                event_lines.append(f"**Time:** {dt.strftime('%Y-%m-%d %H:%M:%S')}")
            except (ValueError, OSError):
                event_lines.append(f"**Time:** {event['starttime']}")

        lines.append("\n".join(event_lines))

    if len(events) > max_events:
        lines.append(f"\n*... and {len(events) - max_events} more events*")

    return "\n\n".join(lines)


@tool
@log_tool_call
def search_qradar_by_ip(ip_address: str, hours: int = 24) -> str:
    """Search QRadar SIEM for security events involving an IP address.

    Use this tool when:
    - User asks to search QRadar for an IP address
    - User wants to check if an IP has any security events or alerts
    - User is investigating suspicious activity from/to an IP
    - User asks "any events for IP X?" or "search SIEM for IP"

    Returns events showing source/destination IPs, event names, magnitude, and timestamps.

    Args:
        ip_address: The IP address to search for (e.g., "192.168.1.100", "10.0.0.50")
        hours: Number of hours to look back (default: 24, max: 168)
    """
    if not _qradar_client:
        return "Error: QRadar service is not initialized."

    ip_address = ip_address.strip()

    # Validate hours
    hours = min(max(1, hours), 168)  # Clamp between 1-168 hours

    logging.info(f"Searching QRadar for IP {ip_address} over last {hours} hours")

    result = _qradar_client.search_events_by_ip(ip_address, hours=hours)

    if "error" in result:
        return f"Error: {result['error']}"

    events = result.get("events", [])
    if not events:
        return f"No events found for IP `{ip_address}` in the last {hours} hours."

    output = [
        "## QRadar IP Search Results",
        f"**IP Address:** {ip_address}",
        f"**Time Range:** Last {hours} hours",
        "",
        _format_events_for_display(events)
    ]

    return "\n".join(output)


@tool
@log_tool_call
def search_qradar_by_domain(domain: str, hours: int = 24) -> str:
    """Search QRadar SIEM for security events involving a domain or URL.

    Use this tool when:
    - User asks to search QRadar for a domain name
    - User wants to check if anyone accessed a suspicious domain
    - User is investigating phishing or malicious URLs
    - User asks "any activity to evil.com?" or "search SIEM for domain"

    Searches URL fields in QRadar events. Returns matching events with IPs, URLs, and timestamps.

    Args:
        domain: The domain to search for (e.g., "example.com", "malicious-site.net")
        hours: Number of hours to look back (default: 24, max: 168)
    """
    if not _qradar_client:
        return "Error: QRadar service is not initialized."

    domain = domain.strip().lower()
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.split("/")[0]

    # Validate hours
    hours = min(max(1, hours), 168)

    logging.info(f"Searching QRadar for domain {domain} over last {hours} hours")

    result = _qradar_client.search_events_by_domain(domain, hours=hours)

    if "error" in result:
        return f"Error: {result['error']}"

    events = result.get("events", [])
    if not events:
        return f"No events found for domain `{domain}` in the last {hours} hours."

    output = [
        "## QRadar Domain Search Results",
        f"**Domain:** {domain}",
        f"**Time Range:** Last {hours} hours",
        "",
        _format_events_for_display(events)
    ]

    return "\n".join(output)


@tool
@log_tool_call
def get_qradar_offense(offense_id: int) -> str:
    """Get detailed information about a SINGLE QRadar offense when you have the specific offense ID number.

    IMPORTANT: This tool requires a specific offense ID number. If the user asks to "list offenses",
    "show offenses", "get today's offenses", or wants to see multiple offenses, use list_qradar_offenses instead.

    Use this tool ONLY when:
    - User explicitly mentions a specific offense ID number (e.g., "tell me about offense 12345")
    - User references a known offense ID from QRadar (e.g., "what's offense 131140?")
    - User asks "lookup offense ID X" or "get offense number Y"

    DO NOT use this tool when:
    - User asks for "today's offenses" or "recent offenses" (use list_qradar_offenses)
    - User asks to "show offenses" or "list offenses" (use list_qradar_offenses)
    - User wants to see multiple offenses (use list_qradar_offenses)
    - No specific offense ID is mentioned (use list_qradar_offenses)

    Returns offense description, severity, magnitude, event counts, source IPs, and categories.

    Args:
        offense_id: The QRadar offense ID number (e.g., 12345, 131140) - REQUIRED, must be provided by user
    """
    if not _qradar_client:
        return "Error: QRadar service is not initialized."

    logging.info(f"Getting QRadar offense {offense_id}")

    result = _qradar_client.get_offense(offense_id)

    if "error" in result:
        return f"Error: {result['error']}"

    return QRadarClient.format_offense_summary(result)


@tool
@log_tool_call
def list_qradar_offenses(status: str = "OPEN", limit: int = 10) -> str:
    """List recent QRadar offenses - use this for viewing MULTIPLE offenses or when no specific offense ID is given.

    This is the DEFAULT tool to use for QRadar offense queries when the user does NOT provide a specific offense ID.

    Use this tool when:
    - User asks for "today's offenses" or "recent offenses" or "current offenses"
    - User asks to "get offenses" or "show offenses" or "list offenses"
    - User wants a summary of QRadar offenses (open, closed, all)
    - User asks "what offenses are open?" or "any new offenses?"
    - User asks "show me QRadar offenses" or "what's happening in QRadar?"
    - User does NOT provide a specific offense ID number
    - User wants to see multiple offenses at once

    Returns a list of offenses with ID, description, severity, event count, and status.
    Offenses are sorted by last updated time (most recent first).

    Args:
        status: Offense status filter - "OPEN", "HIDDEN", "CLOSED", or "all" for no filter (default: "OPEN")
        limit: Maximum number of offenses to return (default: 10, max: 50)
    """
    if not _qradar_client:
        return "Error: QRadar service is not initialized."

    # Validate limit
    limit = min(max(1, limit), 50)

    # Build filter
    filter_query = None
    if status.lower() != "all":
        filter_query = f"status={status.upper()}"

    logging.info(f"Listing QRadar offenses (status={status}, limit={limit})")

    result = _qradar_client.get_offenses(
        filter_query=filter_query,
        sort="-last_updated_time",
        limit=limit
    )

    if "error" in result:
        return f"Error: {result['error']}"

    offenses = result.get("offenses", [])
    if not offenses:
        return f"No {status} offenses found."

    output = [
        "## QRadar Offenses",
        f"**Status Filter:** {status}",
        f"**Count:** {len(offenses)}",
        ""
    ]

    for offense in offenses:
        offense_summary = [
            f"### Offense #{offense.get('id', 'Unknown')}",
            f"**Description:** {offense.get('description', 'N/A')[:100]}...",
            f"**Severity:** {offense.get('severity', 'Unknown')}/10",
            f"**Event Count:** {offense.get('event_count', 0):,}",
            f"**Status:** {offense.get('status', 'Unknown')}",
        ]
        output.append("\n".join(offense_summary))

    return "\n\n".join(output)


@tool
@log_tool_call
def run_qradar_aql_query(aql_query: str) -> str:
    """Run a custom AQL (Ariel Query Language) query directly in QRadar.

    IMPORTANT: If the user's message contains SQL-like syntax (SELECT, FROM, WHERE,
    LIMIT, LAST X HOURS), use THIS tool immediately. Do NOT interpret field names
    like "Threat Name" or "sourceip" as search terms for other tools.

    Use this tool when:
    - User provides ANY text containing SELECT...FROM events or SELECT...FROM flows
    - User asks to "run this AQL", "execute this query", or "run this query"
    - User pastes a query with SQL-like syntax

    Examples of queries that MUST use this tool:
    - "Run this AQL query: SELECT sourceip FROM events LAST 24 HOURS"
    - "SELECT sourceip, \"Threat Name\" FROM events WHERE magnitude > 7 LIMIT 10 LAST 24 HOURS"
    - Any message containing SELECT...FROM events/flows pattern

    DO NOT use other tools (like threat intel lookups) just because the query mentions
    field names like "Threat Name" - those are QRadar database columns, not search terms.

    Args:
        aql_query: The AQL query to execute (e.g., "SELECT * FROM events LAST 1 HOURS LIMIT 10")
    """
    if not _qradar_client:
        return "Error: QRadar service is not initialized."

    aql_query = aql_query.strip()

    if not aql_query:
        return "Error: AQL query cannot be empty."

    logging.info(f"Running AQL query: {aql_query[:100]}...")

    result = _qradar_client.run_aql_search(aql_query, timeout=120, max_results=100)

    if "error" in result:
        return f"Error: {result['error']}"

    events = result.get("events", result.get("flows", []))

    if not events:
        return "Query completed but returned no results."

    output = [
        "## QRadar AQL Query Results",
        f"**Query:** `{aql_query[:80]}...`" if len(aql_query) > 80 else f"**Query:** `{aql_query}`",
        "",
        _format_events_for_display(events)
    ]

    return "\n".join(output)


# Sample prompts for testing:
# - "Show me the last 5 open offenses in QRadar"
# - "Search QRadar for any events from IP 10.0.0.50 in the last 12 hours"
# - "Get details on QRadar offense 131140"
# - "Search QRadar for any activity involving evil.com"
# - "List all closed offenses"
# - "Run this AQL query: SELECT sourceip, destinationip, eventname FROM events LAST 1 HOURS LIMIT 5"
