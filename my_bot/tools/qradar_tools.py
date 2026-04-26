"""
QRadar Tools Module

Provides QRadar SIEM integration for security event searches and offense management.
Supports AQL queries, event searches, and offense lookups.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Optional

from langchain_core.tools import tool

from services.qradar import QRadarClient
from src.utils.tool_decorator import log_tool_call
from src.utils.llm_decorators import validate_args, IP_ADDRESS_PATTERN, DOMAIN_PATTERN

# Lazy-initialized QRadar client
_qradar_client: Optional[QRadarClient] = None

# Lazy-initialized LLM for NL→AQL translation (separate from the security assistant bot's main LLM
# so the system prompt + few-shots stay scoped to AQL generation only)
_nl_to_aql_llm = None


def _get_qradar_client() -> Optional[QRadarClient]:
    """Get QRadar client (lazy initialization)."""
    global _qradar_client
    if _qradar_client is None:
        try:
            client = QRadarClient()
            if client.is_configured():
                _qradar_client = client
            else:
                logging.warning("QRadar client not configured (missing API URL or key)")
        except Exception as e:
            logging.error(f"Failed to initialize QRadar client: {e}")
    return _qradar_client


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
        if "logsource" in event:
            event_lines.append(f"**Log Source:** {event['logsource']}")
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
@validate_args(ip_address=IP_ADDRESS_PATTERN)
@log_tool_call
def search_qradar_by_ip(ip_address: str, hours: int = 24) -> str:
    """Search QRadar SIEM for security events involving an IP address.

    Use this tool when:
    - User asks to search QRadar for an IP address
    - User wants to check if an IP has any security events or alerts
    - User is investigating suspicious activity from/to an IP
    - User asks "any events for IP X?" or "search SIEM for IP"

    Searches both sourceip and destinationip across all log sources.
    Returns events with source/dest IPs, event names, log source, magnitude, and timestamps.

    NOTE: For more targeted IP searches (specific log source, aggregation, or custom fields),
    use run_qradar_aql_query instead with a hand-crafted query.

    Args:
        ip_address: The IP address to search for (e.g., "<internal-host>", "<internal-host>")
        hours: Number of hours to look back (default: 24, max: 168)
    """
    client = _get_qradar_client()
    if not client:
        return "Error: QRadar service is not available."

    ip_address = ip_address.strip()

    # Validate hours
    hours = min(max(1, hours), 168)  # Clamp between 1-168 hours

    logging.info(f"Searching QRadar for IP {ip_address} over last {hours} hours")

    result = client.search_events_by_ip(ip_address, hours=hours)

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
@validate_args(domain=DOMAIN_PATTERN)
@log_tool_call
def search_qradar_by_domain(domain: str, hours: int = 24) -> str:
    """Search QRadar SIEM for security events involving a domain or URL.

    Use this tool when:
    - User asks to search QRadar for a domain name
    - User wants to check if anyone accessed a suspicious domain
    - User is investigating phishing or malicious URLs
    - User asks "any activity to evil.com?" or "search SIEM for domain"

    Searches URL fields across web proxy, email, O365, and Palo Alto log sources.
    Returns matching events with IPs, URLs, usernames, and timestamps.

    NOTE: For more targeted domain searches (specific log source, aggregation, or custom fields),
    use run_qradar_aql_query instead with a hand-crafted query.

    Args:
        domain: The domain to search for (e.g., "example.com", "malicious-site.net")
        hours: Number of hours to look back (default: 24, max: 168)
    """
    client = _get_qradar_client()
    if not client:
        return "Error: QRadar service is not available."

    domain = domain.strip().lower()
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.split("/")[0]

    # Validate hours
    hours = min(max(1, hours), 168)

    logging.info(f"Searching QRadar for domain {domain} over last {hours} hours")

    result = client.search_events_by_domain(domain, hours=hours)

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
    client = _get_qradar_client()
    if not client:
        return "Error: QRadar service is not available."

    logging.info(f"Getting QRadar offense {offense_id}")

    result = client.get_offense(offense_id)

    if "error" in result:
        return f"Error: {result['error']}"

    return QRadarClient.format_offense_summary(result)


def _format_epoch_ms(epoch_ms) -> str:
    """Convert epoch milliseconds to human-readable UTC string."""
    try:
        ts = int(epoch_ms) / 1000
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, OSError, TypeError):
        return "Unknown"


@tool
@log_tool_call
def list_qradar_offenses(status: str = "OPEN", hours_back: int = 0, limit: int = 10) -> str:
    """List QRadar offenses, optionally filtered to a recent time window.

    This is the DEFAULT tool to use for QRadar offense queries when the user does NOT provide a specific offense ID.

    Use this tool when:
    - User asks for "today's offenses" or "recent offenses" or "current offenses"
    - User asks to "get offenses" or "show offenses" or "list offenses"
    - User wants a summary of QRadar offenses (open, closed, all)
    - User asks "what offenses are open?" or "any new offenses?"
    - User asks "show me QRadar offenses" or "what's happening in QRadar?"
    - User does NOT provide a specific offense ID number
    - User wants to see multiple offenses at once

    IMPORTANT: When the user asks for "today's" offenses, set hours_back=24.
    When they ask for "recent" or "this week", set hours_back=168.
    When they just say "open offenses" with no time qualifier, leave hours_back=0 (no time filter).

    Returns a list of offenses with ID, description, severity, event count, status, source, categories, and timestamps.
    Offenses are sorted by start_time (most recent first) when a time filter is used, otherwise by last_updated_time.

    Args:
        status: Offense status filter - "OPEN", "HIDDEN", "CLOSED", or "all" for no filter (default: "OPEN")
        hours_back: Only return offenses created within this many hours (0 = no time filter, default: 0)
        limit: Maximum number of offenses to return (default: 10, max: 50)
    """
    client = _get_qradar_client()
    if not client:
        return "Error: QRadar service is not available."

    # Validate limit
    limit = min(max(1, limit), 50)

    # Build filter
    filters = []
    if status.lower() != "all":
        filters.append(f"status={status.upper()}")

    if hours_back > 0:
        cutoff_ms = int((datetime.now(timezone.utc).timestamp() - hours_back * 3600) * 1000)
        filters.append(f"start_time > {cutoff_ms}")

    filter_query = " AND ".join(filters) if filters else None
    sort_field = "-start_time" if hours_back > 0 else "-last_updated_time"

    logging.info(f"Listing QRadar offenses (status={status}, hours_back={hours_back}, limit={limit})")

    result = client.get_offenses(
        filter_query=filter_query,
        sort=sort_field,
        limit=limit
    )

    if "error" in result:
        return f"Error: {result['error']}"

    offenses = result.get("offenses", [])
    if not offenses:
        time_note = f" in the last {hours_back} hours" if hours_back > 0 else ""
        return f"No {status} offenses found{time_note}."

    time_label = f" (last {hours_back}h)" if hours_back > 0 else ""
    output = [
        "## QRadar Offenses",
        f"**Status:** {status}{time_label}",
        f"**Count:** {len(offenses)}",
        ""
    ]

    for offense in offenses:
        offense_source = offense.get("offense_source", "")
        categories = offense.get("categories", [])
        start_time = offense.get("start_time")
        last_updated = offense.get("last_updated_time")

        offense_summary = [
            f"### Offense #{offense.get('id', 'Unknown')}",
            f"**Description:** {offense.get('description', 'N/A')}",
            f"**Severity:** {offense.get('severity', 'Unknown')}/10 | **Magnitude:** {offense.get('magnitude', 'Unknown')}/10",
            f"**Events:** {offense.get('event_count', 0):,} | **Status:** {offense.get('status', 'Unknown')}",
        ]
        if offense_source:
            offense_summary.append(f"**Source:** {offense_source}")
        if categories:
            offense_summary.append(f"**Categories:** {', '.join(categories[:5])}")
        if start_time:
            offense_summary.append(f"**Created:** {_format_epoch_ms(start_time)}")
        if last_updated:
            offense_summary.append(f"**Last Updated:** {_format_epoch_ms(last_updated)}")

        output.append("\n".join(offense_summary))

    output.append("")
    output.append("---")
    output.append("NOTE: Present only the data above. Do not add MITRE ATT&CK mappings, threat attributions, or analysis beyond what is shown here.")

    return "\n\n".join(output)


@tool
@log_tool_call
def run_qradar_aql_query(aql_query: str) -> str:
    """Run an AQL (Ariel Query Language) query in QRadar. Also use this tool to WRITE
    AQL from scratch when the user asks a natural-language question about SIEM event data
    (e.g., "show top blocked domains", "who accessed evil.com", "high severity events today").

    WHEN TO USE:
    - User provides raw AQL (SELECT...FROM events)
    - User asks a natural-language question about event/log data that requires querying QRadar
    - User asks about traffic, connections, authentications, threats, or endpoint activity

    AQL SYNTAX (clause order is strict):
      SELECT cols FROM events WHERE conditions [GROUP BY col] [ORDER BY col DESC] [LIMIT N] LAST N HOURS|DAYS
    - When combining OR with AND, always parenthesize the OR: WHERE (A OR B) AND C
    - Time window REQUIRED: always end with LAST N HOURS or LAST N DAYS
    - String matching: ILIKE '%value%' (case-insensitive), LIKE (case-sensitive)
    - Double-quote custom properties: "Threat Name", "Computer Hostname", "User Agent"
    - Functions: qidname(qid) AS eventName, logsourcename(logsourceid) AS logSource,
      CATEGORYNAME(category), DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS time
    - Offense events: WHERE INOFFENSE(offense_id)
    - Top-N pattern: SELECT col, COUNT(*) AS cnt FROM events WHERE ... GROUP BY col ORDER BY cnt DESC LIMIT 10 LAST 24 HOURS
    - Time series: SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:00') AS hour, COUNT(*) AS cnt FROM events WHERE ... GROUP BY hour ORDER BY hour ASC LAST 24 HOURS

    LOG SOURCES & FIELDS (filter with logsourcetypename(devicetype) = '...'):
    - Web Proxy (Zscaler Nss / Blue Coat): sourceip, destinationip, "Computer Hostname", username, URL, "Referer", "User Agent", filename, "Action" (Allowed/Blocked/nss-fw)
    - Email (Area1 Security / Abnormal Security): sourceip, username, sender, recipient, "Subject"
    - Office 365 (deviceType='397', Operation IN ('TIUrlClickData','TIMailData')): username, URL, "Subject", "Filename"
    - Palo Alto (Palo Alto PA Series): sourceip, destinationip, "Threat Name", "Action", URL, "TSLD", "PAN Log SubType"
    - Endpoint (CrowdStrike Falcon / Tanium): "Computer Hostname", username, "Process Name", "Command", "MD5 Hash", "SHA256 Hash"
    - Entra ID (Microsoft Azure Active Directory): username, sourceip, Operation, "Conditional Access Status", "Region"
    - ZPA (Zscaler Private Access): username, sourceip, "ZPN-Sess-Status"
    - Common fields (all sources): sourceip, destinationip, destinationport, username, starttime, magnitude (0-10)

    PERFORMANCE: NEVER GROUP BY URL (millions of unique values, will time out). Use GROUP BY "TSLD" for domain aggregations.
    When grouping, exclude nulls: add "TSLD" IS NOT NULL (or relevant field) to WHERE.
    HARD CAP — max time window is LAST 4 HOURS. Never use LAST N DAYS. Never use LAST N HOURS where N > 4. Even "today" / "this morning" should be LAST 4 HOURS. The tool will rewrite anything larger to 4 HOURS automatically.

    Args:
        aql_query: The AQL query to execute, or a well-formed SELECT statement you construct from the user's question.
    """
    from services.qradar import cap_aql_time_window

    client = _get_qradar_client()
    if not client:
        return "Error: QRadar service is not available."

    aql_query = aql_query.strip()

    if not aql_query:
        return "Error: AQL query cannot be empty."

    # Only allow SELECT queries — reject destructive statements
    aql_upper = aql_query.upper().lstrip('(')
    forbidden = ('DELETE', 'UPDATE', 'INSERT', 'DROP', 'ALTER', 'CREATE', 'TRUNCATE')
    if not aql_upper.startswith('SELECT'):
        return "Error: Only SELECT queries are allowed."
    if any(keyword in aql_upper for keyword in forbidden):
        return "Error: Only SELECT queries are allowed."

    # Auto-append LIMIT 100 if no LIMIT clause
    if 'LIMIT' not in aql_upper:
        aql_query += ' LIMIT 100'

    # Auto-append LAST 4 HOURS if no time clause (4-hour cap on LLM-facing tools)
    if 'LAST' not in aql_upper and 'START' not in aql_upper:
        aql_query += ' LAST 4 HOURS'

    # Defensive cap: rewrite any window larger than 4 HOURS, regardless of source
    capped = cap_aql_time_window(aql_query, max_hours=4)
    if capped != aql_query:
        logging.info("AQL time window capped to 4 HOURS: %r → %r", aql_query[-40:], capped[-40:])
        aql_query = capped

    logging.info(f"Running AQL query: {aql_query[:100]}...")

    result = client.run_aql_search(aql_query, timeout=300, max_results=100)

    if "error" in result:
        return (
            "Error: QRadar rejected the query and no data was retrieved.\n"
            "Tell the user the query failed. DO NOT invent example data, "
            "placeholder usernames, or fabricated rows.\n"
            f"Underlying error: {result['error']}"
        )

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


# ── NL → AQL specialist tool ──
#
# Reuses the prompt assets from the qradar-chat web handler so the two surfaces
# stay in sync (categories, schemas, AQL reference, system prompt, code-block parser).


def _get_nl_to_aql_llm():
    """Lazy-init a small failover LLM dedicated to NL→AQL translation."""
    global _nl_to_aql_llm
    if _nl_to_aql_llm is None:
        from my_bot.utils.llm_factory import create_metiq_llm
        _nl_to_aql_llm = create_metiq_llm(
            max_tokens=2048, timeout=300,
            extra_body={"chat_template_kwargs": {"enable_thinking": False}},
        )
    return _nl_to_aql_llm


# Keyword → category mapping for auto-detection.
# the security assistant bot has no sidebar — when the caller doesn't specify a category, we score
# the question against these keywords and pick the highest-scoring match.
# Order matters only as a tiebreaker (first match wins on equal scores).
_CATEGORY_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    ("web_proxy", (
        "web proxy", "zscaler nss", "blue coat", "bluecoat", "browse", "browsed",
        "blocked domain", "blocked url", "blocked site", "user agent", "referer",
        "downloaded file", "url category", "web filter",
    )),
    ("email", (
        "email", "e-mail", "sender", "recipient", "subject line", "phish",
        "phishing", "area1", "abnormal security", "mail flow", "inbound mail",
        "threat mail", "malicious mail", "spam",
    )),
    ("o365", (
        "o365", "office 365", "office365", "microsoft 365", "tiurlclick", "timaildata",
        "air investigation", "url click", "safe links", "atp", "defender for office",
    )),
    ("paloalto", (
        "palo alto", "paloalto", "pan-os", "panos", "pa series", "wildfire",
        "firewall threat", "pan log", "tsld", "url filtering",
    )),
    ("endpoint", (
        "endpoint", "crowdstrike", "falcon", "tanium", "process name", "command line",
        "md5", "sha256", "file hash", "host activity", "edr", "noisy host", "noisiest host",
    )),
    ("entra_id", (
        "entra", "azure ad", "azure active directory", "aad", "sign-in", "signin",
        "sign in", "conditional access", "ca policy", "interactive login", "mfa",
    )),
    ("zpa", (
        "zpa", "zscaler private access", "zpn-sess", "private access session",
    )),
]


def _infer_category(question: str) -> str:
    """Pick the best log source category for a question via keyword scoring.

    Returns the category id with the most keyword hits, or 'all_events' if no
    category scores above zero. This replaces the sidebar dataset-picker that
    the qradar-chat web page has.
    """
    if not question:
        return "all_events"
    q = question.lower()
    best_id = "all_events"
    best_score = 0
    for cat_id, keywords in _CATEGORY_KEYWORDS:
        score = sum(1 for kw in keywords if kw in q)
        if score > best_score:
            best_score = score
            best_id = cat_id
    return best_id


@tool
@log_tool_call
def nl_to_aql_query(question: str, category: str = "auto") -> str:
    """Translate a natural-language question into AQL, execute it in QRadar, and return results.

    This is the smartest QRadar tool — use it whenever the user asks an English question about
    SIEM data and you want a focused, log-source-aware query without writing AQL yourself.
    A specialist LLM handles AQL generation with category-specific schemas and few-shot examples,
    so the security assistant bot doesn't need to know AQL syntax.

    DATASET SELECTION: The tool auto-detects the right log source category from keywords in the
    question (e.g. "Entra sign-in" → entra_id, "blocked domain" → web_proxy). You normally don't
    need to pass `category` — leave it as "auto" and it'll pick the best match. Only set it
    explicitly if the user names a specific dataset and the keywords are ambiguous.

    Use this tool when:
    - User asks a natural-language question about SIEM/QRadar event data
      (e.g., "show top blocked domains", "any failed sign-ins in Entra?",
       "what threats did Palo Alto detect today?", "noisiest endpoints in the last hour")
    - User asks an exploratory SIEM question without providing AQL
    - You want pre-built schemas, log-source filters, and AQL guidance applied automatically

    Available categories (auto-detected from question; pass explicitly only if you must override):
    - web_proxy   — Zscaler NSS & Blue Coat web proxy logs
    - email       — Area1 & Abnormal email security
    - o365        — Office 365 threat intel (URL clicks, mail data, AIR investigations)
    - paloalto    — Palo Alto firewall threats and traffic
    - endpoint    — CrowdStrike Falcon & Tanium endpoint detections
    - entra_id    — Microsoft Entra ID / Azure AD sign-ins
    - zpa         — Zscaler Private Access sessions
    - all_events  — Any log source (cross-source searches or when no dataset matches)

    NOTE: For raw AQL the user provides verbatim, use run_qradar_aql_query.
    For simple IP/domain searches with no aggregation, use search_qradar_by_ip / search_qradar_by_domain.

    Args:
        question: The user's natural-language question (e.g., "Top 10 source IPs in the last hour")
        category: Log source category id, or "auto" (default) to auto-detect from the question
    """
    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
    from src.components.web.qradar_chat_handler import (
        _CATEGORIES_BY_ID,
        _extract_aql,
        AQL_REFERENCE,
        SYSTEM_PROMPT,
    )

    client = _get_qradar_client()
    if not client:
        return "Error: QRadar service is not available."

    question = (question or "").strip()
    if not question:
        return "Error: question cannot be empty."

    # Auto-detect category from question keywords if not explicitly set
    inferred = False
    if not category or category.lower() == "auto":
        category = _infer_category(question)
        inferred = True
        logging.info("NL→AQL auto-detected category=%s for question=%r", category, question[:80])

    cat = _CATEGORIES_BY_ID.get(category)
    if not cat:
        valid = ", ".join(c["id"] for c in _CATEGORIES_BY_ID.values())
        return f"Error: unknown category '{category}'. Valid: {valid}"

    schema = cat.get("schema", "No schema available.")
    log_source_filter = cat.get("log_source_filter")

    if log_source_filter:
        log_source_rule = f"Always include this log source filter in WHERE: {log_source_filter}"
        category_context = f"Category: {cat.get('name', category)}\n{cat.get('description', '')}"
    else:
        log_source_rule = "No default log source filter — user may query any source"
        category_context = "All Events — no log source restriction"

    today = datetime.now().strftime("%B %d, %Y")
    system = SYSTEM_PROMPT.format(
        schema=schema, today=today,
        log_source_rule=log_source_rule,
        category_context=category_context,
        aql_reference=AQL_REFERENCE,
    )

    # Few-shot example — teaches parenthesization of any OR-joined log source filter
    wrapped_filter = (
        f"({log_source_filter})" if log_source_filter and " OR " in log_source_filter
        else (log_source_filter or "1=1")
    )
    msgs = [
        SystemMessage(content=system),
        HumanMessage(content="Show me the top 10 source IPs in the last hour"),
        AIMessage(content=(
            "```aql\nSELECT sourceip, COUNT(*) AS cnt\n"
            "FROM events\n"
            f"WHERE {wrapped_filter}\n"
            "GROUP BY sourceip\nORDER BY cnt DESC\nLIMIT 10\nLAST 1 HOURS\n```"
        )),
    ]
    if log_source_filter and " OR " in log_source_filter:
        msgs.append(HumanMessage(content="Top blocked domains"))
        msgs.append(AIMessage(content=(
            "```aql\nSELECT \"TSLD\", COUNT(*) AS cnt\n"
            "FROM events\n"
            f"WHERE ({log_source_filter})\n"
            "  AND \"Action\" = 'Blocked'\n"
            "  AND \"TSLD\" IS NOT NULL\n"
            "GROUP BY \"TSLD\"\nORDER BY cnt DESC\nLIMIT 10\nLAST 1 HOURS\n```"
        )))
    msgs.append(HumanMessage(content=question))

    # Step 1: Generate AQL via specialist LLM
    try:
        llm = _get_nl_to_aql_llm()
        resp = llm.invoke(msgs)
    except Exception as exc:
        logging.error("NL→AQL LLM call failed: %s", exc)
        return (
            "Error: QRadar rejected the query and no data was retrieved.\n"
            "Tell the user the query failed. DO NOT invent example data, "
            "placeholder usernames, or fabricated rows.\n"
            f"Underlying error: NL→AQL translation failed: {exc}"
        )

    from services.qradar import cap_aql_time_window

    full_text = (resp.content or "").strip()
    aql_query = _extract_aql(full_text)
    if not aql_query:
        # LLM declined to produce AQL (conversational response) — surface it
        return f"No AQL generated. LLM response:\n\n{full_text}"

    # Step 2: Validate (SELECT only, no destructive)
    aql_upper = aql_query.upper().lstrip("(")
    forbidden = ("DELETE", "UPDATE", "INSERT", "DROP", "ALTER", "CREATE", "TRUNCATE")
    if not aql_upper.startswith("SELECT"):
        return f"Error: generated query is not a SELECT.\n\n```aql\n{aql_query}\n```"
    if any(kw in aql_upper for kw in forbidden):
        return f"Error: generated query contains forbidden keyword.\n\n```aql\n{aql_query}\n```"

    # Step 2b: Cap the time window — LLM may emit 24h queries that time out
    capped = cap_aql_time_window(aql_query, max_hours=4)
    if capped != aql_query:
        logging.info("NL→AQL time window capped to 4 HOURS: %r → %r",
                     aql_query[-40:], capped[-40:])
        aql_query = capped

    # Step 3: Execute
    logging.info("Executing NL→AQL query (category=%s): %s", category, aql_query[:120])
    result = client.run_aql_search(aql_query, timeout=300, max_results=100)

    cat_label = f"{cat.get('name', category)}" + (" (auto-detected)" if inferred else "")

    if "error" in result:
        return (
            f"## NL→AQL Query (dataset: {cat_label})\n\n"
            f"**Question:** {question}\n\n"
            f"**Generated AQL:**\n```aql\n{aql_query}\n```\n\n"
            "**Error: QRadar rejected the query and no data was retrieved.**\n"
            "Tell the user the query failed. DO NOT invent example data, "
            "placeholder usernames, or fabricated rows.\n"
            f"Underlying error: {result['error']}"
        )

    events = result.get("events", result.get("flows", []))
    output = [
        f"## NL→AQL Query (dataset: {cat_label})",
        f"**Question:** {question}",
        "",
        f"**Generated AQL:**\n```aql\n{aql_query}\n```",
        "",
    ]
    if not events:
        output.append("Query executed successfully but returned **no results**.")
    else:
        output.append(_format_events_for_display(events))

    return "\n".join(output)


# Sample prompts for testing:
# - "Show me the last 5 open offenses in QRadar"
# - "Search QRadar for any events from IP <internal-host> in the last 12 hours"
# - "Get details on QRadar offense 131140"
# - "Search QRadar for any activity involving evil.com"
# - "List all closed offenses"
# - "Run this AQL query: SELECT sourceip, destinationip, eventname FROM events LAST 1 HOURS LIMIT 5"
# - "Top blocked domains in web proxy in the last hour" (→ nl_to_aql_query category=web_proxy)
# - "Any failed Entra sign-ins today?" (→ nl_to_aql_query category=entra_id)
