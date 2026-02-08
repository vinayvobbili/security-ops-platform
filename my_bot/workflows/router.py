"""
Workflow Router

Routes queries to LangGraph workflows when explicitly requested via the 'workflow' command.

Usage:
    workflow investigate 1.2.3.4 and add results to XSOAR ticket 12345
    workflow full analysis of evil-domain.com
    workflow incident response for ticket 929947

The explicit command approach avoids regex pattern matching maintenance burden
and makes user intent clear. If not using the workflow command, the LLM handles
the query through normal LangChain tool calling.
"""

import re
import logging
from typing import Optional, Tuple, Literal

logger = logging.getLogger(__name__)

# Command prefix for workflow
WORKFLOW_PREFIX = "workflow "


def is_workflow_command(query: str) -> bool:
    """
    Check if query is an explicit workflow command.

    Args:
        query: The user's query string

    Returns:
        True if query starts with 'workflow '
    """
    return query.lower().strip().startswith(WORKFLOW_PREFIX)


def strip_workflow_prefix(query: str) -> str:
    """
    Remove the 'workflow' prefix from a query.

    Args:
        query: The user's query string

    Returns:
        Query with prefix removed
    """
    query_lower = query.lower().strip()
    if query_lower.startswith(WORKFLOW_PREFIX):
        return query[len(WORKFLOW_PREFIX):].strip()
    return query


def detect_workflow_type(query: str) -> Literal["ioc_investigation", "incident_response", "unknown"]:
    """
    Determine which workflow to run based on the query content.
    Uses simple keyword matching - not regex patterns.

    Args:
        query: The workflow query (with prefix already stripped)

    Returns:
        Workflow type identifier
    """
    query_lower = query.lower()

    # Check for incident/ticket keywords first (more specific)
    ticket_keywords = ["ticket", "incident", "case", "xsoar"]
    if any(kw in query_lower for kw in ticket_keywords):
        ticket_id = extract_ticket_id_from_query(query)
        if ticket_id:
            return "incident_response"

    # Check for IOC-related keywords
    ioc_keywords = ["investigate", "analysis", "analyze", "enrich", "lookup", "check"]
    if any(kw in query_lower for kw in ioc_keywords):
        ioc_value, _ = extract_ioc_from_query(query)
        if ioc_value:
            return "ioc_investigation"

    # If we found an IOC in the query, default to IOC investigation
    ioc_value, _ = extract_ioc_from_query(query)
    if ioc_value:
        return "ioc_investigation"

    return "unknown"


def extract_ioc_from_query(query: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract IOC value and type from a query.

    Args:
        query: The user's query string

    Returns:
        Tuple of (ioc_value, ioc_type) or (None, None) if not found
    """
    # IP address pattern
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'

    # Domain pattern (simplified)
    domain_pattern = r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})\b'

    # Hash patterns (MD5, SHA1, SHA256)
    hash_pattern = r'\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b'

    # URL pattern
    url_pattern = r'(https?://[^\s]+)'

    # Check URL first (most specific)
    url_match = re.search(url_pattern, query)
    if url_match:
        return (url_match.group(1), "url")

    # Check hash (before IP - hash could look like partial IP)
    hash_match = re.search(hash_pattern, query)
    if hash_match:
        return (hash_match.group(1), "hash")

    # Check IP
    ip_match = re.search(ip_pattern, query)
    if ip_match:
        ip = ip_match.group(1)
        # Validate octets
        octets = ip.split('.')
        if all(0 <= int(o) <= 255 for o in octets):
            return (ip, "ip")

    # Check domain
    domain_match = re.search(domain_pattern, query)
    if domain_match:
        domain = domain_match.group(1).lower()
        # Filter out common false positives
        if domain not in ('example.com', 'test.com') and '.' in domain:
            return (domain, "domain")

    return (None, None)


def extract_ticket_id_from_query(query: str) -> Optional[str]:
    """
    Extract XSOAR ticket ID from a query.

    Args:
        query: The user's query string

    Returns:
        Ticket ID string or None if not found
    """
    # Pattern: ticket/case/incident followed by optional # and digits
    patterns = [
        r'(?:ticket|case|incident)\s*#?\s*(\d+)',
        r'#(\d{6,})',  # Just # followed by 6+ digit number
    ]

    for pattern in patterns:
        match = re.search(pattern, query, re.IGNORECASE)
        if match:
            return match.group(1)

    return None


def parse_workflow_request(query: str) -> dict:
    """
    Parse a workflow request to extract parameters.

    Args:
        query: The full query (with 'workflows' prefix)

    Returns:
        Dict with parsed information:
        {
            "workflow_type": "ioc_investigation" | "incident_response" | "unknown",
            "workflow_query": str,  # Query with prefix stripped
            "ioc_value": str | None,
            "ioc_type": str | None,
            "ticket_id": str | None,
        }
    """
    workflow_query = strip_workflow_prefix(query)
    workflow_type = detect_workflow_type(workflow_query)

    ioc_value, ioc_type = extract_ioc_from_query(workflow_query)
    ticket_id = extract_ticket_id_from_query(workflow_query)

    return {
        "workflow_type": workflow_type,
        "workflow_query": workflow_query,
        "ioc_value": ioc_value,
        "ioc_type": ioc_type,
        "ticket_id": ticket_id,
    }


def get_workflow_help() -> str:
    """Return help text for the workflow command."""
    return """## 🔄 Workflow Command

Use `workflow` to run multi-step investigations that query multiple tools automatically.

### Usage
```
workflow <your request>
```

### IOC Investigation Examples
Queries VT, AbuseIPDB, Shodan, Recorded Future, and QRadar (if high risk):
```
workflow investigate 185.220.101.1
workflow analyze domain evil.com
workflow full analysis of 45.155.205.233
workflow check suspicious IP 203.0.113.50
```

### Incident Response Examples
Fetches ticket, checks CrowdStrike, searches QRadar, enriches IOCs:
```
workflow investigate XSOAR ticket 1089073
workflow incident response for case 1089073
workflow triage ticket 1089073 with IOC enrichment
```

### Demo Comparisons
```
workflow investigate 8.8.8.8          → LOW risk (Google DNS)
workflow investigate 185.220.101.1   → HIGH risk (Tor exit node)
```

### When to use workflow vs regular queries

| Use Case | Command |
|----------|---------|
| Quick single-tool check | `check IP on VirusTotal` |
| Full multi-source analysis | `workflow investigate 185.220.101.1` |
| Get ticket info | `get XSOAR ticket 1089073` |
| Full ticket investigation | `workflow investigate XSOAR ticket 1089073` |

**Note:** Without the `workflow` command, the LLM handles queries through normal tool calling.
"""
