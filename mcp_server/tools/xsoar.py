"""XSOAR SOAR tools."""

import logging
from typing import Optional

from mcp_server.server import mcp

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        from services.xsoar.ticket_handler import TicketHandler
        _client = TicketHandler()
    return _client


_SUMMARY_FIELDS = ("id", "name", "type", "status", "severity", "owner",
                    "created", "closed", "CustomFields.hostname",
                    "CustomFields.detectionname", "CustomFields.sourceip")


def _slim_ticket(ticket: dict) -> dict:
    """Extract only the fields needed for a summary table."""
    slim = {}
    for field in _SUMMARY_FIELDS:
        if "." in field:
            parts = field.split(".", 1)
            slim[parts[1]] = (ticket.get(parts[0]) or {}).get(parts[1])
        else:
            slim[field] = ticket.get(field)
    return slim


@mcp.tool(tags={"readonly"})
def xsoar_get_tickets(query: str, size: int = 100) -> dict:
    """Search XSOAR incidents by query string. Returns summary fields only.

    Args:
        query: XSOAR search query (e.g. 'status:Active -category:job')
        size: Max incidents to return
    """
    client = _get_client()
    tickets = client.get_tickets(query, size=size)
    return {"count": len(tickets), "tickets": [_slim_ticket(t) for t in tickets]}


@mcp.tool(tags={"readonly"})
def xsoar_search_tickets(
    text: str,
    days_back: int = 30,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    incident_type: str = "CIRT",
    size: int = 50,
) -> dict:
    """Free-text live search across XSOAR tickets (no local index).

    Combines a free-text term with optional metadata filters. For deep
    details on a single hit, follow up with xsoar_get_case(incident_id).

    Args:
        text: Free-text search — matches name, details, notes, custom fields.
              Wrap exact phrases in double quotes.
        days_back: Limit to last N days (default 30). 0 = all-time.
        status: Optional 'Active' or 'closed'.
        severity: Optional 'Low', 'Medium', 'High', 'Critical'.
        incident_type: XSOAR type, exact match (default 'CIRT'; does NOT
                       include 'CIRT IOC Hunt'). Empty string = all.
        size: Max results (default 50).
    """
    from datetime import datetime, timedelta, timezone

    parts: list[str] = []
    text = (text or "").strip()
    if text:
        parts.append(text)
    if incident_type:
        parts.append(f"type:{incident_type}")
    if status:
        parts.append(f"status:{status}")
    if severity:
        parts.append(f"severity:{severity}")
    if days_back and days_back > 0:
        since = (datetime.now(timezone.utc) - timedelta(days=days_back)) \
            .strftime("%Y-%m-%dT%H:%M:%SZ")
        parts.append(f'created:>="{since}"')

    query = " ".join(parts).strip()
    client = _get_client()
    tickets = client.get_tickets(query, size=size, paginate=False)
    return {
        "count": len(tickets),
        "query": query,
        "tickets": [_slim_ticket(t) for t in tickets],
    }


def _slim_closed_ticket(ticket: dict) -> dict:
    """Slim a closed-ticket dict, including impact / close fields."""
    base = _slim_ticket(ticket)
    cf = ticket.get("CustomFields", {}) or {}
    base.update({
        "impact": cf.get("impact"),
        "closeReason": ticket.get("closeReason"),
        "closeNotes": (ticket.get("closeNotes") or "")[:500],
    })
    return base


@mcp.tool(tags={"readonly"})
def xsoar_get_closed_tickets_by_period(
    start: str,
    end: str,
    impact: Optional[str] = None,
    include_unowned: bool = False,
    include_notes: bool = True,
    size: int = 200,
) -> dict:
    """CIRT tickets closed in a window — shift performance / close-rate review.

    Always excludes job-category and IOC Hunt tickets. By default also
    excludes unowned (playbook auto-close) tickets — set include_unowned=True
    for auto-close ratio analysis.

    Args:
        start: Eastern time, format 'YYYY-MM-DDTHH:MM:SS' (e.g. '2026-04-16T07:00:00').
        end:   Same format, exclusive.
        impact: 'Benign True Positive' | 'False Positive' | 'Ignore' |
                'Security Testing' | 'Malicious True Positive'.
        include_unowned: Default False (skip auto-closes).
        include_notes: Default True; disable for very large windows.
        size: Max tickets (default 200).
    """
    from concurrent.futures import ThreadPoolExecutor
    from datetime import datetime
    from zoneinfo import ZoneInfo

    eastern = ZoneInfo("America/New_York")

    def _fmt(dt_str: str) -> str:
        dt = datetime.fromisoformat(dt_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=eastern)
        s = dt.strftime("%Y-%m-%dT%H:%M:%S%z")
        return s[:-2] + ":" + s[-2:]

    parts = [
        "status:closed",
        "-category:job",
        "type:CIRT",
        '-type:"CIRT IOC Hunt"',
    ]
    if not include_unowned:
        parts.append('-owner:""')
    parts.append(f'closed:>="{_fmt(start)}"')
    parts.append(f'closed:<"{_fmt(end)}"')
    query = " ".join(parts)

    client = _get_client()
    tickets = client.get_tickets(query, size=size)

    # Post-hoc impact filter (XSOAR query language is unreliable on CustomFields)
    if impact:
        tickets = [
            t for t in tickets
            if (t.get("CustomFields") or {}).get("impact") == impact
        ]

    slim_tickets = [_slim_closed_ticket(t) for t in tickets]

    if include_notes and slim_tickets:
        def _fetch(t):
            try:
                return t["id"], client.get_user_notes(t["id"])
            except Exception as e:
                logger.warning(f"Failed to fetch notes for {t.get('id')}: {e}")
                return t["id"], []

        with ThreadPoolExecutor(max_workers=8) as ex:
            notes_by_id = dict(ex.map(_fetch, slim_tickets))

        for t in slim_tickets:
            t["notes"] = notes_by_id.get(t["id"], [])

    return {
        "count": len(slim_tickets),
        "query": query,
        "tickets": slim_tickets,
    }


@mcp.tool(tags={"readonly"})
def xsoar_get_case_full(incident_id: str) -> dict:
    """Full XSOAR case dump — escape hatch. Prefer xsoar_get_case.

    ⚠️ Returns the entire investigation including war-room entries,
    playbook outputs, integration command results, every analyst note.
    Typically 20K-100K tokens. Use only when xsoar_get_case (slim) is
    missing a field you need (raw playbook output / war-room transcript).

    Args:
        incident_id: The XSOAR incident ID
    """
    client = _get_client()
    return client.get_case_data_with_notes(incident_id)


@mcp.tool(tags={"readonly"})
def xsoar_get_case_image(incident_id: str, image_ref: str) -> dict:
    """Download a screenshot/image embedded in an XSOAR case note to disk.

    Analysts paste evidence (original-request emails, tool screenshots) into
    war-room notes as markdown images. The investigation API returns these as
    `![image.png](/xsoar/markdown/image/<name>)` references, NOT as text/bytes.
    This tool fetches the raw image so it can be viewed/OCR'd, and returns the
    local file path to read.

    Args:
        incident_id: The XSOAR incident ID (namespaces the output directory).
        image_ref: The image reference — accepts a bare filename, the
            `/xsoar/markdown/image/<name>` path, a full URL, or the whole
            `![alt](path)` markdown snippet copied from a note.

    Returns:
        {"path", "filename", "bytes", "content_type"} — read `path` to view it.
    """
    client = _get_client()
    return client.get_case_image(incident_id, image_ref)


@mcp.tool(tags={"readonly"})
def xsoar_get_case(
    incident_id: str,
    max_notes: int = 5,
    note_chars: int = 800,
) -> dict:
    """Get an XSOAR case by ID — slim summary, default for pull/fetch/get prompts.

    Returns core ticket fields + recent analyst notes (truncated). For full
    war-room / playbook / integration history use xsoar_get_case_full.

    Args:
        incident_id: The XSOAR incident ID.
        max_notes: Most recent N analyst notes (default 5).
        note_chars: Truncate each note to this many chars (default 800).
    """
    client = _get_client()
    case = client.get_case_data(incident_id)
    cf = case.get("CustomFields") or {}

    all_notes = client.get_user_notes(incident_id)
    trimmed_notes = [
        {
            "author": n.get("author"),
            "created_at": n.get("created_at"),
            "note_text": (n.get("note_text") or "")[:note_chars],
        }
        for n in all_notes[:max_notes]
    ]

    return {
        "id": case.get("id"),
        "name": case.get("name"),
        "type": case.get("type"),
        "status": case.get("status"),
        "severity": case.get("severity"),
        "owner": case.get("owner"),
        "created": case.get("created"),
        "closed": case.get("closed"),
        "impact": cf.get("impact"),
        "closeReason": case.get("closeReason"),
        "closeNotes": (case.get("closeNotes") or "")[:1500],
        "hostname": cf.get("hostname"),
        "detectionname": cf.get("detectionname"),
        "sourceip": cf.get("sourceip"),
        "note_count": len(all_notes),
        "notes": trimmed_notes,
    }


@mcp.tool(tags={"mutating"})
def xsoar_create_incident(payload: dict) -> dict:
    """Create a new XSOAR incident.

    Args:
        payload: Incident creation payload with fields like name, type, severity, etc.
    """
    client = _get_client()
    return client.create(payload)


@mcp.tool(tags={"mutating"})
def xsoar_update_incident(ticket_id: str, update_data: dict) -> dict:
    """Update fields on an existing XSOAR incident.

    Args:
        ticket_id: The XSOAR incident ID
        update_data: Dict of fields to update
    """
    client = _get_client()
    return client.update_incident(ticket_id, update_data)


@mcp.tool(tags={"mutating"})
def xsoar_add_note(incident_id: str, note: str, markdown: bool = True) -> dict:
    """Add a note/entry to an existing XSOAR ticket.

    Args:
        incident_id: The XSOAR incident ID
        note: Note content (supports markdown)
        markdown: Whether the note uses markdown formatting
    """
    client = _get_client()
    return client.create_new_entry_in_existing_ticket(
        incident_id, note, markdown=markdown
    )


@mcp.tool(tags={"mutating"})
def xsoar_complete_task(ticket_id: str, task_name: str, task_input: str = "") -> dict:
    """Complete a playbook task in an XSOAR incident.

    Args:
        ticket_id: The XSOAR incident ID
        task_name: Name of the playbook task to complete
        task_input: Optional input for the task
    """
    client = _get_client()
    result = client.complete_task(ticket_id, task_name, task_input=task_input)
    return {"success": True, "result": result}


@mcp.tool(tags={"mutating"})
def xsoar_link_tickets(parent_ticket_id: str, link_ticket_id: str) -> dict:
    """Link two XSOAR tickets together.

    Args:
        parent_ticket_id: The parent incident ID
        link_ticket_id: The incident ID to link
    """
    client = _get_client()
    result = client.link_tickets(parent_ticket_id, link_ticket_id)
    if result is None:
        return {"error": "Failed to link tickets"}
    return result
