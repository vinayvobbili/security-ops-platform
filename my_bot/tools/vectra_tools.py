"""
Vectra AI Tools Module

Provides Vectra AI NDR integration for threat detection and entity lookup.
Supports querying detections, entities (hosts/accounts), and assignments.
"""

import logging
from typing import Optional

from langchain_core.tools import tool

from services.vectra import VectraClient
from src.utils.tool_decorator import log_tool_call

# Lazy-initialized Vectra client
_vectra_client: Optional[VectraClient] = None


def _get_vectra_client() -> Optional[VectraClient]:
    """Get Vectra client (lazy initialization)."""
    global _vectra_client
    if _vectra_client is None:
        try:
            client = VectraClient()
            if client.is_configured():
                _vectra_client = client
            else:
                logging.warning("Vectra client not configured (missing credentials)")
        except Exception as e:
            logging.error(f"Failed to initialize Vectra client: {e}")
    return _vectra_client


def _format_detection_result(detections: list) -> str:
    """Format detection results for display."""
    if not detections:
        return "No detections found matching the criteria."

    lines = [f"## Vectra Detections ({len(detections)} found)", ""]

    for det in detections:
        det_id = det.get("id", "Unknown")
        det_type = det.get("detection_type", "Unknown")
        threat = det.get("threat", 0)
        certainty = det.get("certainty", 0)
        state = det.get("state", "unknown")
        threat_level = VectraClient.get_threat_level(threat, certainty)

        # Get summary info
        summary = det.get("summary", {})
        description = summary.get("description", "No description available")

        # Get associated entity info
        src_entity = det.get("src_linked_account") or det.get("src_host", {})
        entity_name = src_entity.get("name", "Unknown") if isinstance(src_entity, dict) else "Unknown"

        lines.append(f"### Detection #{det_id}: {det_type}")
        lines.append(f"**Threat Level:** {threat_level}")
        lines.append(f"**Scores:** Threat: {threat}/100 | Certainty: {certainty}/100")
        lines.append(f"**State:** {state}")
        lines.append(f"**Entity:** {entity_name}")
        lines.append(f"**Summary:** {description}")
        lines.append("")

    return "\n".join(lines)


def _format_entity_result(entities: list) -> str:
    """Format entity results for display."""
    if not entities:
        return "No entities found matching the criteria."

    lines = [f"## Vectra Entities ({len(entities)} found)", ""]

    for ent in entities:
        entity_id = ent.get("id", "Unknown")
        name = ent.get("name", "Unknown")
        entity_type = ent.get("type", "unknown").title()
        threat = ent.get("threat", 0)
        certainty = ent.get("certainty", 0)
        threat_level = VectraClient.get_threat_level(threat, certainty)

        last_source = ent.get("last_source", "N/A")
        detection_count = ent.get("detection_count", 0)
        is_prioritized = ent.get("is_prioritized", False)
        tags = ent.get("tags", [])

        lines.append(f"### {entity_type} #{entity_id}: {name}")
        lines.append(f"**Threat Level:** {threat_level}")
        lines.append(f"**Scores:** Threat: {threat}/100 | Certainty: {certainty}/100")
        lines.append(f"**Last Source IP:** {last_source}")
        lines.append(f"**Detection Count:** {detection_count}")
        lines.append(f"**Prioritized:** {'Yes' if is_prioritized else 'No'}")
        if tags:
            lines.append(f"**Tags:** {', '.join(tags)}")
        lines.append("")

    return "\n".join(lines)


def _format_single_detection(det: dict) -> str:
    """Format a single detection for detailed display."""
    det_id = det.get("id", "Unknown")
    det_type = det.get("detection_type", "Unknown")
    threat = det.get("threat", 0)
    certainty = det.get("certainty", 0)
    state = det.get("state", "unknown")
    threat_level = VectraClient.get_threat_level(threat, certainty)

    summary = det.get("summary", {})
    description = summary.get("description", "No description available")

    # Timestamps
    first_seen = det.get("first_timestamp", "Unknown")
    last_seen = det.get("last_timestamp", "Unknown")

    # Associated entities
    src_entity = det.get("src_linked_account") or det.get("src_host", {})
    entity_name = src_entity.get("name", "Unknown") if isinstance(src_entity, dict) else "Unknown"
    entity_id = src_entity.get("id", "Unknown") if isinstance(src_entity, dict) else "Unknown"

    # Tags and notes
    tags = det.get("tags", [])
    notes = det.get("notes", [])
    is_triaged = det.get("is_triaged", False)

    lines = [
        f"## Vectra Detection #{det_id}",
        "",
        f"**Detection Type:** {det_type}",
        f"**Threat Level:** {threat_level}",
        f"**Scores:** Threat: {threat}/100 | Certainty: {certainty}/100",
        f"**State:** {state}",
        f"**Triaged:** {'Yes' if is_triaged else 'No'}",
        "",
        "### Timeline",
        f"**First Seen:** {first_seen}",
        f"**Last Seen:** {last_seen}",
        "",
        "### Associated Entity",
        f"**Name:** {entity_name}",
        f"**Entity ID:** {entity_id}",
        "",
        "### Summary",
        description,
    ]

    if tags:
        lines.append("")
        lines.append(f"**Tags:** {', '.join(tags)}")

    if notes:
        lines.append("")
        lines.append("### Notes")
        for note in notes[:5]:  # Limit to first 5 notes
            lines.append(f"- {note.get('note', 'N/A')}")

    return "\n".join(lines)


def _format_single_entity(ent: dict) -> str:
    """Format a single entity for detailed display."""
    entity_id = ent.get("id", "Unknown")
    name = ent.get("name", "Unknown")
    entity_type = ent.get("type", "unknown").title()
    threat = ent.get("threat", 0)
    certainty = ent.get("certainty", 0)
    threat_level = VectraClient.get_threat_level(threat, certainty)

    last_source = ent.get("last_source", "N/A")
    detection_count = ent.get("detection_count", 0)
    is_prioritized = ent.get("is_prioritized", False)
    tags = ent.get("tags", [])

    # Get detection types if available
    detection_types = ent.get("detection_set", [])
    active_detections = [d for d in detection_types if d.get("state") == "active"]

    lines = [
        f"## Vectra {entity_type} #{entity_id}",
        "",
        f"**Name:** {name}",
        f"**Type:** {entity_type}",
        f"**Threat Level:** {threat_level}",
        f"**Scores:** Threat: {threat}/100 | Certainty: {certainty}/100",
        f"**Last Source IP:** {last_source}",
        f"**Detection Count:** {detection_count}",
        f"**Prioritized:** {'Yes' if is_prioritized else 'No'}",
    ]

    if tags:
        lines.append(f"**Tags:** {', '.join(tags)}")

    if active_detections:
        lines.append("")
        lines.append("### Active Detections")
        for det in active_detections[:10]:  # Limit to first 10
            det_id = det.get("id", "?")
            det_type = det.get("detection_type", "Unknown")
            lines.append(f"- Detection #{det_id}: {det_type}")

    return "\n".join(lines)


@tool
@log_tool_call
def get_vectra_detections(
    limit: int = 20,
    state: str = "active",
    min_threat: int = 0
) -> str:
    """Get recent detections from Vectra AI NDR platform.

    Use this tool to retrieve threat detections from Vectra. Returns detections
    sorted by severity with threat scores, entity associations, and summaries.

    Args:
        limit: Maximum number of detections to return (default 20, max 100)
        state: Filter by state - "active" (default) or "inactive"
        min_threat: Minimum threat score to filter by (0-100, default 0)
    """
    client = _get_vectra_client()
    if not client:
        return "Error: Vectra service is not available."

    # Validate and cap limit
    limit = min(max(1, limit), 100)

    data = client.get_detections(
        limit=limit,
        state=state,
        threat_gte=min_threat if min_threat > 0 else None
    )

    if "error" in data:
        return f"Error: {data['error']}"

    detections = data.get("results", [])
    return _format_detection_result(detections)


@tool
@log_tool_call
def get_vectra_detection_details(detection_id: int) -> str:
    """Get detailed information about a specific Vectra detection.

    Use this tool when you need full details about a particular detection,
    including timeline, entity info, notes, and complete summary.

    Args:
        detection_id: The numeric ID of the detection to retrieve
    """
    client = _get_vectra_client()
    if not client:
        return "Error: Vectra service is not available."

    data = client.get_detection_by_id(detection_id)

    if "error" in data:
        return f"Error: {data['error']}"

    return _format_single_detection(data)


@tool
@log_tool_call
def get_high_threat_detections(min_threat: int = 50, limit: int = 10) -> str:
    """Get high-threat detections from Vectra requiring immediate attention.

    Use this tool to quickly identify the most critical active threats
    in the environment. Returns active detections with high threat scores.

    Args:
        min_threat: Minimum threat score threshold (default 50, range 0-100)
        limit: Maximum number of results (default 10, max 50)
    """
    client = _get_vectra_client()
    if not client:
        return "Error: Vectra service is not available."

    # Validate inputs
    min_threat = max(0, min(100, min_threat))
    limit = min(max(1, limit), 50)

    data = client.get_high_threat_detections(min_threat=min_threat, limit=limit)

    if "error" in data:
        return f"Error: {data['error']}"

    detections = data.get("results", [])

    if not detections:
        return f"No active detections found with threat score >= {min_threat}. This is good news!"

    return _format_detection_result(detections)


@tool
@log_tool_call
def search_vectra_entity_by_hostname(hostname: str) -> str:
    """Search for a host entity in Vectra by hostname.

    Use this tool to look up threat information for a specific host/device
    by its hostname. Returns entity details, threat scores, and associated detections.

    Args:
        hostname: The hostname to search for (e.g., "WORKSTATION01")
    """
    client = _get_vectra_client()
    if not client:
        return "Error: Vectra service is not available."

    hostname = hostname.strip()
    data = client.search_entity_by_name(hostname, entity_type="host")

    if "error" in data:
        return f"Error: {data['error']}"

    entities = data.get("results", [])

    if not entities:
        return f"No host entity found in Vectra matching '{hostname}'"

    return _format_entity_result(entities)


@tool
@log_tool_call
def search_vectra_entity_by_ip(ip_address: str) -> str:
    """Search for an entity in Vectra by IP address.

    Use this tool to look up threat information for a device or account
    associated with a specific IP address.

    Args:
        ip_address: The IP address to search for (e.g., "10.0.1.50")
    """
    client = _get_vectra_client()
    if not client:
        return "Error: Vectra service is not available."

    ip_address = ip_address.strip()
    data = client.search_entity_by_ip(ip_address)

    if "error" in data:
        return f"Error: {data['error']}"

    entities = data.get("results", [])

    if not entities:
        return f"No entity found in Vectra with IP address '{ip_address}'"

    return _format_entity_result(entities)


@tool
@log_tool_call
def get_vectra_entity_details(entity_id: int) -> str:
    """Get detailed information about a specific Vectra entity.

    Use this tool when you need full details about a host or account entity,
    including all associated detections and threat scoring.

    Args:
        entity_id: The numeric ID of the entity to retrieve
    """
    client = _get_vectra_client()
    if not client:
        return "Error: Vectra service is not available."

    data = client.get_entity_by_id(entity_id)

    if "error" in data:
        return f"Error: {data['error']}"

    return _format_single_entity(data)


@tool
@log_tool_call
def get_prioritized_vectra_entities(limit: int = 10) -> str:
    """Get prioritized entities from Vectra requiring investigation.

    Use this tool to get the list of hosts/accounts that have been
    prioritized for investigation based on threat and certainty scores.

    Args:
        limit: Maximum number of entities to return (default 10, max 50)
    """
    client = _get_vectra_client()
    if not client:
        return "Error: Vectra service is not available."

    limit = min(max(1, limit), 50)
    data = client.get_prioritized_entities(limit=limit)

    if "error" in data:
        return f"Error: {data['error']}"

    entities = data.get("results", [])

    if not entities:
        return "No prioritized entities found. The environment appears clean or entities haven't been prioritized yet."

    lines = [f"## Prioritized Vectra Entities ({len(entities)} found)", "", "*These entities have been flagged for investigation based on threat activity.*", ""]

    for ent in entities:
        entity_id = ent.get("id", "Unknown")
        name = ent.get("name", "Unknown")
        entity_type = ent.get("type", "unknown").title()
        threat = ent.get("threat", 0)
        certainty = ent.get("certainty", 0)
        threat_level = VectraClient.get_threat_level(threat, certainty)
        detection_count = ent.get("detection_count", 0)

        lines.append(f"### {entity_type}: {name} (ID: {entity_id})")
        lines.append(f"**Threat Level:** {threat_level}")
        lines.append(f"**Scores:** Threat: {threat} | Certainty: {certainty}")
        lines.append(f"**Active Detections:** {detection_count}")
        lines.append("")

    return "\n".join(lines)


# =============================================================================
# SAMPLE TEST PROMPTS
# =============================================================================
# Use these prompts to test Vectra tools via the Pokedex bot:
#
# --- Detection Tools ---
#
# get_vectra_detections:
#   "Show me the latest Vectra detections"
#   "What are the active detections in Vectra?"
#   "Get me the last 10 Vectra detections with threat score above 30"
#
# get_vectra_detection_details:
#   "Get details for Vectra detection 12345"
#   "Show me more info about Vectra detection ID 789"
#
# get_high_threat_detections:
#   "What are the high-threat detections in Vectra?"
#   "Show me critical Vectra alerts"
#   "Get Vectra detections with threat score above 70"
#   "Are there any urgent Vectra detections I should look at?"
#
# --- Entity Lookup Tools ---
#
# search_vectra_entity_by_hostname:
#   "Look up WORKSTATION01 in Vectra"
#   "What does Vectra show for host SERVER-DB-PROD?"
#   "Check Vectra for any threats on LAPTOP-JSMITH"
#
# search_vectra_entity_by_ip:
#   "Search Vectra for IP 10.0.1.50"
#   "What does Vectra have on 192.168.1.100?"
#   "Check 172.16.0.25 in Vectra"
#
# get_vectra_entity_details:
#   "Get details for Vectra entity 456"
#   "Show me full info on Vectra entity ID 123"
#
# get_prioritized_vectra_entities:
#   "What entities are prioritized in Vectra?"
#   "Show me the Vectra investigation queue"
#   "Which hosts need attention according to Vectra?"
#   "Get the prioritized entities from Vectra"
#
# --- Combined/Natural Queries ---
#
#   "Is there anything concerning in Vectra right now?"
#   "Check if 10.0.5.100 has any Vectra detections"
#   "What's the threat status for host FINANCE-PC-01?"
#   "Give me a Vectra summary of high priority items"
#
# =============================================================================
