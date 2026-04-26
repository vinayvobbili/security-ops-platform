"""Entity-level context enrichment for XSOAR triage.

Provides enrichment functions that operate on the affected hostname and
username extracted from an XSOAR ticket, rather than on raw IOCs:

  enrich_vectra_context   — Vectra NDR threat/certainty scores and active
                            detections for the host and user entities
  enrich_qradar_activity  — Last N hours of SIEM events across all log sources
                            for the hostname and/or username
  enrich_snow_context     — ServiceNow incidents and change tickets for the
                            affected CI
  enrich_varonis_context  — Varonis DatAlert user alerts and host data activity
                            (via XSOAR integration — no direct API key needed)
  enrich_ad_context       — Active Directory user and computer object details
                            (via XSOAR integration — no direct API key needed)
                            affected CI (host), giving the LLM visibility into
                            whether planned maintenance explains the alert

All functions are designed to fail gracefully: they return an empty dict (or a
dict with an "error" key) if the underlying service is unavailable or the
entities are unknown, and never raise exceptions into the caller.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Vectra NDR context
# ---------------------------------------------------------------------------

def enrich_vectra_context(
    hostname: str,
    username: str,
    source_ip: str = "",
) -> Dict[str, Any]:
    """Fetch Vectra NDR threat/certainty scores and active detections.

    Searches for the host entity by hostname (falling back to source IP if the
    name lookup returns nothing) and the account entity by username. Returns
    threat scores, certainty, prioritization status, and a summary of active
    detections for each entity found.

    Args:
        hostname: Affected hostname from the XSOAR ticket
        username: Affected username from the XSOAR ticket
        source_ip: Optional source IP as a fallback for host entity lookup

    Returns:
        Dict with 'host_entity' and/or 'account_entity' keys, or empty dict
        if neither entity is found. Each entity dict contains threat,
        certainty, detection_count, is_prioritized, and detections list.
    """
    if not hostname and not username and not source_ip:
        return {}

    try:
        from services.vectra import VectraClient
        client = VectraClient()
        if not client.is_configured():
            return {"error": "Vectra not configured"}
    except Exception as e:
        return {"error": str(e)}

    result: Dict[str, Any] = {}

    # Host entity lookup
    if hostname or source_ip:
        host_entity = _vectra_find_host(client, hostname, source_ip)
        if host_entity:
            result["host_entity"] = host_entity

    # Account entity lookup
    if username:
        account_entity = _vectra_find_account(client, username)
        if account_entity:
            result["account_entity"] = account_entity

    return result


def _vectra_find_host(client: Any, hostname: str, source_ip: str) -> Optional[Dict[str, Any]]:
    """Find a Vectra host entity by name, falling back to IP."""
    entity = None

    if hostname:
        short = hostname.split('.')[0]
        resp = client.search_entity_by_name(short, entity_type="host")
        if "error" not in resp:
            entity = _pick_best_entity(resp.get("results", []), short)

    if entity is None and source_ip:
        resp = client.search_entity_by_ip(source_ip)
        if "error" not in resp:
            results = [e for e in resp.get("results", []) if e.get("type") == "host"]
            entity = results[0] if results else None

    if entity is None:
        return None

    return _summarise_entity(client, entity)


def _vectra_find_account(client: Any, username: str) -> Optional[Dict[str, Any]]:
    """Find a Vectra account entity by username."""
    # Strip domain prefix (DOMAIN\\user or user@domain)
    short = username.split('\\')[-1].split('@')[0]
    resp = client.search_entity_by_name(short, entity_type="account")
    if "error" in resp:
        return None

    entity = _pick_best_entity(resp.get("results", []), short)
    if entity is None:
        return None

    return _summarise_entity(client, entity)


def _pick_best_entity(entities: List[dict], name: str) -> Optional[dict]:
    """Return the entity with the highest threat score whose name contains the search term."""
    name_upper = name.upper()
    matches = [
        e for e in entities
        if name_upper in str(e.get("name", "")).upper()
    ]
    if not matches:
        matches = entities  # fall back to all results
    if not matches:
        return None
    return max(matches, key=lambda e: e.get("threat", 0))


def _summarise_entity(client: Any, entity: dict) -> Dict[str, Any]:
    """Extract the fields most useful for LLM triage context."""
    entity_id = entity.get("id")
    threat = entity.get("threat", 0)
    certainty = entity.get("certainty", 0)

    summary: Dict[str, Any] = {
        "id": entity_id,
        "name": entity.get("name", ""),
        "type": entity.get("type", ""),
        "threat": threat,
        "certainty": certainty,
        "threat_level": client.get_threat_level(threat, certainty),
        "detection_count": entity.get("detection_count", 0),
        "is_prioritized": entity.get("is_prioritized", False),
        "last_source": entity.get("last_source", ""),
        "last_detection_type": entity.get("last_detection_type", ""),
        "state": entity.get("state", ""),
        "tags": entity.get("tags", []),
    }

    # Fetch active detections for this entity (best-effort, up to 5)
    if entity_id and entity.get("detection_count", 0) > 0:
        try:
            det_resp = client.get_detections(
                limit=5,
                state="active",
            )
            if "error" not in det_resp:
                # Filter to detections belonging to this entity
                entity_dets = [
                    d for d in det_resp.get("results", [])
                    if _detection_belongs_to_entity(d, entity_id, entity.get("type"))
                ]
                if entity_dets:
                    summary["active_detections"] = [
                        {
                            "type": d.get("detection_type", ""),
                            "category": d.get("category", ""),
                            "threat": d.get("threat", 0),
                            "certainty": d.get("certainty", 0),
                            "triage_rule_count": d.get("triage_rule_count", 0),
                            "is_triaged": d.get("is_triaged", False),
                            "summary": _vectra_detection_summary(d),
                        }
                        for d in entity_dets[:5]
                    ]
        except Exception as e:
            logger.debug(f"Vectra detection fetch failed for entity {entity_id}: {e}")

    return summary


def _detection_belongs_to_entity(detection: dict, entity_id: int, entity_type: str) -> bool:
    """Check if a detection's src_host or src_account matches the entity."""
    if entity_type == "host":
        src = detection.get("src_host") or {}
        return src.get("id") == entity_id
    elif entity_type == "account":
        src = detection.get("src_account") or {}
        return src.get("id") == entity_id
    return False


def _vectra_detection_summary(d: dict) -> str:
    """Build a one-line summary of a Vectra detection."""
    summary_data = d.get("summary") or {}
    description = summary_data.get("description", "")
    if description:
        return str(description)[:200]
    return d.get("detection_type", "")


# ---------------------------------------------------------------------------
# QRadar entity activity
# ---------------------------------------------------------------------------

def enrich_qradar_activity(
    hostname: str,
    username: str,
    source_ip: str = "",
    hours: int = 4,
) -> Dict[str, Any]:
    """Fetch recent SIEM events for the affected hostname and/or username.

    Runs up to two AQL searches in parallel (hostname + username) and merges
    the results. Deduplicates events that appear in both result sets.

    This enrichment intentionally casts a wide net — it returns all log source
    types with magnitude >= 3 so the LLM can see the full activity picture on
    the host/user, not just the triggering detection.

    Args:
        hostname: Affected hostname from the XSOAR ticket
        username: Affected username from the XSOAR ticket
        source_ip: Optional fallback for IP-based search if no hostname match
        hours: Activity window in hours (default 4)

    Returns:
        Dict with 'events' list, 'event_count', 'log_sources' summary,
        and 'searched_by' indicating which entity was searched.
        Returns empty dict if no entities available.
    """
    if not hostname and not username and not source_ip:
        return {}

    try:
        from services.qradar import QRadarClient
        client = QRadarClient()
        if not client.is_configured():
            return {"error": "QRadar not configured"}
    except Exception as e:
        return {"error": str(e)}

    from concurrent.futures import ThreadPoolExecutor, as_completed

    futures_map = {}
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="qradar-entity") as pool:
        if hostname:
            futures_map[pool.submit(
                client.search_events_by_hostname, hostname, hours
            )] = "hostname"
        elif source_ip:
            # IP fallback when no hostname available
            futures_map[pool.submit(
                client.search_events_by_ip, source_ip, hours
            )] = "source_ip"

        if username:
            futures_map[pool.submit(
                client.search_events_by_username, username, hours
            )] = "username"

        raw_results: Dict[str, Any] = {}
        for future in as_completed(futures_map, timeout=120):
            key = futures_map[future]
            try:
                raw_results[key] = future.result()
            except Exception as e:
                logger.warning(f"QRadar entity activity search ({key}) failed: {e}")
                raw_results[key] = {"error": str(e)}

    # Merge and deduplicate events from both searches
    all_events: List[dict] = []
    seen_keys = set()
    searched_by = []

    for key, res in raw_results.items():
        if "error" in res:
            continue
        searched_by.append(key)
        for ev in res.get("events", []):
            # Dedup key: event_time + event_name + sourceip + destinationip
            dedup = (
                ev.get("event_time", ""),
                ev.get("event_name", ""),
                ev.get("sourceip", ""),
                ev.get("destinationip", ""),
            )
            if dedup not in seen_keys:
                seen_keys.add(dedup)
                all_events.append(ev)

    if not all_events and not searched_by:
        errors = {k: v.get("error") for k, v in raw_results.items() if "error" in v}
        return {"error": f"All QRadar activity searches failed: {errors}"}

    # Sort by magnitude desc, then time desc
    all_events.sort(
        key=lambda e: (-int(e.get("magnitude", 0)), e.get("event_time", "")),
        reverse=False,
    )

    # Summarise log sources seen
    log_source_counts: Dict[str, int] = {}
    for ev in all_events:
        ls = ev.get("log_source", "unknown")
        log_source_counts[ls] = log_source_counts.get(ls, 0) + 1

    return {
        "events": all_events[:25],
        "event_count": len(all_events),
        "log_source_summary": log_source_counts,
        "searched_by": searched_by,
        "hours": hours,
    }


# ---------------------------------------------------------------------------
# ServiceNow context
# ---------------------------------------------------------------------------

def enrich_snow_context(
    hostname: str,
    username: str,
) -> Dict[str, Any]:
    """Fetch ServiceNow incidents and change tickets for the affected host/user.

    Two queries are run:
    1. Recent incidents where the affected CI matches the hostname
    2. Active/scheduled change tickets for the hostname

    The change ticket data is especially valuable: if there is an active change
    window on the host, many alerts will be expected activity. Surfacing this
    during triage prevents unnecessary escalations.

    Args:
        hostname: Affected hostname from the XSOAR ticket
        username: Affected username (used for incident search fallback)

    Returns:
        Dict with 'incidents' and 'changes' lists, plus summary counts.
        Returns empty dict if hostname and username are both blank.
    """
    if not hostname and not username:
        return {}

    try:
        from services.service_now import ServiceNowClient
        client = ServiceNowClient()
    except Exception as e:
        return {"error": str(e)}

    result: Dict[str, Any] = {"incidents": [], "changes": []}

    search_term = hostname or username

    # Incidents for this CI
    try:
        incidents = client.search_incidents_by_ci(search_term, hours=72)
        if isinstance(incidents, list):
            result["incidents"] = [_summarise_snow_incident(i) for i in incidents[:5]]
            result["incident_count"] = len(incidents)
    except Exception as e:
        logger.warning(f"SNOW incident search failed for {search_term}: {e}")
        result["incidents"] = []

    # Change tickets for this CI
    if hostname:
        try:
            changes = client.search_changes_by_ci(hostname)
            if isinstance(changes, list):
                result["changes"] = [_summarise_snow_change(c) for c in changes[:5]]
                result["change_count"] = len(changes)
        except Exception as e:
            logger.warning(f"SNOW change search failed for {hostname}: {e}")
            result["changes"] = []

    return result


def _summarise_snow_incident(inc: dict) -> Dict[str, Any]:
    """Extract the most triage-relevant fields from a SNOW incident record."""
    return {
        "number": inc.get("number", inc.get("incidentNumber", "")),
        "short_description": str(inc.get("shortDescription", inc.get("description", "")))[:200],
        "state": inc.get("state", ""),
        "priority": inc.get("priority", ""),
        "assignment_group": inc.get("assignmentGroup", ""),
        "opened_at": inc.get("createdDate", inc.get("openedAt", "")),
        "resolved_at": inc.get("resolvedDate", inc.get("resolvedAt", "")),
        "ci": inc.get("configurationItem", inc.get("ciItem", "")),
    }


def _summarise_snow_change(chg: dict) -> Dict[str, Any]:
    """Extract the most triage-relevant fields from a SNOW change ticket record."""
    return {
        "number": chg.get("number", chg.get("changeNumber", "")),
        "short_description": str(chg.get("shortDescription", chg.get("description", "")))[:200],
        "state": chg.get("state", chg.get("status", "")),
        "type": chg.get("type", chg.get("changeType", "")),
        "planned_start": chg.get("plannedStart", chg.get("startDate", "")),
        "planned_end": chg.get("plannedEnd", chg.get("endDate", "")),
        "assignment_group": chg.get("assignmentGroup", ""),
        "ci": chg.get("configurationItem", chg.get("ciItem", "")),
    }


# ---------------------------------------------------------------------------
# Varonis context
# ---------------------------------------------------------------------------

def enrich_varonis_context(
    hostname: str,
    username: str,
    ticket_id: str,
) -> Dict[str, Any]:
    """Fetch Varonis DatAlert alerts and data activity for the affected entities.

    Runs two XSOAR war room commands against the ticket's investigation:
      - !varonis-get-alert-evidence (keyed on username)
      - !varonis-get-data-activity  (keyed on hostname)

    Both run in parallel. Results are read from the incident context after
    both commands complete.

    Args:
        hostname: Affected hostname from the XSOAR ticket
        username: Affected username from the XSOAR ticket
        ticket_id: XSOAR incident ID (commands execute in this investigation)

    Returns:
        Dict with 'user_alerts' and/or 'data_activity' keys, or empty dict
        if neither is available. Returns {"error": ...} on client failure.
    """
    if not ticket_id or (not hostname and not username):
        return {}

    try:
        from services.varonis import VaronisClient
        client = VaronisClient()
    except Exception as e:
        return {"error": str(e)}

    from concurrent.futures import ThreadPoolExecutor, as_completed

    result: Dict[str, Any] = {}
    futures_map = {}

    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="varonis") as pool:
        if username:
            futures_map[pool.submit(client.get_user_alerts, username, ticket_id)] = "user_alerts"
        if hostname:
            futures_map[pool.submit(client.get_data_activity, hostname, ticket_id)] = "data_activity"

        for future in as_completed(futures_map, timeout=90):
            key = futures_map[future]
            try:
                data = future.result()
                if data is not None:
                    result[key] = data
            except Exception as e:
                logger.warning(f"Varonis enrichment ({key}) failed: {e}")

    return result


# ---------------------------------------------------------------------------
# Active Directory context
# ---------------------------------------------------------------------------

def enrich_ad_context(
    hostname: str,
    username: str,
    ticket_id: str,
) -> Dict[str, Any]:
    """Fetch Active Directory user and computer object details.

    Runs two XSOAR war room commands against the ticket's investigation:
      - !ad-get-user     (keyed on username)
      - !ad-get-computer (keyed on hostname)

    Both run in parallel. Results are read from the incident context.

    AD context helps establish whether the activity is consistent with the
    account's role: group memberships, OU placement (workstation vs server
    vs privileged tier), account enabled status, and last logon time.

    Args:
        hostname: Affected hostname from the XSOAR ticket
        username: Affected username from the XSOAR ticket
        ticket_id: XSOAR incident ID (commands execute in this investigation)

    Returns:
        Dict with 'user' and/or 'computer' keys, or empty dict if neither
        is available. Returns {"error": ...} on client failure.
    """
    if not ticket_id or (not hostname and not username):
        return {}

    try:
        from services.active_directory import ActiveDirectoryClient
        client = ActiveDirectoryClient()
    except Exception as e:
        return {"error": str(e)}

    from concurrent.futures import ThreadPoolExecutor, as_completed

    result: Dict[str, Any] = {}
    futures_map = {}

    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="ad-lookup") as pool:
        if username:
            futures_map[pool.submit(client.get_user, username, ticket_id)] = "user"
        if hostname:
            futures_map[pool.submit(client.get_computer, hostname, ticket_id)] = "computer"

        for future in as_completed(futures_map, timeout=60):
            key = futures_map[future]
            try:
                data = future.result()
                if data is not None:
                    result[key] = data
            except Exception as e:
                logger.warning(f"AD enrichment ({key}) failed: {e}")

    return result
