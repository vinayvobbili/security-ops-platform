"""CrowdStrike process-tree correlation for an alert.

Most CS detections that matter to an analyst are NOT isolated — they're one
node in a chain (e.g. install module -> assembly load -> lateral move). The
Falcon UI surfaces this via process trees and incident leads, but the SOC
analyst working an XSOAR ticket never sees it unless they pivot. This module
pulls the chain back out.

For an anchor alert it asks: which other CS detections on the same host
within a +/- N minute window share a process-tree, process-graph, detection
aggregate, or incident-lead identifier with this alert? It returns a unified
chain ordered by time, with the strongest matching linkage labelled per
result and the relative offset from the anchor.

Linkage priority (strongest -> weakest):
  1. tree_id                     -> same CS process tree (highest fidelity)
  2. triggering_process_graph_id -> same process graph
  3. aggregate_id                -> same CS detection aggregate
  4. lead_id                     -> same CS incident lead (often spans trees)
  5. time_adjacent               -> same host, no linkage, just close in time

The maruyama 2026-04-09 chain demonstrated all three layers in a single
incident (00:23 -> 00:42 share tree_id; 01:26 lateral movement is a
different tree but shares lead_id with the anchor). The plan's original
"+/- 60 min" window misses the lateral move at +63 min, so this module
defaults to +/- 2 hours -- still 1 CS API call.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# Default lookback window centered on the anchor alert. The CS API time
# filter is anchored on `created_timestamp`, so we're really asking "any
# host detections within +/- WINDOW_MINUTES of the anchor's creation time."
# Bumped to 120 minutes after the maruyama chain showed a same-incident
# lateral move at +63 min -- a tighter +/- 60 min would have missed it.
WINDOW_MINUTES = 120

# Cap on results returned. A single host within a 4-hour window almost
# never produces this many CS detections; the cap is a safety belt against
# a noise-storm host hosing the response.
MAX_RESULTS = 50


# Linkage field priority -- strongest to weakest. Each entry is
# (label, field_name_on_alert). The first match wins for a given alert.
_LINKAGE_PRIORITY = [
    ("same_tree", "tree_id"),
    ("same_process_graph", "triggering_process_graph_id"),
    ("same_aggregate", "aggregate_id"),
    ("same_lead", "lead_id"),
]


def _parse_ts(s: str) -> Optional[datetime]:
    """Parse a CS ISO-8601 timestamp into a UTC-aware datetime."""
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def _classify_linkage(
    other: Dict[str, Any], anchor: Dict[str, Any],
) -> Optional[Dict[str, str]]:
    """Return the strongest linkage between `other` and `anchor`, or None.

    Returned dict has `label` (e.g. "same_tree") and `detail` (the matching
    field=value pair) for downstream rendering.
    """
    for label, field in _LINKAGE_PRIORITY:
        a_val = anchor.get(field)
        o_val = other.get(field)
        if a_val and o_val and a_val == o_val:
            return {"label": label, "detail": f"{field}={a_val}"}
    return None


def build_process_tree_correlation(det: Dict[str, Any]) -> Dict[str, Any]:
    """Find other CS detections on the same host that link to this one.

    Args:
        det: The raw CS v2 alert payload returned by
             CrowdStrikeClient.get_detection_by_id().

    Returns:
        Dict with `linked_chain` (graph/lead-linked siblings) and
        `time_adjacent` (same host, time-adjacent, no graph linkage).
        On API failure, returns `{"error": ...}` with the rest empty.
    """
    device = det.get("device") or {}
    hostname = (
        device.get("hostname")
        or (det.get("host_names") or [None])[0]
        or ""
    )
    if hostname:
        hostname = hostname.strip()
    anchor_composite_id = det.get("composite_id") or ""
    anchor_ts_raw = det.get("created_timestamp") or ""
    anchor_ts = _parse_ts(anchor_ts_raw)

    result: Dict[str, Any] = {
        "anchor_composite_id": anchor_composite_id,
        "anchor_timestamp": anchor_ts_raw,
        "hostname": hostname,
        "window_minutes": WINDOW_MINUTES,
        "linked_chain": [],
        "time_adjacent": [],
    }

    if not hostname or not anchor_ts:
        # Without a hostname or anchor timestamp we can't form the query.
        # Return the empty shell rather than raising -- the renderer will
        # see empty arrays and skip the section.
        return result

    # Lazy-import the client to keep test isolation cheap.
    try:
        from services.crowdstrike import CrowdStrikeClient
        client = CrowdStrikeClient()
    except Exception as e:
        logger.warning(f"[CSTree] CrowdStrikeClient init failed: {e}")
        result["error"] = str(e)
        return result

    # Single CS API call: host + +/- WINDOW_MINUTES window. The result
    # set is then classified client-side using the linkage priority list.
    start = (anchor_ts - timedelta(minutes=WINDOW_MINUTES)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    end = (anchor_ts + timedelta(minutes=WINDOW_MINUTES)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    fql = (
        f"device.hostname:'{hostname}'"
        f"+created_timestamp:>='{start}'"
        f"+created_timestamp:<='{end}'"
    )
    try:
        resp = client.get_detections(limit=MAX_RESULTS, filter_query=fql)
        if "error" in resp:
            result["error"] = resp["error"]
            return result
        siblings = resp.get("results") or []
    except Exception as e:
        logger.warning(f"[CSTree] host+window query failed: {e}")
        result["error"] = str(e)
        return result

    # Strip the anchor itself out of the candidate list.
    siblings = [
        s for s in siblings
        if s.get("composite_id") != anchor_composite_id
    ]

    linked_chain: List[Dict[str, Any]] = []
    time_adjacent: List[Dict[str, Any]] = []

    for s in siblings:
        s_ts = _parse_ts(s.get("created_timestamp", ""))
        if not s_ts:
            continue
        offset_minutes = int((s_ts - anchor_ts).total_seconds() / 60)

        entry: Dict[str, Any] = {
            "composite_id": s.get("composite_id", ""),
            "created_timestamp": s.get("created_timestamp", ""),
            "minutes_offset": offset_minutes,
            "pattern_id": str(s.get("pattern_id", "") or ""),
            "name": s.get("name", "") or s.get("display_name", ""),
            "severity_name": s.get("severity_name", ""),
            "user_name": s.get("user_name", ""),
            "filename": s.get("filename", ""),
            "cmdline": (s.get("cmdline", "") or "")[:200],
            "tactic": s.get("tactic", ""),
            "technique": s.get("technique", ""),
            # Capture network_accesses + dns_requests + hashes on each
            # sibling so downstream gap modules (cs_lateral_targets,
            # cs_ioc_threat_intel) can reach the full chain without
            # re-fetching. The host+window query already returns the full
            # v2 alert payload, so this is free data.
            "network_accesses": s.get("network_accesses") or [],
            "dns_requests": s.get("dns_requests") or [],
            "sha256": s.get("sha256", "") or "",
            "md5": s.get("md5", "") or "",
            "parent_sha256": (s.get("parent_details") or {}).get("sha256", "") or "",
            "grandparent_sha256": (s.get("grandparent_details") or {}).get("sha256", "") or "",
        }

        linkage = _classify_linkage(s, det)
        if linkage:
            entry["linkage"] = linkage["label"]
            entry["linkage_detail"] = linkage["detail"]
            linked_chain.append(entry)
        else:
            entry["linkage"] = "time_adjacent"
            time_adjacent.append(entry)

    # Order both lists chronologically so the renderer can show them as a
    # timeline without re-sorting.
    linked_chain.sort(key=lambda e: e.get("minutes_offset", 0))
    time_adjacent.sort(key=lambda e: e.get("minutes_offset", 0))

    result["linked_chain"] = linked_chain
    result["time_adjacent"] = time_adjacent
    return result
