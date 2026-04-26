"""Cross-source correlation: QRadar offenses on the same host/user.

When a CrowdStrike detection fires on a host or user, the only thing the
analyst sees in the XSOAR ticket is the CS-side story. If QRadar already
has an OPEN offense on the same entity -- either the anchor host, the
anchor user, or one of the lateral-movement targets resolved in Gap 4 --
that's a strong corroborating signal. It tells the analyst the same
activity is tripping multiple independent detection pipelines, which is
either (a) the same event observed from different telemetry sources, (b)
two different malicious things happening on the same host at once, or
(c) coordinated noise that deserves cross-source tuning.

Conversely, a scan that turns up ZERO open offenses across all of the
CS alert's entities is itself a meaningful data point: the CS detection
is single-source noise from QRadar's perspective, which nudges the
analyst toward FP-leaning conclusions.

## Strategy

QRadar's `/siem/offenses` REST endpoint does NOT support filtering on
`offense_source` (HTTP 422 "Filtering is unsupported on the field").
So we can't ask the server "give me offenses whose source matches X."
Instead:

  1. ONE broad call: `get_offenses(filter_query="status=OPEN and
     last_updated_time>={cutoff}")` -- bounded by the lookback window
     and capped at MAX_OPEN_OFFENSES_TO_SCAN, sorted by most recent.
  2. Client-side scan: for each returned offense, build a haystack
     from `offense_source + description + rule names` (lowercased) and
     substring-match every entity against it.
  3. Dedupe matches by offense id, accumulating the set of matching
     entities (a single offense often corroborates multiple entities).
  4. Annotate each match with `hours_from_anchor` (signed delta of the
     offense `start_time` from the CS detection `created_timestamp`).
  5. Sort by absolute proximity to the CS anchor and cap the final
     rendered list.

One QRadar REST call per enriched CS alert. Tanium is NOT checked --
it's unreachable from this VM (see project memory lab-vm1 notes).

## Entity set

CS `user_name` is often a SAM-style identifier (e.g. "ZSYSH9J") while
QRadar offenses key on the human email / `user_principal` form, so we
expand the entity set to include both sides. IPs are included because
many QRadar rules use the IP as the offense indexer.

  - anchor_hostname      (device.hostname)
  - anchor_username      (user_name, SAM-style)
  - anchor_user_principal (user_principal, email/UPN form)
  - anchor_local_ip      (device.local_ip)
  - anchor_external_ip   (device.external_ip)
  - lateral_target_hostname (each resolved lateral target)
  - lateral_target_local_ip (each resolved lateral target IP)
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# Lookback window for open offenses. 7 days from the current time is
# generous enough to capture offenses that have been active around the
# CS detection window without dredging up stale noise.
CORRELATION_LOOKBACK_DAYS = 7

# Cap on how many open offenses we'll pull for the client-side scan.
# QRadar can return a large page with a Range header; 1000 is a safe
# upper bound that covers a busy 7-day window on this tenant while
# keeping the payload under a few MB.
MAX_OPEN_OFFENSES_TO_SCAN = 1000

# Final cap on the merged, deduped offense list rendered for the analyst.
MAX_TOTAL_OFFENSES = 15

# Minimum entity length -- anything shorter is too ambiguous to substring-
# match against a free-text haystack (would false-match in descriptions).
# Hostnames are typically 6+, SAM usernames 5+, IPv4 addresses 7+, emails
# 7+, so this cutoff is safe for our entity set.
MIN_ENTITY_LENGTH = 5


def _parse_ts(s: str) -> Optional[datetime]:
    """Parse a CS ISO-8601 timestamp into a UTC-aware datetime."""
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def _collect_entities(
    det: Dict[str, Any],
    cs_lateral_targets: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, str]]:
    """Build the list of entities to correlate against QRadar.

    Returns a list of `{type, value, role}` dicts, unique by
    (type, lowercased value), with values below MIN_ENTITY_LENGTH
    filtered out. The order is deterministic: anchor entities first in
    fixed order, then lateral targets in Gap-4 order.
    """
    entities: List[Dict[str, str]] = []
    seen: set = set()

    def _add(etype: str, value: str, role: str) -> None:
        v = (value or "").strip()
        if len(v) < MIN_ENTITY_LENGTH:
            return
        key = (etype, v.lower())
        if key in seen:
            return
        seen.add(key)
        entities.append({"type": etype, "value": v, "role": role})

    device = det.get("device") or {}

    # --- Anchor host ---
    _add(
        "hostname",
        device.get("hostname") or (det.get("host_names") or [None])[0] or "",
        "anchor_source",
    )

    # --- Anchor user (SAM + UPN form) ---
    _add("username", det.get("user_name") or "", "anchor_source")
    _add("user_principal", det.get("user_principal") or "", "anchor_source")

    # --- Anchor IPs ---
    _add("ip", device.get("local_ip") or "", "anchor_source")
    _add("ip", device.get("external_ip") or "", "anchor_source")

    # --- Lateral targets from Gap 4 ---
    if cs_lateral_targets and isinstance(cs_lateral_targets, dict):
        for t in cs_lateral_targets.get("targets") or []:
            dev = t.get("target_device") or {}
            _add("hostname", dev.get("hostname", ""), "lateral_target")
            _add("ip", dev.get("local_ip", ""), "lateral_target")

    return entities


def _build_offense_haystack(offense: Dict[str, Any]) -> str:
    """Build a lowercased searchable blob from an offense for substring
    matching. Combines `offense_source`, `description`, and rule names --
    the three structured fields where an entity identifier plausibly
    appears in a QRadar offense payload.
    """
    parts: List[str] = []
    parts.append((offense.get("offense_source") or "").lower())
    parts.append((offense.get("description") or "").lower())
    for r in offense.get("rules") or []:
        if isinstance(r, dict):
            parts.append((r.get("name") or "").lower())
    return " \u0001 ".join(p for p in parts if p)


def _summarize_offense(
    offense: Dict[str, Any],
    anchor_ts: Optional[datetime],
    matched_entities: List[Dict[str, str]],
) -> Dict[str, Any]:
    """Convert a raw QRadar offense dict to a compact summary entry.

    `hours_from_anchor` is the signed delta (in decimal hours) of the
    offense `start_time` relative to the CS detection `created_timestamp`.
    Negative = offense started BEFORE the CS anchor; positive = AFTER.
    """
    oid = offense.get("id")
    start_time_ms = offense.get("start_time") or 0
    last_updated_ms = offense.get("last_updated_time") or 0

    hours_from_anchor: Optional[float] = None
    if anchor_ts and start_time_ms:
        try:
            anchor_ms = int(anchor_ts.timestamp() * 1000)
            delta_h = (int(start_time_ms) - anchor_ms) / (1000.0 * 3600.0)
            hours_from_anchor = round(delta_h, 2)
        except Exception:
            hours_from_anchor = None

    rule_names: List[str] = []
    for r in offense.get("rules") or []:
        if isinstance(r, dict) and r.get("name"):
            rule_names.append(r["name"])

    log_source_names: List[str] = []
    for ls in offense.get("log_sources") or []:
        if isinstance(ls, dict) and ls.get("name"):
            log_source_names.append(ls["name"])

    return {
        "offense_id": oid,
        "description": (offense.get("description") or "").strip()[:300],
        "status": offense.get("status", ""),
        "magnitude": offense.get("magnitude", 0),
        "severity": offense.get("severity", 0),
        "relevance": offense.get("relevance", 0),
        "credibility": offense.get("credibility", 0),
        "offense_type_str": offense.get("offense_type_str", ""),
        "offense_source": offense.get("offense_source", ""),
        "event_count": offense.get("event_count", 0),
        "flow_count": offense.get("flow_count", 0),
        "source_count": offense.get("source_count", 0),
        "categories": (offense.get("categories") or [])[:5],
        "log_sources": log_source_names[:5],
        "rule_names": rule_names[:5],
        "start_time": int(start_time_ms) if start_time_ms else 0,
        "last_updated_time": int(last_updated_ms) if last_updated_ms else 0,
        "hours_from_anchor": hours_from_anchor,
        "matched_entities": list(matched_entities),
    }


def build_cross_source_correlation(
    det: Dict[str, Any],
    cs_lateral_targets: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Correlate a CS alert's entities against open QRadar offenses.

    Args:
        det: The raw CS v2 alert payload returned by
             CrowdStrikeClient.get_detection_by_id().
        cs_lateral_targets: Output of build_lateral_targets(det), if
            available. Lateral target hostnames + local IPs are added
            to the entity list so we catch offenses on the pivot
            destinations as well as the source host.

    Returns:
        Dict with `entities_checked`, `offenses` (deduped + sorted by
        proximity), `total_matched`, `offenses_scanned`, `truncated`,
        plus error/diagnostic fields. On total failure returns
        `{"error": ...}` with the rest empty.
    """
    anchor_ts_raw = det.get("created_timestamp") or ""
    anchor_ts = _parse_ts(anchor_ts_raw)
    device = det.get("device") or {}
    anchor_hostname = (
        device.get("hostname")
        or (det.get("host_names") or [None])[0]
        or ""
    )
    if anchor_hostname:
        anchor_hostname = anchor_hostname.strip()
    anchor_username = (det.get("user_name") or "").strip()

    entities = _collect_entities(det, cs_lateral_targets)

    result: Dict[str, Any] = {
        "anchor_hostname": anchor_hostname,
        "anchor_username": anchor_username,
        "anchor_timestamp": anchor_ts_raw,
        "entities_checked": entities,
        "lookback_days": CORRELATION_LOOKBACK_DAYS,
        "offenses": [],
        "total_matched": 0,
        "offenses_scanned": 0,
        "truncated": False,
    }

    if not entities:
        return result

    try:
        from services.qradar import QRadarClient
        client = QRadarClient()
        if not client.is_configured():
            result["error"] = "QRadar not configured"
            return result
    except Exception as e:
        logger.warning(f"[CSCrossSource] QRadarClient init failed: {e}")
        result["error"] = str(e)
        return result

    # Single broad fetch: status=OPEN within the lookback window,
    # sorted by most recent. Client-side filtered afterwards because
    # /siem/offenses doesn't support filtering on `offense_source`.
    lookback_cutoff_ms = int(
        (datetime.now(timezone.utc) - timedelta(days=CORRELATION_LOOKBACK_DAYS))
        .timestamp() * 1000
    )
    try:
        resp = client.get_offenses(
            filter_query=(
                f"status=OPEN and last_updated_time>={lookback_cutoff_ms}"
            ),
            sort="-last_updated_time",
            limit=MAX_OPEN_OFFENSES_TO_SCAN,
        )
    except Exception as e:
        logger.warning(f"[CSCrossSource] get_offenses call raised: {e}")
        result["error"] = str(e)
        return result

    if "error" in resp:
        result["error"] = f"get_offenses: {str(resp['error'])[:300]}"
        return result

    all_offenses = resp.get("offenses") or []
    result["offenses_scanned"] = len(all_offenses)
    # Note if we hit the scan cap -- a bigger tenant might have >1000
    # open offenses in 7 days and the analyst should know we didn't see
    # all of them.
    if len(all_offenses) >= MAX_OPEN_OFFENSES_TO_SCAN:
        result["scan_cap_hit"] = True

    # Pre-lowercase entity values once; scan is O(offenses * entities).
    entity_values = [(e["value"].lower(), e) for e in entities]

    offenses_by_id: Dict[Any, Dict[str, Any]] = {}
    for o in all_offenses:
        haystack = _build_offense_haystack(o)
        if not haystack:
            continue
        matched: List[Dict[str, str]] = []
        for v_lc, e in entity_values:
            if v_lc in haystack:
                matched.append(e)
        if not matched:
            continue
        oid = o.get("id")
        if oid is None:
            continue
        if oid not in offenses_by_id:
            offenses_by_id[oid] = _summarize_offense(o, anchor_ts, matched)
        else:
            # Offense matched multiple entities on a prior iteration
            # (shouldn't happen since we scan each offense once, but
            # harmless to merge).
            existing = offenses_by_id[oid]["matched_entities"]
            for me in matched:
                if me not in existing:
                    existing.append(me)

    merged = list(offenses_by_id.values())

    # Sort by absolute proximity to the CS anchor so the most likely
    # corroborating offenses surface first. Offenses without a parsed
    # delta drop to the bottom.
    def _sort_key(o: Dict[str, Any]) -> float:
        h = o.get("hours_from_anchor")
        if h is None:
            return float("inf")
        return abs(float(h))

    merged.sort(key=_sort_key)

    result["total_matched"] = len(merged)
    if len(merged) > MAX_TOTAL_OFFENSES:
        result["truncated"] = True
        merged = merged[:MAX_TOTAL_OFFENSES]
    result["offenses"] = merged

    return result
