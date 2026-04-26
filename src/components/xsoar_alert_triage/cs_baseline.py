"""CrowdStrike baseline / behavior-delta context for an alert.

The smoking-gun extractor (Gap 1) tells the analyst WHAT happened in this
specific alert. This module tells them WHETHER THIS USER OR HOST HAS DONE
THIS BEFORE — turning a binary detection into a behavior delta.

For an alert like "Pattern 10420 SuspiciousDotNetAssemblyLoad fired on
RZIT8LLL by user ZSYSH9J," the baseline answers three questions the analyst
would otherwise have to pivot into the Falcon console to ask:

  1. Has ZSYSH9J triggered Pattern 10420 before? When?  (user x pattern)
  2. What other CS detections has ZSYSH9J had recently? (user_recent)
  3. What other CS detections has RZIT8LLL had recently? (host_recent)

These three facts let an analyst recognize a stable, recurring research-tool
user vs. a one-off anomaly without ever leaving the ticket.

Three CrowdStrike API calls per ticket. The user x pattern lookback defaults
to 90 days (long-tail behavior — has this ever happened?), the user_recent
and host_recent lookbacks default to 30 days (focused on recent operational
state — what else is going on right now?).
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# Defaults — keep conservative so we don't drown the API or the analyst.
# The user x pattern intersection benefits from a long lookback (researcher
# tooling tends to recur on a weekly or monthly cadence). The "what else has
# this user/host done lately" queries get a tighter window so we surface
# operationally-relevant context, not noise from months ago.
USER_PATTERN_LOOKBACK_DAYS = 90
USER_RECENT_LOOKBACK_DAYS = 30
HOST_RECENT_LOOKBACK_DAYS = 30

# Cap each query so a noisy host/user can't blow up the response. 200 is far
# above any realistic recurring count for a single user x pattern; if the
# real number is higher we report the count as a lower bound.
MAX_RESULTS_PER_QUERY = 200


def _iso_days_ago(days: int) -> str:
    """Return an ISO-8601 (Z-suffixed) timestamp for `days` ago in UTC."""
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _parse_ts(s: str) -> Optional[datetime]:
    """Parse a CS ISO-8601 timestamp into a UTC-aware datetime."""
    if not s:
        return None
    try:
        # CS returns ISO 8601 with Z suffix; fromisoformat needs +00:00
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def _days_ago(iso_ts: str) -> Optional[int]:
    """Return integer days between now (UTC) and an ISO timestamp."""
    ts = _parse_ts(iso_ts)
    if not ts:
        return None
    delta = datetime.now(timezone.utc) - ts
    return max(0, delta.days)


def _summarize_detections(
    detections: List[Dict[str, Any]],
    current_composite_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Reduce a list of CS v2 detections to a baseline summary.

    Strips the *current* alert from the list (so the user doesn't see "1
    occurrence of itself" for a brand-new pattern), then returns count,
    first/last seen, and the top 5 patterns by frequency.
    """
    if current_composite_id:
        detections = [
            d for d in detections
            if d.get("composite_id") != current_composite_id
        ]

    count = len(detections)
    pattern_counter: Counter = Counter()
    pattern_names: Dict[str, str] = {}
    timestamps: List[datetime] = []

    for d in detections:
        pid = str(d.get("pattern_id", "") or "")
        if pid:
            pattern_counter[pid] += 1
            # Prefer `name` (e.g. "SuspiciousDotNetAssemblyLoad") over
            # `display_name` for the human label — `name` is the canonical
            # pattern name, display_name is sometimes a longer phrase.
            label = d.get("name") or d.get("display_name") or ""
            if label and pid not in pattern_names:
                pattern_names[pid] = label
        ts = _parse_ts(d.get("created_timestamp", ""))
        if ts:
            timestamps.append(ts)

    timestamps.sort()
    first_seen = timestamps[0].isoformat() if timestamps else ""
    last_seen = timestamps[-1].isoformat() if timestamps else ""

    top_patterns: List[Dict[str, Any]] = [
        {"pattern_id": pid, "name": pattern_names.get(pid, ""), "count": n}
        for pid, n in pattern_counter.most_common(5)
    ]

    summary: Dict[str, Any] = {
        "count": count,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "top_patterns": top_patterns,
    }
    last_seen_days = _days_ago(last_seen)
    if last_seen_days is not None:
        summary["last_seen_days_ago"] = last_seen_days
    return summary


def build_cs_baseline(det: Dict[str, Any]) -> Dict[str, Any]:
    """Build per-user/per-pattern + recent-by-user + recent-by-host baseline.

    Args:
        det: The raw CS v2 alert payload returned by
             CrowdStrikeClient.get_detection_by_id().

    Returns:
        Dict with three sub-sections (user_pattern, user_recent, host_recent).
        Each sub-section is either a summary dict (count, first/last seen,
        top_patterns) or a `{"error": ...}` dict if that one query failed.
        A failure in one sub-section never blocks the others.
    """
    user_name = (det.get("user_name") or "").strip()
    pattern_id = str(det.get("pattern_id") or "").strip()
    device = det.get("device") or {}
    hostname = (
        device.get("hostname")
        or (det.get("host_names") or [None])[0]
        or ""
    )
    if hostname:
        hostname = hostname.strip()
    current_composite_id = det.get("composite_id") or ""

    baseline: Dict[str, Any] = {
        "user_name": user_name,
        "pattern_id": pattern_id,
        "hostname": hostname,
        "user_pattern": {},
        "user_recent": {},
        "host_recent": {},
    }

    # Lazy-import the client so unit tests can stub it without paying the
    # FalconPy import cost. Reuse a single client across the three queries.
    try:
        from services.crowdstrike import CrowdStrikeClient
        client = CrowdStrikeClient()
    except Exception as e:
        logger.warning(f"[CSBaseline] CrowdStrikeClient init failed: {e}")
        baseline["error"] = str(e)
        return baseline

    # ---- 1. User x pattern intersection (long lookback) ----
    if user_name and pattern_id:
        try:
            cutoff = _iso_days_ago(USER_PATTERN_LOOKBACK_DAYS)
            fql = (
                f"user_name:'{user_name}'"
                f"+pattern_id:'{pattern_id}'"
                f"+created_timestamp:>='{cutoff}'"
            )
            resp = client.get_detections(
                limit=MAX_RESULTS_PER_QUERY, filter_query=fql,
            )
            if "error" in resp:
                baseline["user_pattern"] = {
                    "lookback_days": USER_PATTERN_LOOKBACK_DAYS,
                    "error": resp["error"],
                }
            else:
                summary = _summarize_detections(
                    resp.get("results") or [], current_composite_id,
                )
                summary["lookback_days"] = USER_PATTERN_LOOKBACK_DAYS
                summary["truncated"] = (
                    (resp.get("total") or 0) >= MAX_RESULTS_PER_QUERY
                )
                baseline["user_pattern"] = summary
        except Exception as e:
            logger.warning(f"[CSBaseline] user x pattern query failed: {e}")
            baseline["user_pattern"] = {"error": str(e)}

    # ---- 2. User recent (all patterns, tighter window) ----
    if user_name:
        try:
            cutoff = _iso_days_ago(USER_RECENT_LOOKBACK_DAYS)
            fql = f"user_name:'{user_name}'+created_timestamp:>='{cutoff}'"
            resp = client.get_detections(
                limit=MAX_RESULTS_PER_QUERY, filter_query=fql,
            )
            if "error" in resp:
                baseline["user_recent"] = {
                    "lookback_days": USER_RECENT_LOOKBACK_DAYS,
                    "error": resp["error"],
                }
            else:
                summary = _summarize_detections(
                    resp.get("results") or [], current_composite_id,
                )
                summary["lookback_days"] = USER_RECENT_LOOKBACK_DAYS
                summary["truncated"] = (
                    (resp.get("total") or 0) >= MAX_RESULTS_PER_QUERY
                )
                baseline["user_recent"] = summary
        except Exception as e:
            logger.warning(f"[CSBaseline] user_recent query failed: {e}")
            baseline["user_recent"] = {"error": str(e)}

    # ---- 3. Host recent (all patterns, tighter window) ----
    if hostname:
        try:
            cutoff = _iso_days_ago(HOST_RECENT_LOOKBACK_DAYS)
            fql = (
                f"device.hostname:'{hostname}'"
                f"+created_timestamp:>='{cutoff}'"
            )
            resp = client.get_detections(
                limit=MAX_RESULTS_PER_QUERY, filter_query=fql,
            )
            if "error" in resp:
                baseline["host_recent"] = {
                    "lookback_days": HOST_RECENT_LOOKBACK_DAYS,
                    "error": resp["error"],
                }
            else:
                summary = _summarize_detections(
                    resp.get("results") or [], current_composite_id,
                )
                summary["lookback_days"] = HOST_RECENT_LOOKBACK_DAYS
                summary["truncated"] = (
                    (resp.get("total") or 0) >= MAX_RESULTS_PER_QUERY
                )
                baseline["host_recent"] = summary
        except Exception as e:
            logger.warning(f"[CSBaseline] host_recent query failed: {e}")
            baseline["host_recent"] = {"error": str(e)}

    return baseline
