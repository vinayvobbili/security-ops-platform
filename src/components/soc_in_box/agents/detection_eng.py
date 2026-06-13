"""Detection Engineer agent — periodic rule-tuning analysis over the bus.

Runs on a timer (default daily). Each pass:

1. Replays ``soc.audit`` over the configured window.
2. Filters to ``alert.triaged`` events and clusters them by triggering rule.
3. For each rule with enough FP / TP-Benign volume to merit attention,
   asks the LLM for ONE concrete tuning recommendation (exclude this
   service account, narrow this match condition, lower this severity).
4. Publishes a ``DetectionTuningReport`` rollup to ``soc.cases``.
5. Sends a single Pokedex Webex card with the proposals.

v1 produces TEXT recommendations only — no auto-edits to the rule
catalog. The engineer-on-the-loop reviews the card and decides what to
ship. Future work could turn proposals into structured diffs against the
rules cache.

CLI::

    python -m src.components.soc_in_box.agents.detection_eng \\
        --window-hours 24 [--dry-run] [--no-webex] [--no-llm]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from langchain_core.messages import HumanMessage, SystemMessage

from src.components.soc_in_box.bus import (
    STREAM_AUDIT, STREAM_CASES, get_redis_client, publish, replay,
)
from src.components.soc_in_box.schemas import DetectionTuningReport

logger = logging.getLogger(__name__)


ROLE_NAME = "detection_eng"
DEFAULT_WINDOW_HOURS = 24

# A rule must have at least this many FPs (or TP-Benigns) in the window to
# qualify for a tuning proposal. Below this threshold the noise/signal isn't
# worth burning an LLM call on.
QUALIFY_THRESHOLD = 3

# How many proposals to render in the card (we still publish all of them).
MAX_PROPOSALS_CARD = 5

# How many sample tickets to keep per proposal for evidence.
SAMPLE_TICKETS_PER_PROPOSAL = 5

# How many top entities (hostnames/users) to surface per proposal.
TOP_ENTITIES_PER_PROPOSAL = 5

VALID_RISKS = ("low", "medium", "high")


# -- aggregation ---------------------------------------------------------

@dataclass
class RuleCluster:
    rule_name: str
    total_count: int = 0
    false_positive_count: int = 0
    benign_tp_count: int = 0
    malicious_count: int = 0  # tracked for context, not tuning
    contained_count: int = 0
    host_counts: Counter = field(default_factory=Counter)
    user_counts: Counter = field(default_factory=Counter)
    sample_tickets: list[dict[str, Any]] = field(default_factory=list)

    def qualifies(self) -> bool:
        # A rule qualifies if its FP count or its benign-TP count crosses the
        # threshold. Either is a tuning opportunity (FP = rule is too loose;
        # benign-TP = rule is firing on legitimate activity that doesn't need
        # to alert).
        return (self.false_positive_count >= QUALIFY_THRESHOLD
                or self.benign_tp_count >= QUALIFY_THRESHOLD)


def _parse_event_ts(raw: Any) -> Optional[datetime]:
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    if not isinstance(raw, str):
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _rule_name_from_event(e: dict[str, Any]) -> str:
    """Pull the triggering rule name from Sentinel's denormalized details."""
    details = e.get("details") or {}
    for k in ("rule_name", "alert_rule", "ruleName"):
        v = details.get(k)
        if v:
            return str(v).strip()
    return ""


def cluster(events: list[dict[str, Any]],
            window_start: datetime,
            window_end: datetime) -> tuple[int, dict[str, RuleCluster]]:
    """Cluster ``alert.triaged`` events by triggering rule.

    Returns ``(total_alerts_examined, {rule_name: RuleCluster})``.
    Events without a rule_name are skipped (they can't be tuning targets).
    """
    clusters: dict[str, RuleCluster] = {}
    total = 0
    for e in events:
        if e.get("event_type") != "alert.triaged":
            continue
        ts = _parse_event_ts(e.get("timestamp"))
        if ts is None or ts < window_start or ts > window_end:
            continue
        total += 1
        rule = _rule_name_from_event(e)
        if not rule:
            continue
        c = clusters.setdefault(rule, RuleCluster(rule_name=rule))
        c.total_count += 1
        v = e.get("verdict") or ""
        if v == "false_positive":
            c.false_positive_count += 1
        elif v == "true_positive_benign":
            c.benign_tp_count += 1
        elif v == "true_positive_malicious":
            c.malicious_count += 1
        elif v == "true_positive_malicious_contained":
            c.contained_count += 1
        host = e.get("hostname") or ""
        if host:
            c.host_counts[host] += 1
        user = e.get("username") or ""
        if user:
            c.user_counts[user] += 1
        if len(c.sample_tickets) < SAMPLE_TICKETS_PER_PROPOSAL:
            c.sample_tickets.append({
                "ticket_id": e.get("ticket_id") or "",
                "verdict": v,
                "hostname": host,
                "username": user,
                "summary": (e.get("summary") or "")[:200],
            })
    return total, clusters


# -- LLM recommendation --------------------------------------------------

SYSTEM_PROMPT = """You are the Detection Engineer at the company's SOC. You receive a cluster
of recent alerts that all fired from the SAME detection rule, along with the verdicts the
triage team assigned.

Your job: produce ONE concrete tuning recommendation for this rule that would reduce false
positives without losing the true-positive signal. Be specific — name the field, the value,
the condition. Generic advice ("review the rule") is worthless.

Examples of good recommendations:
- "Exclude user_principal_name ending in '@svc.the-company.com' — service accounts are
  responsible for 4 of 5 FPs in this cluster."
- "Tighten the match: require parent_process_name != 'msiexec.exe'. The benign TPs are all
  legitimate software installs."
- "Lower severity from High to Medium — 85% of fires are benign auto-quarantines that
  don't need a P9."
- "Add exclusion for host pattern 'BUILD-*' — Jenkins build agents trigger this from
  nightly scans."

DECISION CRITERIA:

- confidence: 0.0–1.0. How confident are you that this change won't break real detections?
  High confidence requires multiple data points pointing the same way.
- change_risk: "low" / "medium" / "high". How risky is shipping this tuning?
  - low: narrow exclusion (specific user, specific path, specific host) backed by ≥3 FPs.
  - medium: severity change or broader pattern (e.g. host wildcard).
  - high: structural change to the rule logic. Use sparingly.

Output STRICT JSON ONLY (no markdown fence, no prose) with this shape:

{
  "tuning_recommendation": "one or two sentences, specific",
  "confidence": 0.0-1.0,
  "change_risk": "low" | "medium" | "high"
}
"""


def _build_user_prompt(cluster: RuleCluster) -> str:
    parts = [
        f"# Rule: {cluster.rule_name}",
        "",
        f"Total fires in window: {cluster.total_count}",
        f"- false_positive: {cluster.false_positive_count}",
        f"- true_positive_benign: {cluster.benign_tp_count}",
        f"- true_positive_malicious: {cluster.malicious_count}",
        f"- true_positive_malicious_contained: {cluster.contained_count}",
        "",
    ]
    top_hosts = cluster.host_counts.most_common(TOP_ENTITIES_PER_PROPOSAL)
    top_users = cluster.user_counts.most_common(TOP_ENTITIES_PER_PROPOSAL)
    if top_hosts:
        parts.append("Top hosts (count):")
        parts += [f"  - {h}: {c}" for h, c in top_hosts]
        parts.append("")
    if top_users:
        parts.append("Top users (count):")
        parts += [f"  - {u}: {c}" for u, c in top_users]
        parts.append("")
    if cluster.sample_tickets:
        parts.append("Sample tickets (verdict — host — summary):")
        for t in cluster.sample_tickets:
            parts.append(
                f"  - #{t['ticket_id']} [{t['verdict']}] host={t['hostname'] or '-'} "
                f"user={t['username'] or '-'}: {t['summary']}"
            )
        parts.append("")
    parts += [
        "Produce ONE tuning recommendation per the system prompt. JSON only.",
    ]
    return "\n".join(parts)


def _extract_json(text: str) -> Optional[dict[str, Any]]:
    if not text:
        return None
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        return None
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        logger.warning("detection_eng: JSON parse failed: %s", exc)
        return None


def _coerce_risk(v: Any) -> str:
    return v if isinstance(v, str) and v in VALID_RISKS else "medium"


def _llm_recommend(cluster: RuleCluster) -> dict[str, Any]:
    """Single LLM call → tuning recommendation dict. Falls back to a stub on error."""
    try:
        from my_bot.utils.llm_factory import create_llm
        llm = create_llm()
        resp = llm.invoke([
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=_build_user_prompt(cluster)),
        ])
        text = (resp.content or "").strip() if hasattr(resp, "content") else str(resp).strip()
        parsed = _extract_json(text) or {}
        return {
            "tuning_recommendation": str(parsed.get("tuning_recommendation") or "").strip()[:600]
                or _fallback_rec(cluster),
            "confidence": max(0.0, min(1.0, float(parsed.get("confidence") or 0.0))),
            "change_risk": _coerce_risk(parsed.get("change_risk")),
        }
    except Exception as exc:
        logger.warning("detection_eng: LLM recommend failed for %s: %s",
                       cluster.rule_name, exc)
        return {
            "tuning_recommendation": _fallback_rec(cluster),
            "confidence": 0.3,
            "change_risk": "medium",
        }


def _fallback_rec(cluster: RuleCluster) -> str:
    fp = cluster.false_positive_count
    benign = cluster.benign_tp_count
    if fp >= benign:
        return (f"Review rule — {fp} FPs in window. "
                f"(LLM narrative unavailable; manual triage required.)")
    return (f"Review rule — {benign} benign TPs in window. "
            f"(LLM narrative unavailable; manual triage required.)")


def _proposal_from_cluster(cluster: RuleCluster,
                           use_llm: bool) -> dict[str, Any]:
    """Build the dict serialized into ``DetectionTuningReport.proposals``."""
    rec = _llm_recommend(cluster) if use_llm else {
        "tuning_recommendation": _fallback_rec(cluster),
        "confidence": 0.0,
        "change_risk": "medium",
    }
    top_entities: list[str] = []
    for h, c in cluster.host_counts.most_common(TOP_ENTITIES_PER_PROPOSAL):
        if c >= 2:
            top_entities.append(f"host:{h}")
    for u, c in cluster.user_counts.most_common(TOP_ENTITIES_PER_PROPOSAL):
        if c >= 2:
            top_entities.append(f"user:{u}")
    return {
        "rule_name": cluster.rule_name,
        "total_count": cluster.total_count,
        "false_positive_count": cluster.false_positive_count,
        "benign_tp_count": cluster.benign_tp_count,
        "malicious_count": cluster.malicious_count,
        "contained_count": cluster.contained_count,
        "top_entities": top_entities[:TOP_ENTITIES_PER_PROPOSAL],
        "sample_ticket_ids": [t["ticket_id"] for t in cluster.sample_tickets
                              if t.get("ticket_id")],
        "tuning_recommendation": rec["tuning_recommendation"],
        "confidence": rec["confidence"],
        "change_risk": rec["change_risk"],
    }


# -- orchestration -------------------------------------------------------

def run_once(*,
             window_hours: float = DEFAULT_WINDOW_HOURS,
             dry_run: bool = False,
             send_webex: bool = True,
             use_llm: bool = True) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    window_end = now
    window_start = now - timedelta(hours=window_hours)

    client = get_redis_client()
    events = replay(client, STREAM_AUDIT, start="-", end="+", count=None)
    total, clusters = cluster(events, window_start, window_end)
    qualifying = [c for c in clusters.values() if c.qualifies()]
    # Sort by combined tuning-opportunity score (FP + benign), worst first
    qualifying.sort(key=lambda c: (c.false_positive_count + c.benign_tp_count),
                    reverse=True)
    logger.info("detection_eng: window=%sh total=%s rules_seen=%d qualifying=%d",
                window_hours, total, len(clusters), len(qualifying))

    proposals: list[dict[str, Any]] = []
    for c in qualifying:
        proposals.append(_proposal_from_cluster(c, use_llm=use_llm))

    from src.components.soc_in_box.agents.detection_eng_webex import (
        render_card, render_fallback_markdown,
    )
    card = render_card(window_start, window_end, total, proposals)
    markdown = render_fallback_markdown(window_start, window_end, total, proposals)

    webex_msg_id: Optional[str] = None
    if send_webex and not dry_run:
        from my_config import get_config
        cfg = get_config()
        room = cfg.webex_room_id_soc_in_a_box or cfg.webex_room_id_dev_test_space
        if room:
            webex_msg_id = _send_to_webex(markdown, card, room)
        else:
            logger.warning("detection_eng: no Webex room configured, skipping send")

    if not dry_run:
        report = DetectionTuningReport(
            correlation_id=window_start.isoformat(),
            produced_by=ROLE_NAME,
            window_start=window_start,
            window_end=window_end,
            total_alerts_examined=total,
            rules_flagged=len(qualifying),
            proposals=proposals,
            webex_message_id=webex_msg_id,
        )
        publish(client, STREAM_CASES, report)
        logger.info("detection_eng: published detection.tuning_report event_id=%s",
                    report.event_id)

    return {
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "total_alerts_examined": total,
        "rules_flagged": len(qualifying),
        "proposals": proposals,
        "markdown": markdown,
        "card": card,
        "webex_message_id": webex_msg_id,
        "dry_run": dry_run,
    }


def _send_to_webex(markdown: str, card: dict[str, Any], room_id: str) -> Optional[str]:
    from my_config import get_config
    from webexteamssdk import WebexTeamsAPI
    cfg = get_config()
    token = cfg.webex_bot_access_token_pokedex
    if not token:
        logger.warning("detection_eng: WEBEX_BOT_ACCESS_TOKEN_POKEDEX not set, skipping")
        return None
    try:
        api = WebexTeamsAPI(access_token=token)
        msg = api.messages.create(
            roomId=room_id,
            markdown=markdown,
            attachments=[{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": card,
            }],
        )
        return getattr(msg, "id", None)
    except Exception as exc:
        logger.error("detection_eng: Webex send failed: %s", exc)
        return None


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="SOC-in-a-Box Detection Engineer review")
    p.add_argument("--window-hours", type=float, default=DEFAULT_WINDOW_HOURS)
    p.add_argument("--dry-run", action="store_true",
                   help="Compute + print; do not publish to bus or send Webex")
    p.add_argument("--no-webex", action="store_true",
                   help="Publish bus event but skip Webex send")
    p.add_argument("--no-llm", action="store_true",
                   help="Skip LLM recommendation; use deterministic stub")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    args = _build_argparser().parse_args(argv)
    result = run_once(
        window_hours=args.window_hours,
        dry_run=args.dry_run,
        send_webex=not args.no_webex,
        use_llm=not args.no_llm,
    )
    if args.dry_run:
        print(result["markdown"])
        print("\n--- adaptive card ---")
        print(json.dumps(result["card"], indent=2, default=str))
        print("\n--- status ---")
        print(json.dumps({k: v for k, v in result.items()
                          if k not in {"markdown", "card"}},
                         indent=2, default=str))
    else:
        logger.info("detection_eng: done (webex_msg_id=%s, dry_run=%s)",
                    result.get("webex_message_id"), result["dry_run"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
