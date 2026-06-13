"""Threat Hunter agent — proactive pattern detection across the bus.

Runs on a timer (default every 12h). The Hunter is the proactive
complement to the reactive Tier 1/2/IR Lead chain: it scans recent
``alert.triaged`` events for patterns that may have escaped triage —
recurring hosts, confirmed TPs that didn't escalate, shared external
pivots — and produces hunt hypotheses + suggested investigation steps.

v1 hunts what's already on the bus (no live telemetry queries). Three
deterministic detectors fire pre-aggregated clusters; an LLM call per
cluster turns the cluster into an actionable hypothesis.

CLI::

    python -m src.components.soc_in_box.agents.threat_hunter \\
        --window-hours 12 [--dry-run] [--no-webex] [--no-llm]
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
from src.components.soc_in_box.schemas import HuntingReport

logger = logging.getLogger(__name__)


ROLE_NAME = "threat_hunter"
DEFAULT_WINDOW_HOURS = 12

# Pattern thresholds — below these counts a cluster isn't worth a hunt.
HOST_REPEAT_THRESHOLD = 3   # same host in N+ alerts
PIVOT_SHARED_THRESHOLD = 2  # same external IP / domain across N+ tickets
POTENTIAL_MISS_THRESHOLD = 1  # any TP-malicious without follow-on escalation

# v2 verdicts that indicate a confirmed-real incident
MALICIOUS_VERDICTS = ("true_positive_malicious", "true_positive_malicious_contained")

# IP/domain extraction from free-text summaries. Conservative — we don't want to
# false-positive on internal IPs or generic hostnames; defer false-positive
# rejection to the LLM hypothesis step.
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# A simple FQDN matcher: 2+ dot-separated labels of allowed chars, TLD 2-6 chars.
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,}[a-z]{2,6}\b",
                        re.IGNORECASE)


# -- detectors -----------------------------------------------------------

@dataclass
class HostRepeatCluster:
    hostname: str
    ticket_ids: list[str] = field(default_factory=list)
    verdicts: Counter = field(default_factory=Counter)
    rules: Counter = field(default_factory=Counter)
    sample_summaries: list[str] = field(default_factory=list)

    def qualifies(self) -> bool:
        return len(self.ticket_ids) >= HOST_REPEAT_THRESHOLD


@dataclass
class PivotCluster:
    indicator: str  # IP or domain
    kind: str       # "ip" or "domain"
    ticket_ids: list[str] = field(default_factory=list)
    hosts: Counter = field(default_factory=Counter)
    sample_summaries: list[str] = field(default_factory=list)

    def qualifies(self) -> bool:
        return len(self.ticket_ids) >= PIVOT_SHARED_THRESHOLD


@dataclass
class PotentialMiss:
    ticket_id: str
    hostname: str
    username: str
    verdict: str
    summary: str
    priority_score: int
    rule_name: str


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
    details = e.get("details") or {}
    for k in ("rule_name", "alert_rule", "ruleName"):
        v = details.get(k)
        if v:
            return str(v).strip()
    return ""


def _extract_indicators(text: str) -> tuple[list[str], list[str]]:
    """Return (ips, domains) lists from free-text summary."""
    if not text:
        return [], []
    ips = list({m for m in _IP_RE.findall(text)})
    # Drop obvious private/loopback ranges
    ips = [ip for ip in ips
           if not (ip.startswith("10.") or ip.startswith("192.168.")
                   or ip.startswith("172.") or ip.startswith("127.")
                   or ip.startswith("169.254."))]
    domains = list({m.lower() for m in _DOMAIN_RE.findall(text) if "." in m})
    # Strip out things that look like file extensions (.exe, .dll, .ps1, etc.)
    bad_tlds = {"exe", "dll", "ps1", "py", "js", "html", "htm", "log", "txt",
                "bat", "vbs", "msi", "lnk", "scr", "doc", "docx", "pdf", "zip"}
    domains = [d for d in domains if d.rsplit(".", 1)[-1] not in bad_tlds]
    return ips, domains


def _build_clusters(events: list[dict[str, Any]],
                    window_start: datetime,
                    window_end: datetime
                    ) -> tuple[int, dict[str, HostRepeatCluster],
                               dict[str, PivotCluster], list[PotentialMiss]]:
    """Return (total_examined, host_clusters, pivot_clusters, potential_misses)."""
    host_clusters: dict[str, HostRepeatCluster] = {}
    pivot_clusters: dict[str, PivotCluster] = {}
    potential_misses: list[PotentialMiss] = []

    # Map ticket_id → True if it has any follow-on tier2/ir.plan/case.escalated
    # (used by potential-miss detector).
    escalated_tickets: set[str] = set()
    for e in events:
        et = e.get("event_type") or ""
        if et in ("tier2.analysis", "ir.plan", "case.escalated"):
            tid = str(e.get("ticket_id") or "")
            if tid:
                escalated_tickets.add(tid)

    total = 0
    for e in events:
        if e.get("event_type") != "alert.triaged":
            continue
        ts = _parse_event_ts(e.get("timestamp"))
        if ts is None or ts < window_start or ts > window_end:
            continue
        total += 1

        tid = str(e.get("ticket_id") or "")
        verdict = e.get("verdict") or ""
        hostname = (e.get("hostname") or "").strip()
        username = (e.get("username") or "").strip()
        summary = (e.get("summary") or "").strip()
        priority = int(e.get("priority_score") or 0)
        rule = _rule_name_from_event(e)

        # Host repeat detector
        if hostname:
            c = host_clusters.setdefault(hostname,
                                         HostRepeatCluster(hostname=hostname))
            c.ticket_ids.append(tid)
            c.verdicts[verdict] += 1
            if rule:
                c.rules[rule] += 1
            if len(c.sample_summaries) < 3 and summary:
                c.sample_summaries.append(summary[:200])

        # Pivot detector — extract IPs/domains from summary
        ips, domains = _extract_indicators(summary)
        for ip in ips:
            key = f"ip:{ip}"
            p = pivot_clusters.setdefault(key, PivotCluster(indicator=ip, kind="ip"))
            if tid not in p.ticket_ids:
                p.ticket_ids.append(tid)
            if hostname:
                p.hosts[hostname] += 1
            if len(p.sample_summaries) < 3 and summary:
                p.sample_summaries.append(summary[:200])
        for d in domains:
            key = f"domain:{d}"
            p = pivot_clusters.setdefault(key, PivotCluster(indicator=d, kind="domain"))
            if tid not in p.ticket_ids:
                p.ticket_ids.append(tid)
            if hostname:
                p.hosts[hostname] += 1
            if len(p.sample_summaries) < 3 and summary:
                p.sample_summaries.append(summary[:200])

        # Potential miss — confirmed-malicious that didn't escalate
        if verdict in MALICIOUS_VERDICTS and tid and tid not in escalated_tickets:
            potential_misses.append(PotentialMiss(
                ticket_id=tid, hostname=hostname, username=username,
                verdict=verdict, summary=summary[:300],
                priority_score=priority, rule_name=rule,
            ))

    return total, host_clusters, pivot_clusters, potential_misses


# -- LLM hypothesis ------------------------------------------------------

SYSTEM_PROMPT = """You are a Threat Hunter at the company's SOC. You receive a CLUSTER of
related alerts (same host / same external pivot / a confirmed TP that didn't escalate)
and your job is to produce a SHORT hunt hypothesis: what should the responder look at
to determine if this is a real campaign or a false-positive pattern?

Hunt hypotheses are SPECIFIC and actionable. "Investigate further" is useless. Good:

- "Three FPs from BUILD-* hosts all involve PowerShell encoded commands at 02:00 UTC
  — likely Jenkins nightly job. Confirm by checking buildbot user's scheduled tasks."
- "Same external IP 198.51.100.42 hit by FIN-WS-12 + FIN-DB-04 within 10 min — likely
  C2 hop chain. Pull netflow between these hosts for the same window."
- "EXEC-LP-07 triaged as TP-Malicious-Contained but no Tier 2 engagement — verify
  containment held; if not, this needs IR Lead attention."

DECISION CRITERIA:

- confidence: 0.0–1.0 that this cluster represents a real hunting opportunity.
- suggested_investigation: 1-2 SPECIFIC next steps (queries to run, hosts to look at,
  data to pull). Cite real entity names / IPs / time windows.

Output STRICT JSON ONLY (no markdown fence, no prose) with this shape:

{
  "description": "1-2 sentence summary of what you see and what's interesting",
  "suggested_investigation": "1-2 SPECIFIC next steps",
  "confidence": 0.0-1.0
}
"""


def _build_host_prompt(c: HostRepeatCluster) -> str:
    parts = [
        f"# Host repeat: {c.hostname}",
        f"Tickets ({len(c.ticket_ids)}): {', '.join('#' + t for t in c.ticket_ids[:10])}",
        f"Verdicts: " + ", ".join(f"{v}={n}" for v, n in c.verdicts.most_common()),
    ]
    if c.rules:
        parts.append(f"Rules: " + ", ".join(f"'{r}' ({n})" for r, n in c.rules.most_common(3)))
    if c.sample_summaries:
        parts.append("Sample summaries:")
        parts += [f"  - {s}" for s in c.sample_summaries]
    return "\n".join(parts)


def _build_pivot_prompt(c: PivotCluster) -> str:
    parts = [
        f"# Shared {c.kind} pivot: {c.indicator}",
        f"Tickets ({len(c.ticket_ids)}): {', '.join('#' + t for t in c.ticket_ids[:10])}",
    ]
    if c.hosts:
        parts.append("Hosts involved: " + ", ".join(f"{h} ({n})"
                                                     for h, n in c.hosts.most_common(5)))
    if c.sample_summaries:
        parts.append("Sample summaries:")
        parts += [f"  - {s}" for s in c.sample_summaries]
    return "\n".join(parts)


def _build_miss_prompt(m: PotentialMiss) -> str:
    return "\n".join([
        f"# Potential miss: ticket #{m.ticket_id}",
        f"Verdict: {m.verdict} (priority {m.priority_score}/10)",
        f"Host: {m.hostname or '—'}  •  User: {m.username or '—'}",
        f"Rule: {m.rule_name or '—'}",
        f"Summary: {m.summary or '(none)'}",
        "",
        "This ticket was triaged as MALICIOUS but no Tier 2 / IR Lead engagement "
        "was observed in the audit window. Was containment auto-handled, or was "
        "this an escape?",
    ])


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
        logger.warning("threat_hunter: JSON parse failed: %s", exc)
        return None


def _llm_hypothesis(prompt_body: str) -> dict[str, Any]:
    """LLM call → hunt hypothesis dict. Falls back to a stub on error."""
    try:
        from my_bot.utils.llm_factory import create_llm
        llm = create_llm()
        resp = llm.invoke([
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=prompt_body),
        ])
        text = (resp.content or "").strip() if hasattr(resp, "content") else str(resp).strip()
        parsed = _extract_json(text) or {}
        return {
            "description": str(parsed.get("description") or "").strip()[:400]
                or "(no narrative — manual triage required)",
            "suggested_investigation": str(parsed.get("suggested_investigation") or "").strip()[:400]
                or "(no investigation suggested)",
            "confidence": max(0.0, min(1.0, float(parsed.get("confidence") or 0.0))),
        }
    except Exception as exc:
        logger.warning("threat_hunter: LLM hypothesis failed: %s", exc)
        return {
            "description": "(LLM unavailable — manual review of cluster needed)",
            "suggested_investigation": "(LLM unavailable)",
            "confidence": 0.3,
        }


def _finding_from_host(c: HostRepeatCluster, use_llm: bool) -> dict[str, Any]:
    rec = _llm_hypothesis(_build_host_prompt(c)) if use_llm else {
        "description": (f"Host {c.hostname} appeared in {len(c.ticket_ids)} alerts "
                        f"with verdicts: {dict(c.verdicts)}."),
        "suggested_investigation": "(LLM disabled — review tickets manually)",
        "confidence": 0.0,
    }
    return {
        "kind": "host_repeat",
        "indicator": c.hostname,
        "affected_entities": [f"host:{c.hostname}"]
            + [f"rule:{r}" for r, _ in c.rules.most_common(2)],
        "related_tickets": c.ticket_ids[:10],
        "ticket_count": len(c.ticket_ids),
        "description": rec["description"],
        "suggested_investigation": rec["suggested_investigation"],
        "confidence": rec["confidence"],
    }


def _finding_from_pivot(c: PivotCluster, use_llm: bool) -> dict[str, Any]:
    rec = _llm_hypothesis(_build_pivot_prompt(c)) if use_llm else {
        "description": (f"{c.kind.upper()} {c.indicator} seen across {len(c.ticket_ids)} "
                        f"tickets and {len(c.hosts)} hosts."),
        "suggested_investigation": "(LLM disabled — review tickets manually)",
        "confidence": 0.0,
    }
    return {
        "kind": "shared_pivot",
        "indicator": c.indicator,
        "pivot_kind": c.kind,
        "affected_entities": [f"{c.kind}:{c.indicator}"]
            + [f"host:{h}" for h, _ in c.hosts.most_common(5)],
        "related_tickets": c.ticket_ids[:10],
        "ticket_count": len(c.ticket_ids),
        "description": rec["description"],
        "suggested_investigation": rec["suggested_investigation"],
        "confidence": rec["confidence"],
    }


def _finding_from_miss(m: PotentialMiss, use_llm: bool) -> dict[str, Any]:
    rec = _llm_hypothesis(_build_miss_prompt(m)) if use_llm else {
        "description": (f"Ticket #{m.ticket_id} ({m.verdict}) did not escalate to "
                        f"Tier 2 / IR Lead."),
        "suggested_investigation": "(LLM disabled — review ticket manually)",
        "confidence": 0.0,
    }
    return {
        "kind": "potential_miss",
        "indicator": m.ticket_id,
        "affected_entities": [f"host:{m.hostname}", f"user:{m.username}"]
            + ([f"rule:{m.rule_name}"] if m.rule_name else []),
        "related_tickets": [m.ticket_id],
        "ticket_count": 1,
        "priority_score": m.priority_score,
        "verdict": m.verdict,
        "description": rec["description"],
        "suggested_investigation": rec["suggested_investigation"],
        "confidence": rec["confidence"],
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
    total, host_clusters, pivot_clusters, potential_misses = _build_clusters(
        events, window_start, window_end,
    )

    findings: list[dict[str, Any]] = []
    # Worst-first ordering: more tickets / higher pri at top
    for c in sorted(host_clusters.values(),
                    key=lambda x: len(x.ticket_ids), reverse=True):
        if c.qualifies():
            findings.append(_finding_from_host(c, use_llm))
    for c in sorted(pivot_clusters.values(),
                    key=lambda x: len(x.ticket_ids), reverse=True):
        if c.qualifies():
            findings.append(_finding_from_pivot(c, use_llm))
    for m in sorted(potential_misses,
                    key=lambda x: x.priority_score, reverse=True):
        findings.append(_finding_from_miss(m, use_llm))

    logger.info("threat_hunter: window=%sh examined=%d findings=%d "
                "(hosts=%d pivots=%d misses=%d)",
                window_hours, total, len(findings),
                sum(1 for c in host_clusters.values() if c.qualifies()),
                sum(1 for c in pivot_clusters.values() if c.qualifies()),
                len(potential_misses))

    from src.components.soc_in_box.agents.threat_hunter_webex import (
        render_card, render_fallback_markdown,
    )
    card = render_card(window_start, window_end, total, findings)
    markdown = render_fallback_markdown(window_start, window_end, total, findings)

    webex_msg_id: Optional[str] = None
    if send_webex and not dry_run:
        from my_config import get_config
        cfg = get_config()
        room = cfg.webex_room_id_soc_in_a_box or cfg.webex_room_id_dev_test_space
        if room:
            webex_msg_id = _send_to_webex(markdown, card, room)
        else:
            logger.warning("threat_hunter: no Webex room configured, skipping send")

    if not dry_run:
        report = HuntingReport(
            correlation_id=window_start.isoformat(),
            produced_by=ROLE_NAME,
            window_start=window_start,
            window_end=window_end,
            hunts_examined=total,
            findings=findings,
            webex_message_id=webex_msg_id,
        )
        publish(client, STREAM_CASES, report)
        logger.info("threat_hunter: published hunting.report event_id=%s",
                    report.event_id)

    return {
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "hunts_examined": total,
        "findings": findings,
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
        logger.warning("threat_hunter: WEBEX_BOT_ACCESS_TOKEN_POKEDEX not set, skipping")
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
        logger.error("threat_hunter: Webex send failed: %s", exc)
        return None


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="SOC-in-a-Box Threat Hunter sweep")
    p.add_argument("--window-hours", type=float, default=DEFAULT_WINDOW_HOURS)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--no-webex", action="store_true")
    p.add_argument("--no-llm", action="store_true")
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
        logger.info("threat_hunter: done (webex_msg_id=%s, dry_run=%s)",
                    result.get("webex_message_id"), result["dry_run"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
