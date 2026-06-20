#!/usr/bin/env python3
"""SOC-in-a-Box cascade backtest harness.

Replays historical CrowdStrike tickets through the full agent chain
(Tier 2 → IR Lead → Threat Intel) so we can quantify how the AI SOC
would have handled tickets that real analysts already worked. Sentinel
(Tier 1) can also be run in the loop with ``--mode full``; the default
``--mode downstream`` skips Sentinel and fabricates an ``AlertTriaged``
event from the timeline-db ticket fields — much cheaper, and lets us
focus on the new agents.

Ground truth comes from the ticket's ``escalation_state`` field:

    escalation_state ∈ {Tier 2, Tier2, Tier3}  →  human_escalated=True
    status=2 (closed) and no escalation        →  human_escalated=False
    otherwise                                  →  unknown (excluded)

The harness measures: did our Tier 2 escalate to IR Lead on the tickets
where humans did? That's the headline number for the demo.

All side effects are neutered:
 - Bus publishes captured in-process (no Redis writes)
 - Webex card sends → no-op
 - XSOAR note writes → no-op
 - HITL action store → no-op (or routed to backtest sidecar)

Verdicts are persisted to ``data/soc_in_box/verdicts.sqlite`` with
``role`` suffixed ``_backtest`` and ``ground_truth`` filled. A run-level
JSON summary is written to ``data/soc_in_box/backtest_summary.json`` for
the /soc-in-a-box dashboard panel.

Run::

    # Fast smoke test, no LLM calls
    python scripts/soc_in_box_backtest.py --limit 5 --dry-run

    # Real run, downstream only (T2 → IR → TI; no Sentinel)
    python scripts/soc_in_box_backtest.py --limit 30

    # Real run, full pipeline (incl. Sentinel — slow)
    python scripts/soc_in_box_backtest.py --limit 10 --mode full
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sqlite3
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from services.xsoar_timeline_db import get_connection as get_timeline_conn  # noqa: E402
from src.components.soc_in_box import verdict_store  # noqa: E402
from src.components.soc_in_box.schemas import (  # noqa: E402
    AlertTriaged, CaseEscalated, IRPlan, Tier2Analysis,
)

logger = logging.getLogger(__name__)


SUMMARY_PATH = Path("data/soc_in_box/backtest_summary.json")


# ---- Sampling -----------------------------------------------------------

# Severity buckets we draw from. Stratified sampling pulls equal counts
# from each so a tiny --limit doesn't collapse onto sev-1 only.
SEVERITY_BUCKETS = (1, 2, 3, 4)

# Normalize the messy escalation_state strings
ESCALATED_STATES = {"Tier 2", "Tier2", "Tier3", "Tier 3"}


def _normalize_escalation(state: Optional[str]) -> Optional[str]:
    s = (state or "").strip()
    if s in ESCALATED_STATES:
        return "escalate"
    if s in {"", "Other"}:
        # Treat blank as close (Tier 1 closed it). "Other" is ambiguous; exclude.
        return "close" if s == "" else None
    return None


def _ground_truth(row: sqlite3.Row) -> Optional[str]:
    """``escalate`` / ``close`` / None (excluded)."""
    if row["status"] != 2:
        return None
    return _normalize_escalation(row["escalation_state"])


def _sample_tickets(limit: int, stratify: bool, seed: int) -> list[sqlite3.Row]:
    """Pull CrowdStrike-origin closed tickets with a usable ground-truth label.

    Stratified mode: split ``limit`` 50/50 between escalated and closed
    tickets, then within each half stratify across the severity buckets.
    Keeps the cascade-vs-human comparison fair at small N.
    """
    random.seed(seed)
    half_esc = limit // 2
    half_close = limit - half_esc
    with get_timeline_conn() as conn:
        if stratify:
            rows: list[sqlite3.Row] = []
            sev_per_half = max(1, half_esc // len(SEVERITY_BUCKETS))
            for sev in SEVERITY_BUCKETS:
                rows.extend(conn.execute(
                    """SELECT * FROM xsoar_tickets
                       WHERE source_brand='CrowdstrikeFalcon' AND status=2
                         AND severity=?
                         AND (escalation_state IN ('Tier 2','Tier2','Tier3','Tier 3'))
                       ORDER BY RANDOM() LIMIT ?""",
                    (sev, sev_per_half),
                ).fetchall())
            sev_per_half = max(1, half_close // len(SEVERITY_BUCKETS))
            for sev in SEVERITY_BUCKETS:
                rows.extend(conn.execute(
                    """SELECT * FROM xsoar_tickets
                       WHERE source_brand='CrowdstrikeFalcon' AND status=2
                         AND severity=?
                         AND (escalation_state IS NULL OR escalation_state='')
                       ORDER BY RANDOM() LIMIT ?""",
                    (sev, sev_per_half),
                ).fetchall())
            random.shuffle(rows)
            return rows[:limit]
        return conn.execute(
            """SELECT * FROM xsoar_tickets
               WHERE source_brand='CrowdstrikeFalcon' AND status=2
               ORDER BY RANDOM() LIMIT ?""",
            (limit,),
        ).fetchall()


# ---- Synthetic event fabrication ----------------------------------------

def _row_to_alert_triaged_event(row: sqlite3.Row) -> dict[str, Any]:
    """Fabricate an ``AlertTriaged`` event from a historical ticket row.

    Used by ``--mode downstream`` to skip the real Sentinel pipeline.
    The ``verdict`` is chosen to bias toward Tier 2 engagement on tickets
    that humans escalated, so the harness exercises the cascade. This is
    deliberately optimistic for Sentinel — we are measuring the downstream
    agents, not Sentinel itself.
    """
    raw: dict[str, Any] = {}
    if row["raw_json"]:
        try:
            raw = json.loads(row["raw_json"])
        except json.JSONDecodeError:
            raw = {}

    truth = _ground_truth(row)
    # If a human escalated this, give Sentinel TP-malicious so Tier 2 engages.
    # If they closed it, give Sentinel a benign verdict so the cascade has a
    # chance to recognize "nothing to escalate."
    if truth == "escalate":
        verdict = "true_positive_malicious"
        priority = 8
    else:
        verdict = "true_positive_benign"
        priority = 4
    summary = (row["close_notes"] or row["name"] or "(no summary)")[:600]
    sev_display = row["severity_display"] or ""
    rule_name = row["name"] or ""

    event = AlertTriaged(
        correlation_id=str(row["id"]),
        produced_by="sentinel_triage_backtest",
        ticket_id=str(row["id"]),
        verdict=verdict,
        confidence=0.85,
        summary=summary,
        recommended_action="(synthetic backtest event)",
        priority_score=priority,
        hostname=row["hostname"] or "",
        username=row["username"] or "",
        severity=sev_display,
        details={
            "rule_name": rule_name,
            "ticket_type": row["type"] or "",
            "category": row["security_category"] or "",
            "raw_excerpt": {
                k: raw.get(k) for k in (
                    "name", "severity", "details", "type",
                    "labels", "playbookId",
                ) if raw.get(k) is not None
            },
        },
    )
    return json.loads(event.model_dump_json())


@dataclass
class TicketTrace:
    ticket_id: str
    severity: int
    rule_name: str
    hostname: str
    username: str
    ground_truth: Optional[str]

    sentinel_verdict: str = ""
    sentinel_priority: int = 0
    sentinel_wall_ms: int = 0

    tier2_engaged: bool = False
    tier2_refined_verdict: str = ""
    tier2_escalation_decision: str = ""
    tier2_wall_ms: int = 0
    tier2_tools: int = 0

    ir_engaged: bool = False
    ir_severity: str = ""
    ir_bridge_required: bool = False
    ir_containment_count: int = 0
    ir_wall_ms: int = 0
    ir_tools: int = 0

    ti_engaged: bool = False
    ti_actor: str = ""
    ti_sev_adjustment: str = ""
    ti_wall_ms: int = 0
    ti_tools: int = 0

    errors: list[str] = field(default_factory=list)


# ---- Dry-run LLM stub ---------------------------------------------------

_FAKE_DECISIONS = {
    "tier2": {
        "refined_verdict": "true_positive_malicious",
        "confidence": 0.78,
        "escalation_decision": "escalate_to_ir_lead",
        "tier2_summary": "(dry-run) confirmed malicious behavior on host; recommend IR engagement.",
        "similar_incidents": [],
        "next_steps": ["isolate host", "pull memory dump"],
    },
    "ir_lead": {
        "severity": "SEV-2",
        "confidence": 0.80,
        "ir_summary": "(dry-run) IR plan for backtest replay.",
        "containment_actions": ["Isolate host via CS RTR", "Disable AD account"],
        "eradication_actions": ["Remove persistence", "Reset credentials"],
        "recovery_actions": ["Reimage host"],
        "notifications": ["IR On-Call", "AppSec"],
        "bridge_required": True,
        "runbook": "ransomware-precursor",
    },
    "threat_intel": {
        "intel_summary": "(dry-run) likely commodity malware family.",
        "likely_actor": "(dry-run actor)",
        "actor_confidence": 0.45,
        "actor_evidence": "(dry-run) one VT positive overlap.",
        "campaigns": [],
        "mitre_techniques": ["T1059.001"],
        "iocs_examined": [],
        "related_historical_incidents": [],
        "severity_adjustment": "confirm",
        "severity_adjustment_reason": "(dry-run)",
        "confidence": 0.7,
    },
}


class _FakeAIMessage:
    """Minimal AIMessage-like duck for tool-loop exit + final-content path."""

    def __init__(self, content: str):
        self.content = content
        self.tool_calls: list = []


class _FakeChatModel:
    """Returns a canned JSON response keyed by the agent's system prompt.

    Exits the tool loop on first iteration (no tool_calls). The system
    prompt for each agent contains a unique phrase we key on.
    """

    def bind_tools(self, _tools):
        return self

    def invoke(self, messages):
        sys_text = ""
        for m in messages:
            role = getattr(m, "type", None) or (
                "system" if "System" in type(m).__name__ else None)
            if role == "system":
                sys_text = getattr(m, "content", "") or ""
                break
        key = "tier2"
        if "Threat Intel analyst" in sys_text:
            key = "threat_intel"
        elif "STRUCTURED response plan" in sys_text:
            key = "ir_lead"
        elif "Tier 2 SOC Analyst" in sys_text:
            key = "tier2"
        return _FakeAIMessage(json.dumps(_FAKE_DECISIONS[key]))


# ---- Backtest environment + cascade engine ------------------------------

def _prepare_backtest_env() -> None:
    """Make a replay safe to run against the live system.

    The per-ticket agents now run on the aisoc kernel, so side effects are
    suppressed at their seams rather than monkey-patched out:

    - ``SIAB_BACKTEST=1`` makes each agent's ``notify`` hook skip the Webex
      cards (see ``aisoc_seams.notify_suppressed``).
    - XSOAR note writes are already gated off unless ``SOC_WRITE_XSOAR_NOTE=1``.
    - ``AISOC_DATA_DIR`` is pointed at a throwaway scratch dir so the agents'
      own verdict/HITL rows don't pollute the live ``data/soc_in_box`` stores —
      the harness writes its own ``*_backtest`` summary rows separately.
    """
    import os
    os.environ["SIAB_BACKTEST"] = "1"
    scratch = PROJECT_ROOT / "data" / "soc_in_box" / "_backtest_scratch"
    scratch.mkdir(parents=True, exist_ok=True)
    os.environ["AISOC_DATA_DIR"] = str(scratch)


def _backtest_model(dry_run: bool) -> Any:
    """The chat model the cascade runs on: a canned stub for ``--dry-run``,
    otherwise the live failover LLM via the aisoc seam."""
    if dry_run:
        return _FakeChatModel()
    from src.components.soc_in_box.aisoc_seams import soc_chat_model
    return soc_chat_model()


def _run_per_ticket_cascade(triage_event: dict[str, Any], model: Any,
                            dry_run: bool) -> dict[str, dict[str, Any]]:
    """Replay one triaged alert through Tier 2 → IR Lead → Threat Intel.

    Runs the real aisoc-based agents on a throwaway in-memory bus: publish the
    ``AlertTriaged`` event, drain each role in turn, then read the events they
    produced back off the bus. Returns the latest event of each type for the
    ticket, keyed by ``event_type`` — exactly the chain the live SOC would run,
    minus Redis and the Webex cards.
    """
    from aisoc import InMemoryBus, STREAM_TRIAGE
    from aisoc.schemas import parse_event
    from src.components.soc_in_box.agents.tier2 import Tier2Agent
    from src.components.soc_in_box.agents.ir_lead import IRLeadAgent
    from src.components.soc_in_box.agents.threat_intel import ThreatIntelAgent

    tools = None
    if not dry_run:
        from src.components.soc_in_box.aisoc_seams import soc_tools
        tools = soc_tools()

    bus = InMemoryBus()
    bus.publish(STREAM_TRIAGE, parse_event(triage_event))
    for cls in (Tier2Agent, IRLeadAgent, ThreatIntelAgent):
        cls(bus=bus, model=model, tools=tools).drain()

    tid = str(triage_event.get("ticket_id") or "")
    produced: dict[str, dict[str, Any]] = {}
    for ev in bus.replay():
        if str(ev.get("ticket_id")) == tid:
            produced[str(ev.get("event_type"))] = ev
    return produced


# ---- Per-ticket cascade -------------------------------------------------

def _run_one(row: sqlite3.Row, mode: str, dry_run: bool, model: Any) -> TicketTrace:
    """Run a single ticket through the cascade. Returns the trace."""
    truth = _ground_truth(row)
    trace = TicketTrace(
        ticket_id=str(row["id"]),
        severity=int(row["severity"] or 0),
        rule_name=row["name"] or "",
        hostname=row["hostname"] or "",
        username=row["username"] or "",
        ground_truth=truth,
    )

    # --- Step 1: Sentinel ------------------------------------------------
    if mode == "full" and not dry_run:
        try:
            # Build a thin XSOAR-ticket-shaped dict for the pipeline
            ticket = {
                "id": row["id"],
                "name": row["name"],
                "severity": row["severity"],
                "CustomFields": {
                    "affectedhostname": row["hostname"] or "",
                    "affectedusername": row["username"] or "",
                },
                "type": row["type"],
                "details": row["details"] or "",
                "created": row["created_date"],
            }
            from src.components.xsoar_alert_triage.xsoar_triage_pipeline import (
                XsoarTriagePipeline,
            )
            t0 = time.time()
            pipeline = XsoarTriagePipeline(webex_api=None, room_id="")
            # Neuter the side effects on the pipeline instance.
            pipeline._send_triage_card = lambda *a, **kw: ""
            pipeline._write_triage_to_xsoar = lambda *a, **kw: None
            result = pipeline.triage_ticket(ticket)
            trace.sentinel_wall_ms = int((time.time() - t0) * 1000)
            if result is None:
                trace.errors.append("sentinel returned None")
                return trace
            # Adapt to AlertTriaged event dict
            from dataclasses import asdict as _asdict
            details = _asdict(result) if hasattr(result, "__dataclass_fields__") else {}
            details.pop("similar_ticket_prediction", None)
            details.pop("impact_model_prediction", None)
            alert = AlertTriaged(
                correlation_id=str(result.ticket_id),
                produced_by="sentinel_triage_backtest",
                ticket_id=str(result.ticket_id),
                verdict=result.llm_verdict if result.llm_verdict in (
                    "true_positive_malicious",
                    "true_positive_malicious_contained",
                    "true_positive_benign",
                    "false_positive",
                    "close_ticket",
                ) else "close_ticket",
                confidence=max(0.0, min(1.0, float(result.llm_confidence or 0.0))),
                summary=result.llm_summary or result.llm_what_happened or "",
                recommended_action=result.llm_recommended_action or "",
                priority_score=int(result.priority_score or 0),
                hostname=result.hostname or "",
                username=result.username or "",
                severity=result.severity or "",
                details=details,
            )
            triage_event = json.loads(alert.model_dump_json())
        except Exception as exc:
            trace.errors.append(f"sentinel failed: {exc}")
            triage_event = _row_to_alert_triaged_event(row)
    else:
        triage_event = _row_to_alert_triaged_event(row)

    trace.sentinel_verdict = triage_event.get("verdict") or ""
    trace.sentinel_priority = int(triage_event.get("priority_score") or 0)

    # --- Steps 2-4: the per-ticket cascade on the aisoc kernel ------------
    # Tier 2 → IR Lead → Threat Intel, run on a throwaway in-memory bus. Each
    # role engages (or skips) on its own criteria; we read what they produced
    # back off the bus. Per-role wall time comes from the wall_time_ms each
    # agent records on its own event.
    try:
        produced = _run_per_ticket_cascade(triage_event, model, dry_run)
    except Exception as exc:
        trace.errors.append(f"cascade failed: {exc}")
        return trace

    t2 = produced.get("tier2.analysis")
    if t2 is None:
        # Sentinel verdict didn't trigger Tier 2 — fine, ground truth may
        # still be "close" which means agreement.
        return trace
    trace.tier2_engaged = True
    trace.tier2_refined_verdict = t2.get("refined_verdict") or ""
    trace.tier2_escalation_decision = t2.get("escalation_decision") or ""
    trace.tier2_tools = int(t2.get("tool_calls_made") or 0)
    trace.tier2_wall_ms = int(t2.get("wall_time_ms") or 0)

    ir_plan = produced.get("ir.plan")
    if ir_plan is None:
        return trace
    trace.ir_engaged = True
    trace.ir_severity = ir_plan.get("severity") or ""
    trace.ir_bridge_required = bool(ir_plan.get("bridge_required"))
    trace.ir_containment_count = len(ir_plan.get("containment_actions") or [])
    trace.ir_tools = int(ir_plan.get("tool_calls_made") or 0)
    trace.ir_wall_ms = int(ir_plan.get("wall_time_ms") or 0)

    ti_report = produced.get("threat_intel.report")
    if ti_report is None:
        return trace
    trace.ti_engaged = True
    trace.ti_actor = ti_report.get("likely_actor") or ""
    trace.ti_sev_adjustment = ti_report.get("severity_adjustment") or ""
    trace.ti_tools = int(ti_report.get("tool_calls_made") or 0)
    trace.ti_wall_ms = int(ti_report.get("wall_time_ms") or 0)

    return trace


# ---- Reporting ----------------------------------------------------------

def _save_verdicts(traces: list[TicketTrace]) -> None:
    """Persist each stage's verdict to verdicts.sqlite with role=*_backtest."""
    for t in traces:
        if t.sentinel_verdict:
            verdict_store.save_verdict(
                ticket_id=t.ticket_id, correlation_id=t.ticket_id,
                role="sentinel_backtest", verdict=t.sentinel_verdict,
                confidence=0.0,
                reason=(f"priority={t.sentinel_priority} "
                        f"rule={t.rule_name[:60]}"),
                wall_time_ms=t.sentinel_wall_ms,
                ground_truth=t.ground_truth, shadow_mode=False,
            )
        if t.tier2_engaged:
            verdict_store.save_verdict(
                ticket_id=t.ticket_id, correlation_id=t.ticket_id,
                role="tier2_backtest",
                verdict=t.tier2_escalation_decision or t.tier2_refined_verdict,
                confidence=0.0, reason=t.tier2_refined_verdict,
                tool_calls_made=t.tier2_tools, wall_time_ms=t.tier2_wall_ms,
                ground_truth=t.ground_truth, shadow_mode=False,
            )
        if t.ir_engaged:
            verdict_store.save_verdict(
                ticket_id=t.ticket_id, correlation_id=t.ticket_id,
                role="ir_lead_backtest", verdict=t.ir_severity,
                confidence=0.0,
                reason=f"bridge={t.ir_bridge_required} containment={t.ir_containment_count}",
                tool_calls_made=t.ir_tools, wall_time_ms=t.ir_wall_ms,
                ground_truth=t.ground_truth, shadow_mode=False,
            )
        if t.ti_engaged:
            verdict_store.save_verdict(
                ticket_id=t.ticket_id, correlation_id=t.ticket_id,
                role="threat_intel_backtest",
                verdict=t.ti_actor or "no_attribution", confidence=0.0,
                reason=f"sev_adjustment={t.ti_sev_adjustment}",
                tool_calls_made=t.ti_tools, wall_time_ms=t.ti_wall_ms,
                ground_truth=t.ground_truth, shadow_mode=False,
            )


def _aggregate(traces: list[TicketTrace]) -> dict[str, Any]:
    """Roll up per-ticket traces into a JSON-serializable summary."""
    n = len(traces)
    with_truth = [t for t in traces if t.ground_truth in ("escalate", "close")]
    n_truth = len(with_truth)
    n_truth_escalate = sum(1 for t in with_truth if t.ground_truth == "escalate")
    n_truth_close = sum(1 for t in with_truth if t.ground_truth == "close")

    # System escalation = Tier 2 chose escalate_to_ir_lead
    sys_escalated = [t for t in with_truth
                     if t.tier2_escalation_decision == "escalate_to_ir_lead"]
    tp = sum(1 for t in sys_escalated if t.ground_truth == "escalate")
    fp = sum(1 for t in sys_escalated if t.ground_truth == "close")
    fn = sum(1 for t in with_truth
             if t.ground_truth == "escalate"
             and t.tier2_escalation_decision != "escalate_to_ir_lead")
    tn = sum(1 for t in with_truth
             if t.ground_truth == "close"
             and t.tier2_escalation_decision != "escalate_to_ir_lead")
    precision = (tp / (tp + fp) * 100) if (tp + fp) else None
    recall = (tp / (tp + fn) * 100) if (tp + fn) else None
    accuracy = ((tp + tn) / n_truth * 100) if n_truth else None
    f1 = None
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1 = round(2 * precision * recall / (precision + recall), 1)

    # Per-stage rollups
    sentinel_verdicts = Counter(t.sentinel_verdict for t in traces if t.sentinel_verdict)
    tier2_decisions = Counter(t.tier2_escalation_decision
                              for t in traces if t.tier2_engaged)
    ir_sev_dist = Counter(t.ir_severity for t in traces if t.ir_engaged)
    ti_with_actor = sum(1 for t in traces if t.ti_engaged and t.ti_actor)
    ti_total = sum(1 for t in traces if t.ti_engaged)
    ti_sev_adj = Counter(t.ti_sev_adjustment
                         for t in traces if t.ti_engaged and t.ti_sev_adjustment)

    avg_wall_ms = {
        "tier2": _avg([t.tier2_wall_ms for t in traces if t.tier2_engaged]),
        "ir_lead": _avg([t.ir_wall_ms for t in traces if t.ir_engaged]),
        "threat_intel": _avg([t.ti_wall_ms for t in traces if t.ti_engaged]),
    }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ticket_count": n,
        "tickets_with_truth": n_truth,
        "truth_escalated": n_truth_escalate,
        "truth_closed": n_truth_close,
        "sentinel_verdicts": dict(sentinel_verdicts),
        "tier2_engagement": sum(1 for t in traces if t.tier2_engaged),
        "tier2_decisions": dict(tier2_decisions),
        "ir_engagement": sum(1 for t in traces if t.ir_engaged),
        "ir_severity_mix": dict(ir_sev_dist),
        "ti_engagement": ti_total,
        "ti_with_actor": ti_with_actor,
        "ti_sev_adjustments": dict(ti_sev_adj),
        "avg_wall_ms": avg_wall_ms,
        "escalation_confusion": {
            "true_positive": tp, "false_positive": fp,
            "true_negative": tn, "false_negative": fn,
            "precision_pct": round(precision, 1) if precision is not None else None,
            "recall_pct": round(recall, 1) if recall is not None else None,
            "accuracy_pct": round(accuracy, 1) if accuracy is not None else None,
            "f1": f1,
        },
        "errors": [
            {"ticket_id": t.ticket_id, "errors": t.errors}
            for t in traces if t.errors
        ],
    }


def _avg(xs: list[Optional[int]]) -> Optional[int]:
    xs = [int(x) for x in xs if x is not None]
    return int(sum(xs) / len(xs)) if xs else None


def _print_report(summary: dict[str, Any]) -> None:
    n = summary["ticket_count"]
    print()
    print("=" * 60)
    print(f"  SOC-in-a-Box backtest — {n} tickets")
    print("=" * 60)
    print(f"  Generated:        {summary['generated_at']}")
    print(f"  Ground truth:     {summary['tickets_with_truth']} usable "
          f"({summary['truth_escalated']} escalated / "
          f"{summary['truth_closed']} closed)")
    print()
    print("--- Sentinel (synthetic if --mode downstream) ---")
    for v, c in summary["sentinel_verdicts"].items():
        print(f"    {v:35s} {c:>4d}")
    print()
    print("--- Tier 2 ---")
    print(f"    Engaged:          {summary['tier2_engagement']}/{n}")
    for v, c in summary["tier2_decisions"].items():
        print(f"    {v:35s} {c:>4d}")
    if summary['avg_wall_ms']['tier2'] is not None:
        print(f"    Avg wall:         {summary['avg_wall_ms']['tier2']} ms")
    print()
    print("--- IR Lead ---")
    print(f"    Engaged:          {summary['ir_engagement']}/{n}")
    for v, c in summary["ir_severity_mix"].items():
        print(f"    {v:35s} {c:>4d}")
    if summary['avg_wall_ms']['ir_lead'] is not None:
        print(f"    Avg wall:         {summary['avg_wall_ms']['ir_lead']} ms")
    print()
    print("--- Threat Intel ---")
    print(f"    Engaged:          {summary['ti_engagement']}/{n}")
    print(f"    With named actor: {summary['ti_with_actor']}/{summary['ti_engagement']}")
    for v, c in summary["ti_sev_adjustments"].items():
        print(f"    sev_adj={v:30s} {c:>4d}")
    if summary['avg_wall_ms']['threat_intel'] is not None:
        print(f"    Avg wall:         {summary['avg_wall_ms']['threat_intel']} ms")
    print()
    conf = summary["escalation_confusion"]
    print("--- Escalation agreement (Tier 2 → IR Lead vs human) ---")
    print(f"    TP:  {conf['true_positive']:>4d}   FN:  {conf['false_negative']:>4d}")
    print(f"    FP:  {conf['false_positive']:>4d}   TN:  {conf['true_negative']:>4d}")
    print(f"    Precision: {conf['precision_pct']}%   "
          f"Recall: {conf['recall_pct']}%   "
          f"Accuracy: {conf['accuracy_pct']}%   F1: {conf['f1']}")
    if summary["errors"]:
        print()
        print("--- Errors ---")
        for e in summary["errors"][:10]:
            print(f"    #{e['ticket_id']}: {'; '.join(e['errors'])}")
    print()
    print(f"  Verdicts persisted to: {verdict_store.DB_PATH}")
    print(f"  Summary written to:    {SUMMARY_PATH}")
    print()


# ---- Entry point --------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=20,
                        help="Total ticket sample size (default 20)")
    parser.add_argument("--mode", choices=("downstream", "full"),
                        default="downstream",
                        help=("downstream: fabricate AlertTriaged, run T2 → IR → TI. "
                              "full: also run real Sentinel pipeline (slow)."))
    parser.add_argument("--dry-run", action="store_true",
                        help="Stub LLM calls — fast plumbing smoke test.")
    parser.add_argument("--no-stratify", action="store_true",
                        help="Disable per-severity stratified sampling")
    parser.add_argument("--seed", type=int, default=42, help="Sampling seed")
    parser.add_argument("--no-save-summary", action="store_true",
                        help="Skip writing the dashboard summary JSON")
    parser.add_argument("--verbose", action="store_true",
                        help="DEBUG-level logs")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    rows = _sample_tickets(args.limit, not args.no_stratify, args.seed)
    print(f"Sampled {len(rows)} tickets (mode={args.mode}, dry_run={args.dry_run})")
    if not rows:
        print("No tickets available; check data/xsoar_timeline/xsoar_timeline.db.")
        return 1

    _prepare_backtest_env()
    model = _backtest_model(args.dry_run)

    traces: list[TicketTrace] = []
    t0 = time.time()
    for i, row in enumerate(rows, 1):
        try:
            trace = _run_one(row, args.mode, args.dry_run, model)
            traces.append(trace)
        except Exception as exc:
            logger.exception("backtest: ticket %s failed: %s", row["id"], exc)
            t = TicketTrace(
                ticket_id=str(row["id"]),
                severity=int(row["severity"] or 0),
                rule_name=row["name"] or "",
                hostname=row["hostname"] or "",
                username=row["username"] or "",
                ground_truth=_ground_truth(row),
                errors=[f"runner: {type(exc).__name__}: {exc}"],
            )
            traces.append(t)
        # Brief progress hint for live runs
        if not args.dry_run and i % 5 == 0:
            elapsed = time.time() - t0
            print(f"  {i}/{len(rows)} done ({elapsed:.1f}s elapsed)")

    summary = _aggregate(traces)
    summary["mode"] = args.mode
    summary["dry_run"] = args.dry_run
    summary["wall_seconds"] = round(time.time() - t0, 1)

    _save_verdicts(traces)

    if not args.no_save_summary:
        SUMMARY_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(SUMMARY_PATH, "w") as f:
            json.dump(summary, f, indent=2)

    _print_report(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
