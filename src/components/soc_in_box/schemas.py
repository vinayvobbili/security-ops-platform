"""Pydantic schemas for SOC-in-a-Box: bus envelope + event types.

Every event published to Redis Streams is serialized via ``model_dump_json()``
on a subclass of :class:`BusEvent`. Consumers re-hydrate by dispatching on
``event_type`` (a Literal on each subclass).

``Verdict`` matches Sentinel's existing vocabulary (`xsoar_alert_triage`) — Sentinel
is the producer of ``AlertTriaged``, so its terms are canonical. Mapping at the
producer boundary keeps downstream roles (Tier 2 / IR Lead / Detection Engineer
/ Threat Intel / SOC Manager) from drifting against the actual triage output.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


# -- helpers --------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return uuid.uuid4().hex


# Verdict vocabulary mirrors Sentinel's `derive_verdict()` outputs. Order is
# rough severity desc.
Verdict = Literal[
    "true_positive_malicious",
    "true_positive_malicious_contained",
    "true_positive_benign",
    "false_positive",
    "close_ticket",
]

VALID_VERDICTS: tuple[str, ...] = (
    "true_positive_malicious",
    "true_positive_malicious_contained",
    "true_positive_benign",
    "false_positive",
    "close_ticket",
)


# -- bus envelope + event types ------------------------------------------

class BusEvent(BaseModel):
    """Base envelope for every Redis Streams event.

    ``correlation_id`` ties events together for a single ticket as it moves
    triage → Tier 2 → IR Lead. Default to the ticket_id at publish time.
    """

    event_id: str = Field(default_factory=_new_id)
    event_type: str
    timestamp: datetime = Field(default_factory=_now)
    correlation_id: str
    produced_by: str  # e.g. "sentinel_triage", "tier2", "ir_lead"

    model_config = {"extra": "allow"}


class AlertReceived(BusEvent):
    """A new ticket landed somewhere upstream of triage.

    Reserved for future use — Sentinel's poller currently feeds straight into
    triage, so the v1 producer is ``AlertTriaged`` from
    :func:`xsoar_triage_pipeline.triage_ticket`.
    """

    event_type: Literal["alert.received"] = "alert.received"
    ticket_id: str
    source: str = "xsoar"
    rule_name: Optional[str] = None
    severity: Optional[str] = None
    payload: dict[str, Any]


class AlertTriaged(BusEvent):
    """Sentinel's triage verdict on a ticket.

    The convenience top-level fields are denormalized so consumers can filter
    + render without unpacking ``details``. The full XsoarTriageResult dict is
    in ``details`` for consumers that need enrichment / similar tickets /
    investigation pivots / etc.
    """

    event_type: Literal["alert.triaged"] = "alert.triaged"
    ticket_id: str

    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = ""
    recommended_action: str = ""
    priority_score: int = 0  # Sentinel's 1-10 composite

    # Common-case denormalization
    hostname: str = ""
    username: str = ""
    severity: str = ""

    # Full XsoarTriageResult fields (dataclasses.asdict, with non-serializable
    # nested dataclasses dropped). Consumers can pull whatever they need.
    details: dict[str, Any] = Field(default_factory=dict)


class CaseEscalated(BusEvent):
    """Handoff from one role to a higher tier (e.g. triage → Tier 2 → IR Lead)."""

    event_type: Literal["case.escalated"] = "case.escalated"
    ticket_id: str
    from_role: str
    to_role: str
    reason: str


class Tier2Analysis(BusEvent):
    """Tier 2 analyst's deeper investigation on a Sentinel-triaged alert.

    Emitted whenever Tier 2 engages with a ticket (filter: TP-malicious /
    TP-contained OR priority>=7). The ``escalation_decision`` drives whether
    a follow-up :class:`CaseEscalated` event is also published.

    ``original_triage_event_id`` ties this back to the Sentinel
    ``AlertTriaged`` that triggered Tier 2 — useful for the timeline UI and
    backtest harness.
    """

    event_type: Literal["tier2.analysis"] = "tier2.analysis"
    ticket_id: str
    original_triage_event_id: str = ""

    # Sentinel's verdict (passthrough) vs Tier 2's refined verdict
    original_verdict: Verdict
    refined_verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)

    escalation_decision: Literal["escalate_to_ir_lead", "close", "needs_human_review"] = "needs_human_review"
    tier2_summary: str = ""
    similar_incidents: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)

    # Optional denormalization for the timeline UI
    hostname: str = ""
    username: str = ""
    priority_score: int = 0

    tool_calls_made: int = 0
    wall_time_ms: int = 0


Severity = Literal["SEV-1", "SEV-2", "SEV-3", "SEV-4"]

VALID_SEVERITIES: tuple[str, ...] = ("SEV-1", "SEV-2", "SEV-3", "SEV-4")


class IRPlan(BusEvent):
    """IR Lead's response plan for a Tier 2-escalated incident.

    Emitted in response to a ``CaseEscalated`` event addressed to ``ir_lead``.
    The plan is **written**, not **executed** — v1 write policy keeps real-system
    actions out of the agent loop. Containment / eradication / recovery lists
    are the "what we would do" recommendations, queued for human approval.
    """

    event_type: Literal["ir.plan"] = "ir.plan"
    ticket_id: str
    escalation_event_id: str = ""
    tier2_event_id: str = ""

    severity: Severity = "SEV-3"
    confidence: float = Field(ge=0.0, le=1.0)

    ir_summary: str = ""
    containment_actions: list[str] = Field(default_factory=list)
    eradication_actions: list[str] = Field(default_factory=list)
    recovery_actions: list[str] = Field(default_factory=list)
    notifications: list[str] = Field(default_factory=list)
    runbook: str = ""
    bridge_required: bool = False

    # Denormalization for the timeline UI / Webex card
    hostname: str = ""
    username: str = ""
    priority_score: int = 0

    tool_calls_made: int = 0
    wall_time_ms: int = 0


class ActionProposed(BusEvent):
    """Agent proposes a real-system action that needs human approval before execution.

    v1 the only producer is IR Lead (containment plans). Every IRPlan with a
    non-empty ``containment_actions`` list publishes one ``ActionProposed``
    addressed to a human approver. v1 actions are NEVER auto-executed —
    even on approval, the decision is logged and a follow-up ``ActionDecision``
    event is published, but no MCP / CrowdStrike / Tanium write happens. This
    is the demo loop for the SOC-in-a-Box → human handoff. A future executor
    agent will consume approved decisions and actually call the write tool.
    """

    event_type: Literal["action.proposed"] = "action.proposed"
    action_id: str
    ticket_id: str
    proposed_by: str
    kind: str  # e.g. "containment_plan", "block_ip", "disable_account"
    description: str
    actions_summary: list[str] = Field(default_factory=list)
    target: dict[str, Any] = Field(default_factory=dict)
    plan_event_id: str = ""
    # Approver routing — surfaces in the Webex card + decide page so the team
    # knows WHO is supposed to act on this. v1 defaults: containment_plan goes
    # to "IR Lead On-Call". Future kinds (detection_tuning, etc.) set their own.
    approver_role: str = ""
    approver_name: str = ""


class ActionDecision(BusEvent):
    """Human decision on a previously-proposed action.

    ``dummy=True`` means the v1 execute path is stubbed — the decision is
    recorded but no real-system call was made. Future HITL v2 with a real
    executor agent flips ``dummy=False``.
    """

    event_type: Literal["action.decision"] = "action.decision"
    action_id: str
    ticket_id: str
    decision: Literal["approved", "rejected"]
    decided_by: str
    decided_at: datetime
    reason: str = ""
    dummy: bool = True


class ThreatIntelReport(BusEvent):
    """Threat Intel agent's enrichment of a confirmed incident.

    Emitted in response to an ``IRPlan`` event. The TI agent runs the
    indicators (IPs, domains, hashes, host/user) through threat-intel
    sources (VirusTotal, RecordedFuture, abuse.ch, intelx, urlscan, MITRE
    ATT&CK) and produces actor attribution + campaign context + MITRE
    technique mapping. The report posts a separate Pokedex Webex card
    AFTER the IR Lead's card and writes a second war-room note to the
    XSOAR ticket so the IR responder has attribution + plan side-by-side.

    ``severity_adjustment`` is the TI agent's view on whether the IR
    Lead's SEV classification should change given attribution context
    (e.g. confirmed APT raises SEV; confirmed commodity malware lowers).
    """

    event_type: Literal["threat_intel.report"] = "threat_intel.report"
    ticket_id: str
    ir_plan_event_id: str = ""

    intel_summary: str = ""
    likely_actor: str = ""
    actor_confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    actor_evidence: str = ""
    campaigns: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    iocs_examined: list[dict[str, Any]] = Field(default_factory=list)
    related_historical_incidents: list[str] = Field(default_factory=list)
    severity_adjustment: Literal["raise", "lower", "confirm", "none"] = "none"
    severity_adjustment_reason: str = ""
    confidence: float = Field(ge=0.0, le=1.0)

    # Denormalization for timeline / card
    hostname: str = ""
    username: str = ""

    tool_calls_made: int = 0
    wall_time_ms: int = 0


class DetectionTuningReport(BusEvent):
    """Detection Engineer's periodic rollup of rule-tuning opportunities.

    Emitted on a timer (default daily). The Detection Engineer replays the
    triage stream over a window, clusters alerts by triggering rule, and
    proposes specific tuning recommendations for rules that are producing
    a lot of false positives (or benign TPs that don't need to alert).

    ``proposals`` is a flat list — each entry has a ``rule_name``,
    counts, top entities (hostnames/users), sample ticket ids, and the
    LLM's recommended change with a ``change_risk`` rating.

    ``correlation_id`` is the window's ISO start so re-publishes for the
    same window are easy to spot in log search.
    """

    event_type: Literal["detection.tuning_report"] = "detection.tuning_report"
    window_start: datetime
    window_end: datetime
    total_alerts_examined: int
    rules_flagged: int
    proposals: list[dict[str, Any]] = Field(default_factory=list)
    webex_message_id: Optional[str] = None


class HuntingReport(BusEvent):
    """Threat Hunter's periodic rollup of proactive hunting findings.

    Emitted on a timer (default every 12h). The Hunter replays the audit
    window, finds patterns the reactive agents may have missed
    (recurring hosts, TP-malicious that didn't escalate, shared external
    pivots across tickets), and produces a structured findings list with
    per-finding hypothesis + suggested investigation steps.

    Findings are advisory — Threat Hunter does not auto-create tickets
    or escalate. The IR Lead / Threat Intel chain remains the official
    response path; the Hunter is an extra pair of eyes on the bus.
    """

    event_type: Literal["hunting.report"] = "hunting.report"
    window_start: datetime
    window_end: datetime
    hunts_examined: int  # total alert.triaged events in the window
    findings: list[dict[str, Any]] = Field(default_factory=list)
    webex_message_id: Optional[str] = None


class ShiftSummary(BusEvent):
    """SOC Manager's periodic readout over a window of triage activity.

    Emitted on a timer (default every 8h). Aggregates ``AlertTriaged`` events
    from the ``soc.audit`` replay window into deterministic stats + an LLM-
    authored narrative. ``correlation_id`` is the window's ISO start so the
    same window can be re-published idempotently without duplicate ids in
    log search.
    """

    event_type: Literal["shift.summary"] = "shift.summary"
    window_start: datetime
    window_end: datetime
    total_alerts: int
    verdict_counts: dict[str, int] = Field(default_factory=dict)
    top_tickets: list[dict[str, Any]] = Field(default_factory=list)
    narrative_markdown: str = ""
    webex_message_id: Optional[str] = None
