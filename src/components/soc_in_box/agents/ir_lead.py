"""IR Lead agent — incident response plan on Tier 2 escalations.

Subscribes to ``soc.cases``. Engages only on ``CaseEscalated`` events
addressed to ``ir_lead`` (Tier 2 is the producer today; future tiers may
also escalate here).

For each escalated ticket the IR Lead:

1. Hydrates context — pulls the matching ``Tier2Analysis`` + the original
   ``AlertTriaged`` from the audit replay so the LLM has Tier 1's verdict,
   Tier 2's refined verdict + summary, host/user, similar incidents, etc.
2. Optionally runs a few last-mile enrichment lookups (e.g. is this a domain
   controller? is the user privileged?) — read-only tools, hard budget 15.
3. Drafts a structured IR plan: severity (SEV-1..SEV-4), containment /
   eradication / recovery actions, stakeholder notifications, bridge yes/no,
   runbook pointer.
4. Publishes an ``IRPlan`` event to ``soc.cases`` (always) and sends a
   Sleuth Webex card to the dev test space.

v1 is **plan-only** — the agent recommends actions but never executes them.
That stays consistent with the project-wide write policy (read-only against
real systems, sidecar verdicts for human approval).
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any, Optional

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import BaseTool

from my_bot.utils.llm_factory import create_llm
from src.components.soc_in_box.agents.base import Agent
from src.components.soc_in_box.bus import (
    STREAM_AUDIT, STREAM_CASES, replay,
)
from src.components.soc_in_box.schemas import (
    ActionProposed, IRPlan, VALID_SEVERITIES,
)
from src.components.soc_in_box.verdict_store import save_verdict
from src.components.soc_in_box import hitl_store

logger = logging.getLogger(__name__)


ROLE_NAME = "ir_lead"
BUDGET = 15  # lighter than Tier 2 — most enrichment already done

HYDRATE_LOOKBACK = 2000  # audit entries to scan for hydration


SYSTEM_PROMPT = """You are the IR Lead at the company. Tier 2 has escalated a confirmed
incident to you. Your job is to produce a STRUCTURED response plan — not more
investigation.

The plan must answer:

- SEV classification (SEV-1 = enterprise-impacting / regulator-notify; SEV-2 = significant
  blast radius or sensitive asset; SEV-3 = contained but real incident; SEV-4 = minor).
- Containment: immediate actions to stop the bleed (e.g. "Isolate host via CrowdStrike
  RTR", "Disable AD account", "Block C2 domain in the corporate proxy").
- Eradication: remove the root cause (e.g. "Run CS hash hunt across fleet", "Pull
  malicious scheduled task", "Reset privileged credentials").
- Recovery: restore safely (e.g. "Reimage workstation", "Re-enable account post-MFA
  re-enroll", "Validate AV definitions").
- Notifications: who to bring in NOW (e.g. "AppSec", "DLP", "Legal", "GRC", "HR if
  insider", "Customer Success if customer impact"). Be specific.
- Bridge: should we convene an incident bridge? true for SEV-1/SEV-2 with active
  blast radius; false for contained SEV-3/SEV-4.
- Runbook: name the relevant runbook if one applies (e.g. "ransomware-precursor",
  "credential-theft", "phishing-with-malware", "data-exfiltration"). Empty string
  if none fits.

DECISION CRITERIA (be strict — your call drives real human work):

- SEV-1: regulated data confirmed exfiltrated, ransomware actively encrypting, AD
  forest compromise, exec/board impact, customer-facing outage from compromise.
- SEV-2: privileged account confirmed compromised, lateral movement to 3+ hosts,
  domain controller touched, sensitive system (SOX/PCI scope) infected.
- SEV-3: single-host confirmed malicious with containment in place; no spread.
- SEV-4: post-hoc indicator with no active threat (e.g. detected and auto-quarantined,
  user reported successfully).

Output STRICT JSON ONLY (no markdown fence, no prose) with this shape:

{
  "severity": "SEV-1" | "SEV-2" | "SEV-3" | "SEV-4",
  "confidence": 0.0-1.0,
  "ir_summary": "2-3 sentence executive summary an exec could skim",
  "containment_actions": ["action 1", "action 2", ...],
  "eradication_actions": ["action 1", ...],
  "recovery_actions": ["action 1", ...],
  "notifications": ["team or role 1", ...],
  "bridge_required": true | false,
  "runbook": "runbook-name or empty string"
}

Be terse. Cite host names, IPs, account names. No filler like "ensure proper
handling" — concrete actions only.
"""


# -- helpers --------------------------------------------------------------

def _should_engage(event: dict[str, Any]) -> bool:
    if event.get("event_type") != "case.escalated":
        return False
    return (event.get("to_role") or "") == "ir_lead"


def _hydrate_context(ticket_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Pull the latest Tier2Analysis + original AlertTriaged for this ticket.

    Returns ``(tier2_analysis_dict, triage_dict)`` — either may be ``{}`` if
    not found within the lookback window.
    """
    from src.components.soc_in_box.bus import get_redis_client
    client = get_redis_client()
    try:
        events = replay(client, STREAM_AUDIT, start="-", end="+", count=None)
    except Exception as exc:
        logger.warning("ir_lead: audit replay failed: %s", exc)
        return {}, {}
    # Recent last → reverse so we hit the freshest first
    events = events[-HYDRATE_LOOKBACK:]
    events.reverse()
    tier2: dict[str, Any] = {}
    triage: dict[str, Any] = {}
    for e in events:
        if str(e.get("ticket_id") or e.get("correlation_id") or "") != ticket_id:
            continue
        et = e.get("event_type") or ""
        if not tier2 and et == "tier2.analysis":
            tier2 = e
        elif not triage and et == "alert.triaged":
            triage = e
        if tier2 and triage:
            break
    return tier2, triage


def _build_tools(ticket_id: str) -> list[BaseTool]:
    """Reuse Sentinel's read-only triage tool surface."""
    from src.components.xsoar_alert_triage.xsoar_triage_pipeline import _build_triage_tools
    return _build_triage_tools(ticket_id)


def _build_user_prompt(escalation: dict[str, Any],
                       tier2: dict[str, Any],
                       triage: dict[str, Any]) -> str:
    ticket_id = escalation.get("ticket_id", "?")
    parts: list[str] = [
        f"# Incident: Ticket #{ticket_id}",
        f"Escalated by: {escalation.get('from_role', '?')}",
        f"Escalation reason: {escalation.get('reason') or '(none)'}",
        "",
    ]
    if triage:
        parts += [
            "## Sentinel (Tier 1) triage",
            f"- Verdict: **{triage.get('verdict', '?')}** "
            f"(confidence {float(triage.get('confidence') or 0):.2f})",
            f"- Priority: {triage.get('priority_score', 0)}/10",
            f"- Host: {triage.get('hostname') or '—'}",
            f"- User: {triage.get('username') or '—'}",
            f"- Severity: {triage.get('severity') or '—'}",
            f"- Summary: {triage.get('summary') or '(none)'}",
            f"- Sentinel recommended action: {triage.get('recommended_action') or '(none)'}",
            "",
        ]
    if tier2:
        parts += [
            "## Tier 2 investigation",
            f"- Refined verdict: **{tier2.get('refined_verdict', '?')}** "
            f"(confidence {float(tier2.get('confidence') or 0):.2f})",
            f"- Tier 2 summary: {tier2.get('tier2_summary') or '(none)'}",
        ]
        similar = tier2.get("similar_incidents") or []
        if similar:
            parts += ["- Similar past incidents:"]
            parts += [f"    - {s}" for s in similar[:5]]
        next_steps = tier2.get("next_steps") or []
        if next_steps:
            parts += ["- Tier 2's recommended next steps:"]
            parts += [f"    - {s}" for s in next_steps[:6]]
        parts.append("")
    parts += [
        "## Your task",
        "Draft the IR plan. Use tools if you need ONE more piece of context "
        f"(budget: {BUDGET} calls). Then emit the JSON decision block per "
        "the system prompt.",
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
        logger.warning("ir_lead: JSON parse failed: %s", exc)
        return None


def _coerce_severity(v: Any) -> str:
    return v if isinstance(v, str) and v in VALID_SEVERITIES else "SEV-3"


def _coerce_str_list(v: Any, cap: int) -> list[str]:
    if not isinstance(v, list):
        return []
    return [str(x).strip() for x in v if str(x).strip()][:cap]


# -- agent ----------------------------------------------------------------

class IRLeadAgent(Agent):
    role_name = ROLE_NAME
    budget = BUDGET

    def streams_to_consume(self) -> list[str]:
        return [STREAM_CASES]

    def tool_whitelist(self) -> list[BaseTool]:
        # Built per-event (ticket-id bound), so the base property is bypassed.
        return []

    def handle(self, stream: str, event: dict[str, Any]) -> None:
        if not _should_engage(event):
            logger.debug("ir_lead: skip event_id=%s type=%s to_role=%s",
                         event.get("event_id"), event.get("event_type"),
                         event.get("to_role"))
            return

        ticket_id = str(event.get("ticket_id") or "")
        if not ticket_id:
            logger.warning("ir_lead: dropping escalation with empty ticket_id: %s",
                           event.get("event_id"))
            return

        started = time.time()
        logger.info("ir_lead: engaging ticket=%s from=%s",
                    ticket_id, event.get("from_role"))

        tier2_ctx, triage_ctx = _hydrate_context(ticket_id)
        if not tier2_ctx:
            logger.warning("ir_lead: no tier2.analysis hydrated for ticket=%s — "
                           "plan will rely on escalation reason only", ticket_id)

        tools = _build_tools(ticket_id)
        tool_map = {t.name: t for t in tools}
        llm = create_llm().bind_tools(tools)

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=_build_user_prompt(event, tier2_ctx, triage_ctx)),
        ]

        from src.components.xsoar_alert_triage.xsoar_triage_pipeline import (
            _run_triage_tool_loop,
        )
        messages, tool_trace = _run_triage_tool_loop(
            llm, messages, tool_map, max_iterations=self.budget,
        )

        final_text = ""
        last = messages[-1] if messages else None
        if last is not None and hasattr(last, "content") and last.content:
            final_text = last.content if isinstance(last.content, str) else str(last.content)

        decision = _extract_json(final_text)
        if decision is None:
            logger.info("ir_lead: no JSON in tool-loop output, requesting explicit plan")
            plain_llm = create_llm()
            messages.append(HumanMessage(
                content="Emit ONLY the JSON IR plan block now. No prose, no fences."
            ))
            resp = plain_llm.invoke(messages)
            final_text = resp.content if hasattr(resp, "content") else str(resp)
            decision = _extract_json(final_text) or {}

        severity = _coerce_severity(decision.get("severity"))
        confidence = max(0.0, min(1.0, float(decision.get("confidence") or 0.0)))
        ir_summary = str(decision.get("ir_summary") or "")[:2000]
        containment = _coerce_str_list(decision.get("containment_actions"), 10)
        eradication = _coerce_str_list(decision.get("eradication_actions"), 10)
        recovery = _coerce_str_list(decision.get("recovery_actions"), 10)
        notifications = _coerce_str_list(decision.get("notifications"), 10)
        runbook = str(decision.get("runbook") or "").strip()[:80]
        bridge_required = bool(decision.get("bridge_required"))

        wall_time_ms = int((time.time() - started) * 1000)

        plan = IRPlan(
            correlation_id=ticket_id,
            produced_by=self.role_name,
            ticket_id=ticket_id,
            escalation_event_id=str(event.get("event_id") or ""),
            tier2_event_id=str(tier2_ctx.get("event_id") or ""),
            severity=severity,
            confidence=confidence,
            ir_summary=ir_summary,
            containment_actions=containment,
            eradication_actions=eradication,
            recovery_actions=recovery,
            notifications=notifications,
            runbook=runbook,
            bridge_required=bridge_required,
            hostname=triage_ctx.get("hostname") or tier2_ctx.get("hostname") or "",
            username=triage_ctx.get("username") or tier2_ctx.get("username") or "",
            priority_score=int(triage_ctx.get("priority_score")
                               or tier2_ctx.get("priority_score") or 0),
            tool_calls_made=len(tool_trace),
            wall_time_ms=wall_time_ms,
        )
        self.publish(STREAM_CASES, plan)

        # --- HITL handoff ---------------------------------------------------
        # If we have any containment actions, propose them as a single HITL
        # action so a human can approve / reject via the Webex card buttons.
        # v1 is dummy: approval is recorded + audited, but no real-system call
        # is made (that's the future executor agent's job).
        action_id: Optional[str] = None
        approver_role = os.getenv("SOC_HITL_APPROVER_ROLE", "IR Lead On-Call")
        approver_name = os.getenv("SOC_HITL_APPROVER_NAME", "")
        if containment:
            try:
                action_id = hitl_store.propose_action(
                    ticket_id=ticket_id,
                    proposed_by=self.role_name,
                    kind="containment_plan",
                    description=ir_summary or "(no summary)",
                    actions_summary=containment,
                    target={"hostname": plan.hostname, "username": plan.username,
                            "severity": plan.severity},
                    plan_event_id=plan.event_id,
                    approver_role=approver_role,
                    approver_name=approver_name,
                )
                proposed = ActionProposed(
                    correlation_id=ticket_id,
                    produced_by=self.role_name,
                    action_id=action_id,
                    ticket_id=ticket_id,
                    proposed_by=self.role_name,
                    kind="containment_plan",
                    description=ir_summary or "(no summary)",
                    actions_summary=containment,
                    target={"hostname": plan.hostname, "username": plan.username,
                            "severity": plan.severity},
                    plan_event_id=plan.event_id,
                    approver_role=approver_role,
                    approver_name=approver_name,
                )
                self.publish(STREAM_CASES, proposed)
                logger.info("ir_lead: proposed HITL action_id=%s ticket=%s",
                            action_id, ticket_id)
            except Exception as exc:
                logger.warning("ir_lead: HITL propose failed for ticket=%s: %s",
                               ticket_id, exc)
                action_id = None

        save_verdict(
            ticket_id=ticket_id,
            correlation_id=ticket_id,
            role=self.role_name,
            verdict=severity,
            confidence=confidence,
            reason=ir_summary,
            evidence=[t.get("tool") for t in tool_trace if isinstance(t, dict)],
            tool_calls_made=len(tool_trace),
            wall_time_ms=wall_time_ms,
        )
        logger.info(
            "ir_lead: published ir.plan ticket=%s sev=%s bridge=%s tools=%d wall=%dms",
            ticket_id, severity, bridge_required, len(tool_trace), wall_time_ms,
        )

        try:
            from src.components.soc_in_box.agents.ir_lead_webex import send_ir_plan_card
            msg_id = send_ir_plan_card(plan, tier2_ctx, triage_ctx,
                                      hitl_action_id=action_id,
                                      hitl_approver_role=approver_role if action_id else "",
                                      hitl_approver_name=approver_name if action_id else "")
            if msg_id:
                logger.info("ir_lead: posted IR plan card msg=%s", msg_id[:20])
        except Exception as exc:
            logger.warning("ir_lead: card send failed: %s", exc)

        # PAUSED 2026-05-29: XSOAR ticket note write is gated off by default.
        # Set SOC_WRITE_XSOAR_NOTE=1 to re-enable. The Webex card above is
        # unaffected. Mirrors Sentinel triage's XSOAR_TRIAGE_WRITE_NOTE gate.
        if os.getenv("SOC_WRITE_XSOAR_NOTE", "") != "1":
            logger.info("ir_lead: XSOAR note write PAUSED for ticket=%s "
                        "(set SOC_WRITE_XSOAR_NOTE=1 to re-enable)", ticket_id)
        else:
            try:
                from src.components.soc_in_box.agents.ir_lead_webex import (
                    render_xsoar_note,
                )
                from services.xsoar._entries import create_new_entry_in_existing_ticket
                from services.xsoar.ticket_handler import TicketHandler
                handler = TicketHandler()
                create_new_entry_in_existing_ticket(
                    client=handler.client,
                    incident_id=ticket_id,
                    entry_data=render_xsoar_note(plan),
                    markdown=True,
                )
                logger.info("ir_lead: wrote IR plan note to XSOAR ticket=%s", ticket_id)
            except Exception as exc:
                logger.warning("ir_lead: XSOAR note write failed for ticket=%s: %s",
                               ticket_id, exc)


def main() -> int:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    IRLeadAgent().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
