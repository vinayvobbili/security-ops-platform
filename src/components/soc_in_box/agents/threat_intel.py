"""Threat Intel agent — actor attribution + IOC enrichment on confirmed incidents.

Subscribes to ``soc.cases``. Engages only on ``ir.plan`` events (i.e.
after IR Lead has produced a structured plan — by then the case is
confirmed-real and the responder is staffed-up). The TI agent's job is
to complement the plan with actor attribution, campaign context, and
MITRE ATT&CK technique mapping that the IR responder would otherwise
have to dig up by hand.

Output per engaged ticket:

- ``ThreatIntelReport`` event to ``soc.cases``
- Sleuth Webex card to the dev test space
- Second war-room note on the XSOAR ticket (alongside IR Lead's plan note)

The TI agent runs **after** the IR Lead so its output complements
(doesn't gate) the response plan. Severity adjustment recommendations
are informational — they don't auto-rewrite the IR Lead's call.
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
from src.components.soc_in_box.schemas import ThreatIntelReport
from src.components.soc_in_box.verdict_store import save_verdict

logger = logging.getLogger(__name__)


ROLE_NAME = "threat_intel"
BUDGET = 12  # TI lookups are cheap individually; cap keeps cost predictable

HYDRATE_LOOKBACK = 2000

VALID_SEV_ADJUSTMENTS = ("raise", "lower", "confirm", "none")


SYSTEM_PROMPT = """You are the Threat Intel analyst at the company's SOC. The IR Lead has
already produced a response plan for this incident — your job is to ENRICH that plan
with actor attribution, campaign context, and MITRE ATT&CK technique mapping. You are
NOT making containment decisions; the IR Lead owns those.

Use the read-only enrichment tools available to you to:

- Look up confirmed IOCs (IPs, domains, hashes) in VirusTotal, RecordedFuture,
  abuse.ch, intelx, urlscan, shodan
- Search threat actor / campaign databases (recorded_future_search_actor / get_actor)
- Cross-reference observed TTPs against MITRE ATT&CK techniques
- Pull host/user reputation from CrowdStrike threat-graph if useful

DECISION CRITERIA:

- likely_actor: name a specific actor / group ONLY if multiple data points converge.
  "Lazarus" with one hash match is weak; "Lazarus" with hash + C2 infra + technique
  overlap is strong. Default to "" (empty) when attribution is unclear.
- actor_confidence: 0.0–1.0. High requires at least 2 independent corroborating
  sources.
- campaigns: name specific campaigns/operations if the actor has them tracked.
- mitre_techniques: list MITRE technique IDs observed (e.g. "T1059.001" not "PowerShell").
- severity_adjustment: "raise" only if your TI surfaces info that materially
  increases blast radius (e.g. nation-state actor on financial data); "lower" if
  what looked targeted is actually opportunistic commodity malware; "confirm"
  if your findings line up with the IR Lead's SEV; "none" if no opinion.
- related_historical_incidents: prior ticket IDs that share IOCs or actor.

Output STRICT JSON ONLY (no markdown fence, no prose) with this shape:

{
  "intel_summary": "2-3 sentences of actor + campaign context the IR responder needs",
  "likely_actor": "Actor name or empty string",
  "actor_confidence": 0.0-1.0,
  "actor_evidence": "1-2 sentence justification citing specific lookups",
  "campaigns": ["campaign 1", ...],
  "mitre_techniques": ["T1059.001", "T1071.001", ...],
  "iocs_examined": [{"type": "ip|domain|hash", "value": "...", "reputation": "malicious|suspicious|clean|unknown", "source": "vt|rf|..."}, ...],
  "related_historical_incidents": ["#ticket-id - brief reason", ...],
  "severity_adjustment": "raise" | "lower" | "confirm" | "none",
  "severity_adjustment_reason": "1 sentence if not 'none'",
  "confidence": 0.0-1.0
}

Be terse. Cite specific lookups (VT score, RF risk, etc.) — not generic statements.
"""


# -- helpers --------------------------------------------------------------

def _should_engage(event: dict[str, Any]) -> bool:
    return event.get("event_type") == "ir.plan"


def _hydrate_context(ticket_id: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Return ``(ir_plan_dict, tier2_dict, triage_dict)`` for the ticket.
    Each may be ``{}`` if not found in the lookback window.
    """
    from src.components.soc_in_box.bus import get_redis_client
    client = get_redis_client()
    try:
        events = replay(client, STREAM_AUDIT, start="-", end="+", count=None)
    except Exception as exc:
        logger.warning("threat_intel: audit replay failed: %s", exc)
        return {}, {}, {}
    events = events[-HYDRATE_LOOKBACK:]
    events.reverse()
    ir_plan: dict[str, Any] = {}
    tier2: dict[str, Any] = {}
    triage: dict[str, Any] = {}
    for e in events:
        if str(e.get("ticket_id") or e.get("correlation_id") or "") != ticket_id:
            continue
        et = e.get("event_type") or ""
        if not ir_plan and et == "ir.plan":
            ir_plan = e
        elif not tier2 and et == "tier2.analysis":
            tier2 = e
        elif not triage and et == "alert.triaged":
            triage = e
        if ir_plan and tier2 and triage:
            break
    return ir_plan, tier2, triage


def _build_tools(ticket_id: str) -> list[BaseTool]:
    """Reuse Sentinel's read-only triage tool surface — it already covers the
    TI lookups (VT / RF / abuse.ch / intelx / shodan / CS threat-graph).
    """
    from src.components.xsoar_alert_triage.xsoar_triage_pipeline import _build_triage_tools
    return _build_triage_tools(ticket_id)


def _build_user_prompt(ir_plan: dict[str, Any],
                       tier2: dict[str, Any],
                       triage: dict[str, Any]) -> str:
    ticket_id = ir_plan.get("ticket_id") or tier2.get("ticket_id") or triage.get("ticket_id") or "?"
    sev = ir_plan.get("severity") or "?"
    parts = [
        f"# Incident: Ticket #{ticket_id}",
        f"IR Lead severity: **{sev}**  •  Runbook hint: {ir_plan.get('runbook') or '(none)'}",
        f"Host: {ir_plan.get('hostname') or triage.get('hostname') or '—'}  •  "
        f"User: {ir_plan.get('username') or triage.get('username') or '—'}",
        "",
    ]
    if triage:
        parts += [
            "## Sentinel triage",
            f"- Verdict: {triage.get('verdict', '?')} (confidence {float(triage.get('confidence') or 0):.2f})",
            f"- Summary: {triage.get('summary') or '(none)'}",
        ]
        details = triage.get("details") or {}
        rule = details.get("rule_name") or details.get("alert_rule")
        if rule:
            parts.append(f"- Triggering rule: {rule}")
        parts.append("")
    if tier2:
        parts += [
            "## Tier 2 investigation",
            f"- Summary: {tier2.get('tier2_summary') or '(none)'}",
        ]
        similar = tier2.get("similar_incidents") or []
        if similar:
            parts += ["- Similar past incidents:"]
            parts += [f"    - {s}" for s in similar[:5]]
        parts.append("")
    if ir_plan:
        parts += [
            "## IR Lead plan",
            f"- Exec summary: {ir_plan.get('ir_summary') or '(none)'}",
        ]
        containment = ir_plan.get("containment_actions") or []
        if containment:
            parts += ["- Containment actions:"]
            parts += [f"    - {a}" for a in containment[:6]]
        parts.append("")
    parts += [
        "## Your task",
        "Enrich this incident with TI context. Use tools to look up IOCs, search "
        f"actor/campaign databases, and map TTPs to MITRE (budget: {BUDGET} calls). "
        "Then emit the JSON report per the system prompt.",
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
        logger.warning("threat_intel: JSON parse failed: %s", exc)
        return None


def _coerce_str_list(v: Any, cap: int) -> list[str]:
    if not isinstance(v, list):
        return []
    return [str(x).strip() for x in v if str(x).strip()][:cap]


def _coerce_ioc_list(v: Any, cap: int) -> list[dict[str, Any]]:
    if not isinstance(v, list):
        return []
    out: list[dict[str, Any]] = []
    for item in v[:cap]:
        if not isinstance(item, dict):
            continue
        out.append({
            "type": str(item.get("type") or "").strip()[:32],
            "value": str(item.get("value") or "").strip()[:200],
            "reputation": str(item.get("reputation") or "unknown").strip()[:32],
            "source": str(item.get("source") or "").strip()[:32],
        })
    return out


def _coerce_sev_adjustment(v: Any) -> str:
    return v if isinstance(v, str) and v in VALID_SEV_ADJUSTMENTS else "none"


# -- agent ----------------------------------------------------------------

class ThreatIntelAgent(Agent):
    role_name = ROLE_NAME
    budget = BUDGET

    def streams_to_consume(self) -> list[str]:
        return [STREAM_CASES]

    def tool_whitelist(self) -> list[BaseTool]:
        # Built per-event (ticket-id bound), so the base property is bypassed.
        return []

    def handle(self, stream: str, event: dict[str, Any]) -> None:
        if not _should_engage(event):
            return

        ticket_id = str(event.get("ticket_id") or "")
        if not ticket_id:
            logger.warning("threat_intel: dropping ir.plan with empty ticket_id: %s",
                           event.get("event_id"))
            return

        started = time.time()
        logger.info("threat_intel: engaging ticket=%s sev=%s",
                    ticket_id, event.get("severity"))

        ir_plan_ctx, tier2_ctx, triage_ctx = _hydrate_context(ticket_id)
        # Fall back to the event-as-delivered if hydration came up empty for ir.plan
        if not ir_plan_ctx:
            ir_plan_ctx = event

        tools = _build_tools(ticket_id)
        tool_map = {t.name: t for t in tools}
        llm = create_llm().bind_tools(tools)

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=_build_user_prompt(ir_plan_ctx, tier2_ctx, triage_ctx)),
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
            logger.info("threat_intel: no JSON in tool-loop output, requesting explicit report")
            plain_llm = create_llm()
            messages.append(HumanMessage(
                content="Emit ONLY the JSON TI report now. No prose, no fences."
            ))
            resp = plain_llm.invoke(messages)
            final_text = resp.content if hasattr(resp, "content") else str(resp)
            decision = _extract_json(final_text) or {}

        wall_time_ms = int((time.time() - started) * 1000)

        report = ThreatIntelReport(
            correlation_id=ticket_id,
            produced_by=self.role_name,
            ticket_id=ticket_id,
            ir_plan_event_id=str(ir_plan_ctx.get("event_id") or ""),
            intel_summary=str(decision.get("intel_summary") or "")[:2000],
            likely_actor=str(decision.get("likely_actor") or "").strip()[:120],
            actor_confidence=max(0.0, min(1.0,
                float(decision.get("actor_confidence") or 0.0))),
            actor_evidence=str(decision.get("actor_evidence") or "")[:800],
            campaigns=_coerce_str_list(decision.get("campaigns"), 8),
            mitre_techniques=_coerce_str_list(decision.get("mitre_techniques"), 12),
            iocs_examined=_coerce_ioc_list(decision.get("iocs_examined"), 20),
            related_historical_incidents=_coerce_str_list(
                decision.get("related_historical_incidents"), 8),
            severity_adjustment=_coerce_sev_adjustment(decision.get("severity_adjustment")),
            severity_adjustment_reason=str(
                decision.get("severity_adjustment_reason") or "")[:400],
            confidence=max(0.0, min(1.0, float(decision.get("confidence") or 0.0))),
            hostname=ir_plan_ctx.get("hostname") or triage_ctx.get("hostname") or "",
            username=ir_plan_ctx.get("username") or triage_ctx.get("username") or "",
            tool_calls_made=len(tool_trace),
            wall_time_ms=wall_time_ms,
        )
        self.publish(STREAM_CASES, report)
        save_verdict(
            ticket_id=ticket_id, correlation_id=ticket_id, role=self.role_name,
            verdict=report.likely_actor or "no_attribution",
            confidence=report.confidence, reason=report.intel_summary,
            evidence=[t.get("tool") for t in tool_trace if isinstance(t, dict)],
            tool_calls_made=len(tool_trace), wall_time_ms=wall_time_ms,
        )
        logger.info(
            "threat_intel: published threat_intel.report ticket=%s actor=%s "
            "sev_adj=%s tools=%d wall=%dms",
            ticket_id, report.likely_actor or "(none)", report.severity_adjustment,
            len(tool_trace), wall_time_ms,
        )

        # Webex card
        try:
            from src.components.soc_in_box.agents.threat_intel_webex import (
                send_ti_card,
            )
            msg_id = send_ti_card(report, ir_plan_ctx, triage_ctx)
            if msg_id:
                logger.info("threat_intel: posted TI card msg=%s", msg_id[:20])
        except Exception as exc:
            logger.warning("threat_intel: card send failed: %s", exc)

        # XSOAR ticket note
        # PAUSED 2026-05-29: gated off by default. Set SOC_WRITE_XSOAR_NOTE=1
        # to re-enable. Webex card above is unaffected. Mirrors Sentinel
        # triage's XSOAR_TRIAGE_WRITE_NOTE gate.
        if os.getenv("SOC_WRITE_XSOAR_NOTE", "") != "1":
            logger.info("threat_intel: XSOAR note write PAUSED for ticket=%s "
                        "(set SOC_WRITE_XSOAR_NOTE=1 to re-enable)", ticket_id)
        else:
            try:
                from src.components.soc_in_box.agents.threat_intel_webex import (
                    render_xsoar_note,
                )
                from services.xsoar._entries import create_new_entry_in_existing_ticket
                from services.xsoar.ticket_handler import TicketHandler
                handler = TicketHandler()
                create_new_entry_in_existing_ticket(
                    client=handler.client, incident_id=ticket_id,
                    entry_data=render_xsoar_note(report), markdown=True,
                )
                logger.info("threat_intel: wrote TI note to XSOAR ticket=%s", ticket_id)
            except Exception as exc:
                logger.warning("threat_intel: XSOAR note write failed for ticket=%s: %s",
                               ticket_id, exc)


def main() -> int:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    ThreatIntelAgent().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
