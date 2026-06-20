"""IR Lead agent — the aisoc IR Lead agent wired to the live SOC.

The IR Lead reasoning (engage on escalation, the structured-response-plan prompt,
the tool loop, the ``IRPlan`` event, the human-gated containment proposal via
``hitl_store`` + ``ActionProposed``, the verdict row) now lives in the
vendor-neutral ``aisoc`` package — extracted from this module. What stays here is
the *environment* (live LLM, live tools, Redis bus, injected through the aisoc
seams) plus the two pieces that are genuinely ours, re-attached through aisoc's
``notify`` publish hook:

- the Pokedex IR-plan Webex card (with Approve/Reject buttons when there's a
  pending HITL containment action), and
- the optional XSOAR ticket note (gated off by default; SOC_WRITE_XSOAR_NOTE=1).

Output per engaged ticket (unchanged):

- ``IRPlan`` event to ``soc.cases`` (always)
- ``ActionProposed`` event + pending HITL action (only when there are
  containment actions to approve)
- Row in ``verdicts.sqlite`` with role=ir_lead
"""

from __future__ import annotations

import logging
import os
from typing import Any

from aisoc.agents.ir_lead import IRLeadAgent as _AisocIRLeadAgent
from aisoc.bus import STREAM_CASES  # noqa: F401  (re-exported for callers)
from aisoc.schemas import IRPlan, parse_event

from src.components.soc_in_box.aisoc_seams import (
    case_context, notify_suppressed, soc_bus, soc_chat_model, soc_tools,
)

logger = logging.getLogger(__name__)

ROLE_NAME = "ir_lead"


class IRLeadAgent(_AisocIRLeadAgent):
    """aisoc's IR Lead agent + IR's Webex plan card and XSOAR note."""

    def __init__(self, bus: Any = None, model: Any = None, tools: Any = "default") -> None:
        super().__init__(
            bus=bus if bus is not None else soc_bus(),
            model=model if model is not None else soc_chat_model(),
            tools=soc_tools() if tools == "default" else tools,
        )

    def notify(self, stream: str, event: Any) -> None:
        """Post the IR-plan card once per case — on the action proposal when there
        is one (so the card carries the HITL action_id + Approve/Reject buttons),
        otherwise on the plan itself."""
        if notify_suppressed():
            return
        etype = getattr(event, "event_type", "")
        if etype == "ir.plan":
            # A containment plan will be followed by an action.proposed; defer the
            # card to that event so it gets the action_id. Post now only when
            # there's nothing to approve.
            if getattr(event, "containment_actions", None):
                return
            self._post_plan_card(str(getattr(event, "ticket_id", "") or ""),
                                 action_id=None)
        elif etype == "action.proposed":
            self._post_plan_card(str(getattr(event, "ticket_id", "") or ""),
                                 action_id=str(getattr(event, "action_id", "") or ""))

    def _post_plan_card(self, ticket_id: str, action_id: str | None) -> None:
        ctx = case_context(self.bus, ticket_id)
        plan_raw = ctx.get("ir.plan")
        if not plan_raw:
            logger.debug("ir_lead: no ir.plan in context for ticket=%s, skip card",
                         ticket_id)
            return
        tier2_ctx = ctx.get("tier2.analysis") or {}
        triage_ctx = ctx.get("alert.triaged") or {}
        approver_role = os.getenv("SOC_HITL_APPROVER_ROLE", "IR Lead On-Call")
        approver_name = os.getenv("SOC_HITL_APPROVER_NAME", "")
        try:
            plan = parse_event(plan_raw)
            if not isinstance(plan, IRPlan):
                return
            from src.components.soc_in_box.agents.ir_lead_webex import send_ir_plan_card
            msg_id = send_ir_plan_card(
                plan, tier2_ctx, triage_ctx,
                hitl_action_id=action_id,
                hitl_approver_role=approver_role if action_id else "",
                hitl_approver_name=approver_name if action_id else "",
            )
            if msg_id:
                logger.info("ir_lead: posted IR plan card msg=%s", str(msg_id)[:20])
        except Exception as exc:
            logger.warning("ir_lead: card send failed: %s", exc)
            return

        # Optional XSOAR ticket note — PAUSED by default (SOC_WRITE_XSOAR_NOTE=1
        # to re-enable). The card above is unaffected.
        if os.getenv("SOC_WRITE_XSOAR_NOTE", "") != "1":
            logger.info("ir_lead: XSOAR note write PAUSED for ticket=%s "
                        "(set SOC_WRITE_XSOAR_NOTE=1 to re-enable)", ticket_id)
            return
        try:
            from src.components.soc_in_box.agents.ir_lead_webex import render_xsoar_note
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
