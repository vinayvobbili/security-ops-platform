"""Tier 2 Analyst agent — the aisoc Tier 2 agent wired to the live SOC.

The Tier 2 reasoning (engage criteria, deeper-investigation prompt, the
bind-tools-and-iterate loop, the confirm/refine/escalate decision, the
``Tier2Analysis`` + ``CaseEscalated`` events, the verdict row) now lives in the
vendor-neutral ``aisoc`` package — it was extracted from this module verbatim.
What stays here is the *environment*: the live LLM, the live enrichment tools,
and the Redis bus, injected through the three aisoc seams (see
``aisoc_seams``), plus the one piece that is genuinely ours — the Pokedex Webex
escalation card, re-attached through aisoc's ``notify`` publish hook.

Output per engaged ticket (unchanged):

- ``Tier2Analysis`` event to ``soc.cases`` (always)
- ``CaseEscalated`` event to ``soc.cases`` + Pokedex Webex card (only when
  escalation_decision == "escalate_to_ir_lead")
- Row in ``verdicts.sqlite`` with role=tier2
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from aisoc.agents.tier2 import Tier2Agent as _AisocTier2Agent
from aisoc.bus import STREAM_CASES, STREAM_TRIAGE  # noqa: F401  (re-exported for callers)
from aisoc.schemas import Tier2Analysis, parse_event

from src.components.soc_in_box.aisoc_seams import (
    case_context, notify_suppressed, soc_bus, soc_chat_model, soc_tools,
)

logger = logging.getLogger(__name__)

ROLE_NAME = "tier2"


class Tier2Agent(_AisocTier2Agent):
    """aisoc's Tier 2 agent + IR's Pokedex escalation card.

    Constructed with no arguments it builds the live seams (failover LLM, live
    enrichment tools, Redis bus); the backtest harness passes its own
    ``bus``/``model``/``tools`` to run the very same logic offline.
    """

    def __init__(self, bus: Any = None, model: Any = None, tools: Any = "default") -> None:
        super().__init__(
            bus=bus if bus is not None else soc_bus(),
            model=model if model is not None else soc_chat_model(),
            tools=soc_tools() if tools == "default" else tools,
        )

    def notify(self, stream: str, event: Any) -> None:
        """Post the Pokedex escalation card when Tier 2 hands a case to the IR Lead."""
        if getattr(event, "event_type", "") != "case.escalated":
            return
        if notify_suppressed():
            return
        ticket_id = str(getattr(event, "ticket_id", "") or "")
        ctx = case_context(self.bus, ticket_id)
        analysis_raw = ctx.get("tier2.analysis")
        triage_event = ctx.get("alert.triaged") or {}
        if not analysis_raw:
            logger.debug("tier2: no tier2.analysis in context for ticket=%s, skip card",
                         ticket_id)
            return
        try:
            analysis = parse_event(analysis_raw)
            if not isinstance(analysis, Tier2Analysis):
                return
            from src.components.soc_in_box.agents.tier2_webex import send_escalation_card
            msg_id = send_escalation_card(analysis, triage_event)
            if msg_id:
                logger.info("tier2: posted escalation card msg=%s", str(msg_id)[:20])
        except Exception as exc:
            logger.warning("tier2: escalation card send failed: %s", exc)


def main() -> int:
    import os
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    Tier2Agent().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
