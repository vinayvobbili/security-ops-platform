"""Threat Intel agent — the aisoc Threat Intel agent wired to the live SOC.

The Threat Intel reasoning (engage on the IR plan, the attribution prompt, the
tool loop, the ``ThreatIntelReport`` event, the verdict row) now lives in the
vendor-neutral ``aisoc`` package — extracted from this module. What stays here is
the *environment* (live LLM, live tools, Redis bus, injected through the aisoc
seams) plus the two pieces that are genuinely ours, re-attached through aisoc's
``notify`` publish hook: the Pokedex threat-intel Webex card and the optional
XSOAR ticket note (gated off by default; SOC_WRITE_XSOAR_NOTE=1).

Output per engaged ticket (unchanged):

- ``ThreatIntelReport`` event to ``soc.cases``
- Row in ``verdicts.sqlite`` with role=threat_intel
"""

from __future__ import annotations

import logging
import os
from typing import Any

from aisoc.agents.threat_intel import ThreatIntelAgent as _AisocThreatIntelAgent
from aisoc.bus import STREAM_CASES  # noqa: F401  (re-exported for callers)
from aisoc.schemas import ThreatIntelReport, parse_event

from src.components.soc_in_box.aisoc_seams import (
    case_context, notify_suppressed, soc_bus, soc_chat_model, soc_tools,
)

logger = logging.getLogger(__name__)

ROLE_NAME = "threat_intel"


class ThreatIntelAgent(_AisocThreatIntelAgent):
    """aisoc's Threat Intel agent + IR's Webex card and XSOAR note."""

    def __init__(self, bus: Any = None, model: Any = None, tools: Any = "default") -> None:
        super().__init__(
            bus=bus if bus is not None else soc_bus(),
            model=model if model is not None else soc_chat_model(),
            tools=soc_tools() if tools == "default" else tools,
        )

    def notify(self, stream: str, event: Any) -> None:
        """Post the threat-intel card (and optional XSOAR note) on the report."""
        if getattr(event, "event_type", "") != "threat_intel.report":
            return
        if notify_suppressed():
            return
        ticket_id = str(getattr(event, "ticket_id", "") or "")
        ctx = case_context(self.bus, ticket_id)
        ir_plan_ctx = ctx.get("ir.plan") or {}
        triage_ctx = ctx.get("alert.triaged") or {}
        report_raw = ctx.get("threat_intel.report")
        try:
            report = parse_event(report_raw) if report_raw else event
            if not isinstance(report, ThreatIntelReport):
                return
            from src.components.soc_in_box.agents.threat_intel_webex import send_ti_card
            msg_id = send_ti_card(report, ir_plan_ctx, triage_ctx)
            if msg_id:
                logger.info("threat_intel: posted TI card msg=%s", str(msg_id)[:20])
        except Exception as exc:
            logger.warning("threat_intel: card send failed: %s", exc)
            return

        if os.getenv("SOC_WRITE_XSOAR_NOTE", "") != "1":
            logger.info("threat_intel: XSOAR note write PAUSED for ticket=%s "
                        "(set SOC_WRITE_XSOAR_NOTE=1 to re-enable)", ticket_id)
            return
        try:
            from src.components.soc_in_box.agents.threat_intel_webex import render_xsoar_note
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
