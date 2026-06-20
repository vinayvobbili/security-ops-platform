"""IR-side adapters that plug the local environment into the aisoc kernel.

The agent framework, event contract, bus, and case-memory read models now live
in the standalone ``aisoc`` package (vendor-neutral, no IR imports). This module
is the thin bridge in the other direction: it injects *our* real environment
into aisoc's three seams so the kernel runs against the live SOC.

    from src.components.soc_in_box.aisoc_seams import (
        soc_chat_model, soc_tools, soc_bus,
    )
    from aisoc.agents import TriageAgent

    agent = TriageAgent(bus=soc_bus(), model=soc_chat_model(), tools=soc_tools())
    agent.run()

The three seams:

* **ChatModel** — ``create_llm()`` already returns a LangChain ``BaseChatModel``
  (a local model with automatic failover), which satisfies the seam
  directly. No adapter needed; ``soc_chat_model`` is a passthrough.
* **ToolProvider** — ``SocToolProvider`` maps a role to the live enrichment
  tools it may call, reusing the existing triage tool surface. The few tools
  that were ticket-bound closures in the old pipeline are swapped for their raw
  forms (which take ``ticket_id`` as an argument the model fills from the
  prompt), so one long-lived agent can serve many tickets.
* **Bus** — ``soc_bus`` returns aisoc's ``RedisBus`` over our existing Redis
  client, so the event log is the same durable Redis Streams as before.

This is the adapter layer for the migration; it does not change agent behavior.
Nothing imports it yet — the SIAB entrypoints are cut over to it in a later
step.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from aisoc.bus import Bus, InMemoryBus
from aisoc.redis_bus import RedisBus
from aisoc.seams import ChatModel

logger = logging.getLogger(__name__)


# State continuity: aisoc's sidecar stores (verdicts / hitl / case-memory SQLite)
# live under AISOC_DATA_DIR, which defaults to ``data/aisoc``. The SOC web app
# reads the historical ``data/soc_in_box/`` stores, and the two schemas are
# identical (verdicts + hitl tables match column-for-column), so we point aisoc
# at IR's existing dir — the aisoc agents then write verdicts and propose HITL
# actions into the very files the dashboards already read. Resolved relative to
# this worktree so the dev twin stays data-isolated from prod, and only set when
# the caller hasn't pinned it (the backtest points it at a scratch dir).
_IR_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))),
    "data", "soc_in_box",
)
os.environ.setdefault("AISOC_DATA_DIR", _IR_DATA_DIR)


def notify_suppressed() -> bool:
    """True when agent notify() side-effects (Webex cards) must NOT fire.

    The backtest harness replays real tickets through the agents; it sets
    ``SIAB_BACKTEST=1`` so a validation run doesn't post escalation/plan cards to
    the team's Webex space. Live agents leave the flag unset and notify normally.
    """
    return bool(os.getenv("SIAB_BACKTEST"))


def case_context(bus: Bus, ticket_id: str) -> dict[str, dict[str, Any]]:
    """Latest event of each type for ``ticket_id``, from the bus audit log.

    The per-ticket Webex cards want upstream context the agent's own published
    event doesn't carry (the escalation card wants the triage event; the IR-plan
    card wants the Tier 2 + triage events; the threat-intel card wants the IR
    plan + triage). Every one of those is already an event on the audit stream,
    so we read them back keyed by ``event_type`` (last write wins) rather than
    threading context through the agent chain.
    """
    out: dict[str, dict[str, Any]] = {}
    tid = str(ticket_id)
    try:
        for raw in bus.replay():  # defaults to the audit stream
            if str(raw.get("ticket_id")) == tid:
                out[str(raw.get("event_type"))] = raw
    except Exception as exc:  # context is best-effort; a card degrades, never breaks
        logger.debug("aisoc_seams.case_context: replay failed (%s)", exc)
    return out


# Roles that reason over a case with live tools. The windowed roles
# (detection_eng, soc_manager, threat_hunter, campaign_detector) take no live
# tools — they replay the audit log — so they map to an empty tool set.
_REASONING_ROLES = {"triage", "tier2", "ir_lead", "threat_intel"}

# The four tools that were ticket-bound closures in _build_triage_tools; we
# replace them with their raw forms (which expose ticket_id as a parameter).
_TICKET_BOUND_NAMES = {
    "get_ad_user", "get_ad_computer",
    "get_varonis_user_alerts", "get_varonis_data_activity",
}


def soc_chat_model() -> ChatModel:
    """The LLM seam for the tool-calling reasoning roles (triage, tier2, ir_lead,
    threat_intel) — the failover chat model, used as-is (it's a BaseChatModel).

    These roles bind live enrichment tools, so they run on the local tool-capable
    model (with automatic failover baked into ``create_llm``).
    """
    from my_bot.utils.llm_factory import create_llm
    return create_llm()


def soc_summary_model() -> ChatModel:
    """The LLM seam for the windowed, tool-less roles (detection_eng, soc_manager,
    threat_hunter, campaign_detector).

    These roles never call a tool — they replay the audit log and ask for one
    narrative/recommendation per cluster, so they run on the same local chat
    model as the reasoning roles.
    """
    from my_bot.utils.llm_factory import create_llm
    return create_llm()


def _live_triage_tools() -> list[Any]:
    """The live enrichment tool set, ticket-agnostic.

    Reuses the existing triage tool builder for the stateless majority, then
    swaps the four ticket-bound closures for their raw forms so the same list
    works for any ticket — the model passes ``ticket_id`` (it's in the prompt).
    """
    from src.components.xsoar_alert_triage.xsoar_triage_pipeline import (
        _build_triage_tools,
    )
    from my_bot.tools.active_directory_tools import get_ad_computer, get_ad_user
    from my_bot.tools.varonis_tools import (
        get_varonis_data_activity, get_varonis_user_alerts,
    )

    # _build_triage_tools needs a ticket_id only to bake the four closures we're
    # about to drop; the other ~20 tools ignore it.
    stateless = [
        t for t in _build_triage_tools(ticket_id="")
        if getattr(t, "name", "") not in _TICKET_BOUND_NAMES
    ]
    return stateless + [
        get_ad_user, get_ad_computer,
        get_varonis_user_alerts, get_varonis_data_activity,
    ]


class SocToolProvider:
    """The ToolProvider seam — role → live tools.

    Tools are built once, lazily, and shared across roles (they're stateless or
    take their target as an argument). A real per-role split can tighten this
    later; today every reasoning role gets the full enrichment surface, matching
    how the pipeline behaved before the extraction.
    """

    def __init__(self) -> None:
        self._tools: list[Any] | None = None

    def tools_for(self, role: str) -> list[Any]:
        if role not in _REASONING_ROLES:
            return []
        if self._tools is None:
            self._tools = _live_triage_tools()
            logger.info("aisoc_seams: built %d live tools for reasoning roles",
                        len(self._tools))
        return self._tools


def soc_tools() -> SocToolProvider:
    """The ToolProvider seam, wired to the live enrichment tools."""
    return SocToolProvider()


def soc_bus(*, in_memory: bool = False) -> Bus:
    """The bus seam.

    Returns aisoc's ``RedisBus`` over our existing Redis client by default — the
    same durable Redis Streams event log the SOC already runs on. Pass
    ``in_memory=True`` for a throwaway, zero-infrastructure bus (tests, a dry
    backtest).
    """
    if in_memory:
        return InMemoryBus()
    from src.components.soc_in_box.bus import get_redis_client
    return RedisBus(client=get_redis_client())
