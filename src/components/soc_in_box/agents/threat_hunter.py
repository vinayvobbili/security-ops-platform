"""Threat Hunter agent — proactive pattern detection, wired to the SOC.

The windowed hunting logic (replay the audit window, cluster ``alert.triaged``
events into recurring-host / shared-pivot / potential-miss patterns, ask the
model for a hunt hypothesis + investigation per cluster, publish a
``HuntingReport``) now lives in the vendor-neutral ``aisoc`` package — extracted
from this module. What stays here is the *environment* (the live bus + the
corporate-gateway model, injected through the aisoc seams) plus the IR-specific
Pokedex Webex card.

The Hunter is the proactive complement to the reactive Tier 1/2/IR Lead chain:
it scans recent triage for patterns that may have escaped triage and produces
hunt hypotheses + suggested investigation steps. It hunts what's already on the
bus (no live telemetry queries).

CLI::

    python -m src.components.soc_in_box.agents.threat_hunter \\
        --window-hours 12 [--dry-run] [--no-webex] [--no-llm]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from typing import Any, Optional

from aisoc.agents.threat_hunter import DEFAULT_WINDOW_HOURS
from aisoc.agents.threat_hunter import run_once as _aisoc_run_once

logger = logging.getLogger(__name__)

ROLE_NAME = "threat_hunter"


# -- orchestration -------------------------------------------------------

def run_once(*,
             window_hours: float = DEFAULT_WINDOW_HOURS,
             dry_run: bool = False,
             send_webex: bool = True,
             use_llm: bool = True) -> dict[str, Any]:
    """One hunt sweep over the live bus, with a Pokedex Webex card.

    The cluster/hypothesize/publish is aisoc's ``run_once``, fed our live Redis
    bus and the summary model (these windowed roles call no tools). We then
    render the IR Webex card from the returned findings and send it.
    """
    from src.components.soc_in_box.aisoc_seams import soc_bus, soc_summary_model

    result = _aisoc_run_once(
        bus=soc_bus(),
        model=soc_summary_model() if use_llm else None,
        window_hours=window_hours,
        dry_run=dry_run,
        use_llm=use_llm,
    )

    window_start = datetime.fromisoformat(result["window_start"])
    window_end = datetime.fromisoformat(result["window_end"])
    total = result["hunts_examined"]
    findings = result["findings"]

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

    result["markdown"] = markdown
    result["card"] = card
    result["webex_message_id"] = webex_msg_id
    return result


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
