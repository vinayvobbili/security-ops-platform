"""SOC-in-a-Box sandbox — let a human paste a raw log or email and run it
through the *real* Sentinel triage pipeline, then watch the multi-agent
cascade react on /soc-timeline.

This is the "give it something to analyze" surface for stakeholders. Unlike
``demo.py`` (which injects a pre-baked ``AlertTriaged`` straight onto the
bus, skipping triage), the sandbox feeds a synthetic ticket into
``XsoarTriagePipeline.triage_ticket`` so the Tier-1 LLM actually analyzes the
input — IOCs in the pasted text get real VirusTotal / AbuseIPDB lookups — and
the verdict it produces auto-publishes to ``soc.triage``, cascading through
Tier 2 → IR Lead → Threat Intel exactly as a production alert would.

Isolation: sandbox tickets reuse the demo ``999`` id namespace, so:
  - ``demo.cleanup()`` wipes them (one cleanup button covers demo + sandbox),
  - the agent Webex cards stamp a SANDBOX banner (see ``is_sandbox_ticket``),
  - ``_write_triage_to_xsoar`` skips the XSOAR write-back (no real ticket).
The Sentinel triage card is suppressed by running the pipeline with
``webex_api=None``; the cascade cards (Tier 2 / IR Lead / Threat Intel) still
post to the SOC room, banner-stamped.
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


# Shared with demo.DEMO_TICKET_PREFIX so demo.cleanup() covers sandbox runs.
SANDBOX_TICKET_PREFIX = "999"

SANDBOX_BANNER_TEXT = (
    "🧪 SANDBOX — synthetic test input, not a real incident. "
    "No production ticket; actions are advisory only."
)


def is_sandbox_ticket(ticket_id: Any) -> bool:
    """True for demo/sandbox tickets (the reserved ``999`` id namespace)."""
    return str(ticket_id or "").startswith(SANDBOX_TICKET_PREFIX)


def sandbox_banner_card_block() -> dict[str, Any]:
    """An Adaptive Card container to prepend to a cascade card's body."""
    return {
        "type": "Container", "style": "warning", "bleed": True,
        "items": [
            {"type": "TextBlock", "text": SANDBOX_BANNER_TEXT,
             "weight": "Bolder", "wrap": True, "color": "Warning"},
        ],
    }


def sandbox_banner_md() -> str:
    """A markdown banner line to prepend to a cascade card's fallback text."""
    return f"> {SANDBOX_BANNER_TEXT}\n"


# -- input → synthetic ticket -------------------------------------------

# Input kinds the form offers. Maps to XSOAR ticket type + security category
# so the triage prompt picks the right reasoning lane.
KIND_MAP = {
    "phishing":   ("Phishing",           "Phishing"),
    "malware":    ("Malware",            "Malware"),
    "suspicious": ("Suspicious Activity", "Suspicious Activity"),
    "other":      ("Security Alert",      "Other"),
}

# Heuristics for auto-detecting a pasted email so the user can just paste.
_EMAIL_HINT_RE = re.compile(
    r"^(from|to|subject|received|return-path|reply-to|message-id|dkim-signature)\s*:",
    re.IGNORECASE | re.MULTILINE,
)


def _detect_kind(text: str) -> str:
    """Best-effort: an email-looking paste → phishing, else generic."""
    if _EMAIL_HINT_RE.search(text or ""):
        return "phishing"
    return "other"


def _new_sandbox_ticket_id() -> str:
    """A ``999``-prefixed id, epoch-suffixed so runs are distinguishable."""
    return f"{SANDBOX_TICKET_PREFIX}{int(time.time()) % 1000000:06d}"


def build_sandbox_ticket(
    text: str,
    kind: str = "auto",
    hostname: str = "",
    username: str = "",
    name: str = "",
) -> dict[str, Any]:
    """Wrap pasted text into the raw XSOAR ticket dict ``triage_ticket`` expects.

    The pasted content lands in ``details`` — the freeform narrative the triage
    LLM reads and the IOC extractor scans. Optional host/user feed the
    entity-keyed enrichments (AD / Vectra / SNOW / QRadar activity); when blank,
    those enrichments simply no-op and the LLM is told to lower confidence on
    description-only evidence.
    """
    if kind == "auto":
        kind = _detect_kind(text)
    ticket_type, security_category = KIND_MAP.get(kind, KIND_MAP["other"])

    ticket_id = _new_sandbox_ticket_id()
    default_name = {
        "phishing": "[SANDBOX] Reported phishing email",
        "malware": "[SANDBOX] Suspected malware activity",
        "suspicious": "[SANDBOX] Suspicious activity report",
        "other": "[SANDBOX] Analyst-submitted alert",
    }.get(kind, "[SANDBOX] Analyst-submitted alert")

    return {
        "id": ticket_id,
        "investigationId": ticket_id,
        "name": (name.strip() or default_name),
        "type": ticket_type,
        # Medium by default — the LLM derives its own verdict regardless.
        "severity": 2,
        "status": 1,
        "owner": "soc-sandbox",
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "details": text or "",
        "CustomFields": {
            "securitycategory": security_category,
            "detectionsource": "SOC Sandbox",
            "affectedhostname": hostname.strip(),
            "affectedusername": username.strip(),
        },
    }


def run_triage(ticket: dict[str, Any]) -> dict[str, Any]:
    """Run a prebuilt sandbox ticket through the real Sentinel triage pipeline.

    Blocking — the pipeline runs enrichment + LLM triage (~30-90s) and then
    auto-publishes its verdict to the bus, cascading to the downstream agents.

    Returns a small summary dict (ticket_id, kind, verdict) for logging.
    """
    # Lazy import — keeps this module light and avoids dragging the heavy
    # triage pipeline (and its transitive deps) into Webex card modules that
    # only need is_sandbox_ticket / the banner helpers.
    from src.components.xsoar_alert_triage.xsoar_triage_pipeline import (
        XsoarTriagePipeline,
    )

    ticket_id = ticket["id"]
    logger.info("[SOC sandbox] triaging synthetic ticket %s (type=%s host=%s user=%s)",
                ticket_id, ticket.get("type"),
                ticket.get("CustomFields", {}).get("affectedhostname") or "—",
                ticket.get("CustomFields", {}).get("affectedusername") or "—")

    # webex_api=None suppresses the Sentinel triage card; the synthetic-ticket
    # guard in _write_triage_to_xsoar suppresses the XSOAR write-back. The
    # verdict still auto-publishes to soc.triage, so the cascade fires.
    pipeline = XsoarTriagePipeline(webex_api=None, room_id="")
    try:
        result = pipeline.triage_ticket(ticket)
    except Exception as exc:
        logger.exception("[SOC sandbox] triage failed for %s: %s", ticket_id, exc)
        return {"ticket_id": ticket_id, "kind": ticket.get("type"), "error": str(exc)}

    verdict = getattr(result, "llm_verdict", "") if result else ""
    logger.info("[SOC sandbox] %s complete — verdict=%s", ticket_id, verdict or "?")
    return {"ticket_id": ticket_id, "kind": ticket.get("type"), "verdict": verdict}


def analyze(
    text: str,
    kind: str = "auto",
    hostname: str = "",
    username: str = "",
    name: str = "",
) -> dict[str, Any]:
    """Build a synthetic ticket from input and triage it synchronously."""
    ticket = build_sandbox_ticket(text, kind=kind, hostname=hostname,
                                  username=username, name=name)
    return run_triage(ticket)


def start_async(
    text: str,
    kind: str = "auto",
    hostname: str = "",
    username: str = "",
    name: str = "",
) -> str:
    """Build the synthetic ticket, kick off triage on a daemon thread, and
    return its ``ticket_id`` immediately so an HTTP handler can redirect the
    user to /soc-timeline?ticket=<id> to watch the cascade land.
    """
    import threading

    ticket = build_sandbox_ticket(text, kind=kind, hostname=hostname,
                                  username=username, name=name)
    ticket_id = ticket["id"]
    threading.Thread(
        target=run_triage, args=(ticket,),
        name=f"soc-sandbox-{ticket_id}", daemon=True,
    ).start()
    logger.info("[SOC sandbox] dispatched async triage for %s", ticket_id)
    return ticket_id
