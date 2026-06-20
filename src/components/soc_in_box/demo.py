"""SOC-in-a-Box live demo driver.

Fires a realistic synthetic incident end-to-end through the agent chain so
the audience sees each role react in real time:

    Sentinel triage   →  publishes AlertTriaged
    Tier 2 Analyst    →  consumes triage, escalates, publishes Tier2Analysis + CaseEscalated
    IR Lead           →  consumes escalation, publishes IRPlan + ActionProposed, Webex card
                          with HITL approve/reject buttons + XSOAR ticket note
    Threat Intel      →  consumes ir.plan, publishes ThreatIntelReport + Webex card +
                          XSOAR ticket note (actor attribution, MITRE, IOCs)

Usage::

    # Fire the full demo (default: one ticket, 30s pauses for narration)
    python -m src.components.soc_in_box.demo

    # Tighter pacing for a recorded video
    python -m src.components.soc_in_box.demo --pause 10

    # Wipe all demo artifacts (bus events + HITL rows) — ticket prefix 999xxx
    python -m src.components.soc_in_box.demo --cleanup

    # Specific demo scenario
    python -m src.components.soc_in_box.demo --scenario cobalt_strike

The agent services (ir-soc-tier2, ir-soc-ir-lead, ir-soc-threat-intel) must
be running for the chain to cascade. The demo only injects the Sentinel
triage event; the rest is the real agents reacting.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from typing import Any, Optional

from src.components.soc_in_box.bus import (
    STREAM_AUDIT, STREAM_CASES, STREAM_TRIAGE, get_redis_client, publish,
)
from src.components.soc_in_box.schemas import AlertTriaged

logger = logging.getLogger(__name__)


# Tickets starting with 999 are reserved for the demo so cleanup is precise.
DEMO_TICKET_PREFIX = "999"


# -- scenarios -----------------------------------------------------------

def _scenario_cobalt_strike(ticket_id: str) -> AlertTriaged:
    """Exec laptop with active Cobalt Strike beacon. SEV-1 path through IR Lead."""
    return AlertTriaged(
        correlation_id=ticket_id, produced_by="sentinel_triage", ticket_id=ticket_id,
        verdict="true_positive_malicious", confidence=0.91,
        summary=(
            "CrowdStrike detected Cobalt Strike beacon (sha256 a1b2c3d4e5f6...) on "
            "EXEC-LP-CEO-04 with active C2 to 198.51.100.42:443. Process tree shows "
            "powershell.exe → rundll32.exe → unsigned DLL. Beacon callback interval "
            "60s. User is c-suite-asst (executive assistant)."
        ),
        recommended_action=(
            "Isolate EXEC-LP-CEO-04 via CS RTR; reset c-suite-asst credentials; "
            "block 198.51.100.42 at the corporate proxy; hunt sha256 across fleet."
        ),
        priority_score=9, hostname="EXEC-LP-CEO-04", username="c-suite-asst",
        severity="critical",
        details={
            "rule_name": "CrowdStrike — Cobalt Strike Beacon Detected",
            "llm_what_happened": (
                "Confirmed live Cobalt Strike beacon on the CEO's executive "
                "assistant's workstation. Active C2 to known APT infrastructure. "
                "Potential staging for executive credential theft / data "
                "exfiltration. Severity critical, response immediate."
            ),
        },
    )


def _scenario_ransomware_precursor(ticket_id: str) -> AlertTriaged:
    """File-server credential dump suggesting ransomware staging. SEV-2."""
    return AlertTriaged(
        correlation_id=ticket_id, produced_by="sentinel_triage", ticket_id=ticket_id,
        verdict="true_positive_malicious", confidence=0.88,
        summary=(
            "Tanium signal: lsass.exe access from non-system process on FIN-FILE-01. "
            "Mimikatz-like behavior. Source process explorer.exe spawned from "
            "powershell. No malware quarantine — credentials likely dumped."
        ),
        recommended_action=(
            "Isolate FIN-FILE-01; reset all SOX-scope service accounts last used "
            "from this host; check Volume Shadow Copy state (ransomware tell)."
        ),
        priority_score=8, hostname="FIN-FILE-01", username="svc-fileshare",
        severity="high",
        details={
            "rule_name": "Tanium — Credential Dumping Behavior",
            "llm_what_happened": (
                "Credential-theft behavior on a SOX-scope file server. Classic "
                "ransomware-precursor TTP. No payload detonation yet — window "
                "to interrupt is small."
            ),
        },
    )


SCENARIOS = {
    "cobalt_strike": _scenario_cobalt_strike,
    "ransomware_precursor": _scenario_ransomware_precursor,
}


# -- demo driver ---------------------------------------------------------

def _banner(text: str) -> None:
    print(f"\n{'━' * 72}\n  {text}\n{'━' * 72}", flush=True)


def _step(text: str) -> None:
    print(f"\n  →  {text}", flush=True)


def fire(scenario: str = "cobalt_strike", pause_sec: float = 30.0) -> dict[str, Any]:
    """Inject one demo Sentinel triage event and pause so the audience can
    watch the agents react. Returns a small summary dict for logging.

    The pauses let the demo narrator point at the Webex room as each card
    lands. Tighten ``--pause`` for recorded videos.
    """
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario: {scenario!r}; "
                         f"known: {sorted(SCENARIOS)}")

    # Deterministic ticket id per scenario so re-runs are easy to clean up;
    # epoch suffix keeps each run distinguishable in logs.
    ts_suffix = int(time.time()) % 100000
    ticket_id = f"{DEMO_TICKET_PREFIX}{ts_suffix:05d}"

    client = get_redis_client()
    triage = SCENARIOS[scenario](ticket_id)

    _banner(f"SOC-in-a-Box demo — scenario={scenario} ticket=#{ticket_id}")

    _step("[Sentinel] Injecting AlertTriaged onto soc.triage …")
    publish(client, STREAM_TRIAGE, triage)
    print(f"    verdict={triage.verdict}  priority={triage.priority_score}  "
          f"host={triage.hostname}  user={triage.username}")

    _step(f"[Tier 2] Reading from soc.triage, investigating, deciding to escalate "
          f"(watch Webex / soc.cases) — pausing {pause_sec:.0f}s …")
    time.sleep(pause_sec)

    _step(f"[IR Lead] Consuming the escalation, drafting SEV/containment plan, "
          f"sending Sleuth card with HITL Approve/Reject buttons + XSOAR note — "
          f"pausing {pause_sec:.0f}s …")
    time.sleep(pause_sec)

    _step(f"[Threat Intel] Consuming the IR plan, enriching IOCs, attributing actor + "
          f"MITRE techniques, sending its own Webex card + XSOAR note — "
          f"pausing {pause_sec:.0f}s …")
    time.sleep(pause_sec)

    _step("Demo cascade complete. Recommended next-steps for the audience:")
    print("    • Show /soc-timeline — every event the agents emitted")
    print("    • Show the IR Lead Webex card — click ✅ Approve & Execute Containment")
    print("    • Confirm on the Flask page (DEMO MODE banner is the key)")
    print("    • Show /soc-hitl/audit — the human-handoff audit trail")
    print(f"    • Show the XSOAR ticket #{ticket_id} — IR Lead's plan + TI's notes inline")
    print()
    return {"ticket_id": ticket_id, "scenario": scenario}


# -- cleanup -------------------------------------------------------------

def cleanup() -> dict[str, int]:
    """Remove every bus event + HITL row tied to a demo ticket (prefix 999).

    Use after a demo so the next session starts clean. Safe to run anytime —
    only touches the demo ticket namespace.
    """
    client = get_redis_client()
    deleted = {STREAM_TRIAGE: 0, STREAM_CASES: 0, STREAM_AUDIT: 0}
    for stream in (STREAM_TRIAGE, STREAM_CASES, STREAM_AUDIT):
        entries = client.xrange(stream, "-", "+")
        to_del = []
        for mid, fields in entries:
            try:
                e = json.loads(fields.get("payload", "{}"))
                tid = str(e.get("ticket_id") or e.get("correlation_id") or "")
                if tid.startswith(DEMO_TICKET_PREFIX):
                    to_del.append(mid)
            except Exception:
                continue
        if to_del:
            client.xdel(stream, *to_del)
            deleted[stream] = len(to_del)

    # HITL sidecar — wipe rows whose ticket_id starts with the demo prefix.
    try:
        import sqlite3
        from src.components.soc_in_box.hitl_store import DB_PATH, _connect
        if DB_PATH.exists():
            conn = _connect()
            with conn:
                like = f"{DEMO_TICKET_PREFIX}%"
                # Count first for the report
                hitl_actions_n = conn.execute(
                    "SELECT COUNT(*) FROM hitl_actions WHERE ticket_id LIKE ?",
                    (like,),
                ).fetchone()[0]
                hitl_decisions_n = conn.execute(
                    "SELECT COUNT(*) FROM hitl_decisions WHERE ticket_id LIKE ?",
                    (like,),
                ).fetchone()[0]
                conn.execute("DELETE FROM hitl_decisions WHERE ticket_id LIKE ?", (like,))
                conn.execute("DELETE FROM hitl_actions   WHERE ticket_id LIKE ?", (like,))
            conn.close()
            deleted["hitl_actions"] = hitl_actions_n
            deleted["hitl_decisions"] = hitl_decisions_n
    except Exception as exc:
        logger.warning("demo cleanup: HITL cleanup failed: %s", exc)
        deleted["hitl_actions"] = -1
        deleted["hitl_decisions"] = -1

    # Verdict analytics sidecar — wipe rows whose ticket_id starts with the demo
    # prefix. Sandbox/demo cascades write a verdict per agent (Tier 2 / IR Lead /
    # Threat Intel) here; left behind they pollute the backtest/accuracy numbers.
    try:
        from src.components.soc_in_box.verdict_store import (
            DB_PATH as VERDICT_DB, _connect as _verdict_connect,
        )
        if VERDICT_DB.exists():
            vconn = _verdict_connect()
            with vconn:
                like = f"{DEMO_TICKET_PREFIX}%"
                verdicts_n = vconn.execute(
                    "SELECT COUNT(*) FROM verdicts WHERE ticket_id LIKE ?", (like,),
                ).fetchone()[0]
                vconn.execute("DELETE FROM verdicts WHERE ticket_id LIKE ?", (like,))
            vconn.close()
            deleted["verdicts"] = verdicts_n
    except Exception as exc:
        logger.warning("demo cleanup: verdict_store cleanup failed: %s", exc)
        deleted["verdicts"] = -1

    _banner(f"Demo cleanup complete — removed: {deleted}")
    return deleted


# -- CLI -----------------------------------------------------------------

def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="SOC-in-a-Box live demo driver")
    p.add_argument("--scenario", default="cobalt_strike",
                   choices=sorted(SCENARIOS),
                   help="Which demo scenario to fire")
    p.add_argument("--pause", type=float, default=30.0,
                   help="Seconds to pause between cascade steps (lower for video)")
    p.add_argument("--cleanup", action="store_true",
                   help="Wipe demo artifacts (ticket prefix 999) instead of firing")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    logging.basicConfig(
        level="INFO",
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    args = _build_argparser().parse_args(argv)
    if args.cleanup:
        cleanup()
    else:
        fire(scenario=args.scenario, pause_sec=args.pause)
    return 0


if __name__ == "__main__":
    sys.exit(main())
