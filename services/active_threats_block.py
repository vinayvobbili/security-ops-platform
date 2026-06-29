"""Active-Threat Intake — slice 4: containment block wire.

Closes the loop on the active-threat desk: after enrichment says an indicator is
malicious (S2) and the hunt says whether we were touched (S3), this pushes the
bad domains/URLs into containment. It is the *fourth* caller of the existing
shared block kernel ``services.xsoar.url_block.block_url_via_xsoar`` — the same
flow Pokedex (via the MCP tool), the Webex bot card, and domain-monitoring use:
create a CIRT case → acknowledge → fire ``!CIRT_Start_URL_Block`` → audit
note. We add no new block logic; active-threats just becomes another caller.

Scope is domain/URL — the kernel is a URL-block flow (host-only). IPs/hashes are
a different control surface (the corporate proxy blocklist / QRadar reference set / EDR) and
are intentionally out of scope here.

Safety: the kernel's TicketHandler is pinned to the PROD XSOAR tenant, so a call
from a dev instance would push a real production block. The route gates on
``is_production`` and this runner refuses off-prod as defence-in-depth. Like the
enrich/hunt slices, a block runs to tens of seconds (each kernel call sleeps for
XSOAR to settle), so it executes in a daemon thread while the page polls.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Any

from services import active_threats_db as db

logger = logging.getLogger(__name__)

# IOC types this kernel can act on (it strips URLs to host, blocks the domain).
_BLOCKABLE_TYPES = ("domain", "url")

_running: set[str] = set()
_running_lock = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _xsoar_case_url(ticket_id: str) -> str:
    if not ticket_id:
        return ""
    try:
        from my_config import get_config
        base = (get_config().xsoar_prod_ui_base_url or "").rstrip("/")
        return f"{base}/Custom/caseinfoid/{ticket_id}" if base else ""
    except Exception:
        return ""


def blockable_iocs(threat: dict[str, Any]) -> list[dict[str, Any]]:
    """The domain/URL IOCs on a threat, annotated with their S2 verdict.

    Used by the detail page to render the block picker (malicious ones
    pre-selected) and by :func:`start_block` to validate requested targets.
    """
    enr = threat.get("enrichment") if isinstance(threat.get("enrichment"), dict) else {}
    verdict_by_val: dict[str, str] = {}
    for row in (enr.get("iocs") or []):
        if isinstance(row, dict) and row.get("value"):
            verdict_by_val[str(row["value"]).strip().lower()] = row.get("verdict", "unknown")
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for i in (threat.get("iocs") or []):
        if not isinstance(i, dict):
            continue
        typ = (i.get("type") or "").strip().lower()
        val = str(i.get("value") or "").strip()
        if typ not in _BLOCKABLE_TYPES or not val or val.lower() in seen:
            continue
        seen.add(val.lower())
        out.append({
            "value": val, "type": typ,
            "verdict": verdict_by_val.get(val.lower(), "unknown"),
        })
    return out


def _run(uid: str, targets: list[str], owner: str, reason: str) -> None:
    try:
        from services.xsoar.url_block import block_url_via_xsoar

        ticket_id = ""
        blocked: list[dict[str, Any]] = []
        for val in targets:
            res = block_url_via_xsoar(val, reason, owner, xsoar_ticket_id=ticket_id) or {}
            ok = bool(res.get("success"))
            tid = str(res.get("ticket_id") or "")
            if ok and tid and not ticket_id:
                ticket_id = tid  # group every URL into one CIRT case
            blocked.append({"value": val, "success": ok,
                            "ticket_id": tid or ticket_id,
                            "error": res.get("error", "")})

        n_ok = sum(1 for b in blocked if b["success"])
        status = "blocked" if n_ok == len(blocked) else ("partial" if n_ok else "error")
        db.save_block(uid, status, block_result={
            "status": status,
            "blocked": blocked,
            "ticket_id": ticket_id,
            "ticket_url": _xsoar_case_url(ticket_id),
            "owner": owner,
            "count_ok": n_ok,
            "count_total": len(blocked),
            "finished_at": _now_iso(),
        })
    except Exception as e:
        logger.exception("[ActiveThreats] block thread crashed for %s", uid)
        db.save_block(uid, "error", block_result={"status": "error", "error": str(e),
                                                  "finished_at": _now_iso()})
    finally:
        with _running_lock:
            _running.discard(uid)


def start_block(key: str, values: list[str], owner: str = "") -> dict[str, Any]:
    """Block the selected domain/URL IOCs via XSOAR in a daemon thread.

    Refuses off-prod (defence-in-depth — the route gates too) and validates the
    requested values against the threat's blockable IOCs so callers can't push
    arbitrary strings. Returns immediately; the page polls.
    """
    from my_config import get_config
    if not get_config().is_production:
        return {"ok": False, "disabled": True,
                "error": "Blocking is disabled on the dev instance (it would act "
                         "on the production XSOAR tenant)."}

    threat = db.get_threat(key)
    if not threat:
        return {"ok": False, "error": "threat not found"}
    uid = threat.get("uid") or key

    allowed = {b["value"].lower(): b["value"] for b in blockable_iocs(threat)}
    targets = [allowed[v.strip().lower()] for v in (values or [])
               if v and v.strip().lower() in allowed]
    if not targets:
        return {"ok": False, "error": "No blockable domain/URL indicators selected."}

    with _running_lock:
        if uid in _running:
            return {"ok": True, "status": "blocking"}
        _running.add(uid)

    reason = (f"Active-Threat Intake: containment block of "
              f"{threat.get('actor') or threat.get('title') or 'active threat'} "
              f"requested by {owner}")[:300]
    db.save_block(uid, "blocking", block_result={
        "status": "blocking", "started_at": _now_iso(),
        "targets": targets, "owner": owner,
    })
    t = threading.Thread(target=_run, args=(uid, targets, owner, reason), daemon=True,
                         name=f"at-block-{uid[:24]}")
    t.start()
    return {"ok": True, "status": "blocking"}
