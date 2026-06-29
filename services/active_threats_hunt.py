"""Active-Threat Intake — slice 3: telemetry hunt wire.

Takes a threat's extracted IOCs and asks the unified hunt engine "were we
actually hit, and where" — fanning them across QRadar, CrowdStrike, and XSIAM.
This is the first clean caller of ``services.hunt_engine`` (the engine lifted
out of the tipper package); active-threats talks to the neutral contract, not
the tipper-shaped one.

Same execution model as the enrichment slice: a telemetry sweep is slow
(QRadar AQL alone runs to minutes), so the route launches this in a daemon
thread, writes a ``hunt_status='running'`` marker, and the detail page polls
until the HuntResult lands. Persistence is the caller's job — we own the
``hunt_result`` / ``hunt_status`` columns; the engine just returns data.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Any

from services import active_threats_db as db
from services import hunt_engine

logger = logging.getLogger(__name__)

# Active-threats hunts the full default trio; XSIAM is worth the extra latency
# here because adversary reports often carry endpoint indicators.
_SOURCES = ("qradar", "crowdstrike", "xsiam")

_running: set[str] = set()
_running_lock = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _run(uid: str, key: str, label: str, iocs: list[dict]) -> None:
    try:
        result = hunt_engine.hunt(iocs, ref=uid, label=label, sources=_SOURCES)
        blob = result.to_dict()
        blob.setdefault("status", "error" if result.status == "error" else "done")
        db.save_hunt(uid, blob["status"], hunt_result=blob)
    except Exception as e:
        logger.exception("[ActiveThreats] hunt thread crashed for %s", uid)
        db.save_hunt(uid, "error", hunt_result={"status": "error", "error": str(e),
                                                "finished_at": _now_iso()})
    finally:
        with _running_lock:
            _running.discard(uid)


def preflight_plan(key: str) -> dict[str, Any]:
    """Network-free pre-flight: the queries each source *would* run for this
    threat's IOCs, plus a console deep-link per query, so an analyst can review
    the plan or pivot straight into QRadar/Falcon before running a real sweep.

    Synchronous — :func:`hunt_engine.plan` touches no APIs, so unlike
    :func:`start_hunt` there is no thread/poll. Returns ``{ok, plan}`` (or
    ``{ok, plan: None, note}`` when the threat has no IOCs).
    """
    threat = db.get_threat(key)
    if not threat:
        return {"ok": False, "error": "threat not found"}
    iocs = [i for i in (threat.get("iocs") or []) if isinstance(i, dict) and i.get("value")]
    if not iocs:
        return {"ok": True, "plan": None, "note": "No IOCs on this threat to plan."}
    try:
        plan = hunt_engine.plan(iocs, sources=_SOURCES, ref=(threat.get("uid") or key))
        return {"ok": True, "plan": plan}
    except Exception as e:
        logger.exception("[ActiveThreats] preflight plan failed for %s", key)
        return {"ok": False, "error": str(e)}


def start_hunt(key: str) -> dict[str, Any]:
    """Kick off a telemetry hunt in a daemon thread; return immediately.

    If a run is already in flight for this threat, returns the running marker
    rather than launching a second sweep.
    """
    threat = db.get_threat(key)
    if not threat:
        return {"ok": False, "error": "threat not found"}
    uid = threat.get("uid") or key
    iocs = [i for i in (threat.get("iocs") or []) if isinstance(i, dict) and i.get("value")]
    if not iocs:
        blob = {"status": "done", "verdict": "clear", "touched": False, "total_hits": 0,
                "total_iocs_searched": 0, "sources": {}, "hunt_time": _now_iso(),
                "note": "No IOCs on this threat to hunt."}
        db.save_hunt(uid, "done", hunt_result=blob)
        return {"ok": True, "status": "done", "hunt": blob}

    with _running_lock:
        if uid in _running:
            return {"ok": True, "status": "running"}
        _running.add(uid)

    db.save_hunt(uid, "running", hunt_result={"status": "running", "started_at": _now_iso()},
                 hunt_job_id=uid)
    label = (threat.get("title") or threat.get("actor") or "active threat")[:120]
    t = threading.Thread(target=_run, args=(uid, key, label, iocs), daemon=True,
                         name=f"at-hunt-{uid[:24]}")
    t.start()
    return {"ok": True, "status": "running"}
