"""Threat Hunt Workbench — on-demand, analyst-driven threat hunting.

The tipper pipeline runs the same engine automatically on scheduled threat
intel. This service exposes it as a *hunter-in-the-loop* tool: paste a CTI
report / a set of IOCs+TTPs, and get two answers about YOUR environment, live:

  1. "Were we touched?"  — fan the IOCs out across QRadar / CrowdStrike /
     XSIAM / Abnormal, AND let the in-house LLM author behavioral (TTP) hunt
     queries that are validated and actually executed against the SIEMs.
  2. "Can we detect this?" — map the report's MITRE ATT&CK techniques against
     our live detection-rule catalog and surface the coverage gaps.

A short LLM verdict ties it together with recommended next actions.

Everything here is READ-ONLY telemetry search + detection-catalog lookup. It
never blocks, quarantines, detonates, or writes to any security tool. Long
hunts run in a background worker thread; the page polls for progress. Each run
is persisted with an audit trail (who ran what, when, and what it found) so the
team has a shared, revisitable hunt history.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

_DB = Path(__file__).resolve().parent.parent / "data" / "hunt_workbench.db"

# Live hunts hit corp APIs (QRadar/CS/XSIAM) and the local LLM. Cap how many run
# at once so a burst of submissions can't hammer those backends. Excess jobs sit
# in their worker thread (status=queued) until a slot frees.
_MAX_CONCURRENT = 2
_slots = threading.BoundedSemaphore(_MAX_CONCURRENT)

# The verdict LLM summary is a "nice to have" on top of the deterministic floor.
# create_llm carries a 600s HTTP timeout, so a saturated m1 could otherwise pin a
# job for minutes — bound it tightly and fall back to the floor.
_VERDICT_LLM_TIMEOUT = 75.0

# run_behavioral_hunt defaults to a 1800s (30-min) deadline tuned for the hourly
# scheduler. That's far too long for a hunter watching a page — bound it. Hunts
# that don't fit are surfaced as `skipped_deadline` with their query intact.
_BEHAVIORAL_DEADLINE = 300.0

# Lookback presets surfaced in the UI -> hours.
LOOKBACK_HOURS = {"24h": 24, "7d": 168, "30d": 720}
DEFAULT_LOOKBACK = "7d"

# IOC-hunt tools the UI can toggle (qradar + crowdstrike default on).
IOC_TOOLS = ["qradar", "crowdstrike", "xsiam", "abnormal"]
DEFAULT_IOC_TOOLS = ["qradar", "crowdstrike"]


# ── Persistence ───────────────────────────────────────────────────────────────

def _connect() -> sqlite3.Connection:
    _DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB), timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS hunt_jobs (
                id            TEXT PRIMARY KEY,
                created_at    TEXT NOT NULL,
                completed_at  TEXT,
                actor         TEXT,
                title         TEXT,
                narrative     TEXT,
                options_json  TEXT,
                status        TEXT NOT NULL,   -- queued | running | done | error
                phase         TEXT,
                entities_json TEXT,
                ioc_json      TEXT,
                behavioral_json TEXT,
                coverage_json TEXT,
                verdict_json  TEXT,
                error         TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_hunt_jobs_created ON hunt_jobs(created_at DESC)")
        conn.commit()


def _reconcile_orphans() -> None:
    """On process start, no worker thread is driving previously in-flight jobs.
    Mark any leftover queued/running rows as interrupted so the shared history
    never shows a zombie 'running' hunt after a restart."""
    try:
        with _connect() as conn:
            conn.execute(
                "UPDATE hunt_jobs SET status='error', phase='Interrupted', "
                "error='Interrupted by a server restart — re-run the hunt.', "
                "completed_at=? WHERE status IN ('queued','running')",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),),
            )
            conn.commit()
    except Exception:
        logger.exception("[hunt-wb] orphan reconcile failed")


_init_db()
_reconcile_orphans()


def _update(job_id: str, **cols) -> None:
    """Patch columns on a job row. Dict/list values are JSON-encoded by caller."""
    if not cols:
        return
    sets = ", ".join(f"{k} = ?" for k in cols)
    vals = list(cols.values()) + [job_id]
    try:
        with _connect() as conn:
            conn.execute(f"UPDATE hunt_jobs SET {sets} WHERE id = ?", vals)
            conn.commit()
    except Exception:
        logger.exception("[hunt-wb] failed to update job %s", job_id)


def _row_to_job(row: sqlite3.Row) -> Dict[str, Any]:
    def _j(v):
        if not v:
            return None
        try:
            return json.loads(v)
        except Exception:
            return None

    return {
        "id": row["id"],
        "created_at": row["created_at"],
        "completed_at": row["completed_at"],
        "actor": row["actor"],
        "title": row["title"],
        "narrative": row["narrative"],
        "options": _j(row["options_json"]) or {},
        "status": row["status"],
        "phase": row["phase"],
        "entities": _j(row["entities_json"]),
        "ioc": _j(row["ioc_json"]),
        "behavioral": _j(row["behavioral_json"]),
        "coverage": _j(row["coverage_json"]),
        "verdict": _j(row["verdict_json"]),
        "error": row["error"],
    }


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    try:
        with _connect() as conn:
            row = conn.execute("SELECT * FROM hunt_jobs WHERE id = ?", (job_id,)).fetchone()
        return _row_to_job(row) if row else None
    except Exception:
        logger.exception("[hunt-wb] get_job failed")
        return None


def list_recent(limit: int = 25) -> List[Dict[str, Any]]:
    """Compact recent-jobs list for the history rail (no heavy result blobs)."""
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT id, created_at, actor, title, status, phase, verdict_json, ioc_json "
                "FROM hunt_jobs ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
    except Exception:
        logger.exception("[hunt-wb] list_recent failed")
        return []

    out = []
    for r in rows:
        verdict = {}
        hits = None
        try:
            verdict = json.loads(r["verdict_json"]) if r["verdict_json"] else {}
        except Exception:
            verdict = {}
        try:
            ioc = json.loads(r["ioc_json"]) if r["ioc_json"] else None
            if ioc:
                hits = ioc.get("total_hits")
        except Exception:
            hits = None
        out.append({
            "id": r["id"],
            "created_at": r["created_at"],
            "actor": r["actor"],
            "title": r["title"] or "Untitled hunt",
            "status": r["status"],
            "phase": r["phase"],
            "touched": (verdict or {}).get("touched"),
            "detection": (verdict or {}).get("detection"),
            "total_hits": hits,
        })
    return out


# ── Orchestration ───────────────────────────────────────────────────────────────

def submit(narrative: str, title: str = "", actor: str = "anonymous",
           options: Optional[dict] = None) -> str:
    """Create a hunt job and kick off the background worker. Returns job_id."""
    options = options or {}
    job_id = uuid.uuid4().hex[:16]
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title = (title or "").strip() or _derive_title(narrative)

    with _connect() as conn:
        conn.execute(
            "INSERT INTO hunt_jobs (id, created_at, actor, title, narrative, options_json, status, phase) "
            "VALUES (?, ?, ?, ?, ?, ?, 'queued', 'Queued')",
            (job_id, now, actor, title, narrative, json.dumps(options)),
        )
        conn.commit()

    logger.info("[HUNT-WB] user=%s action=submit job=%s title=%s", actor, job_id, title[:80])

    t = threading.Thread(target=_run_job, args=(job_id, narrative, title, options),
                         name=f"hunt-wb-{job_id}", daemon=True)
    t.start()
    return job_id


def _derive_title(narrative: str) -> str:
    line = (narrative or "").strip().splitlines()[0] if (narrative or "").strip() else ""
    line = line.strip().lstrip("#").strip()
    return (line[:90] or "Untitled hunt")


def _run_job(job_id: str, narrative: str, title: str, options: dict) -> None:
    """Background pipeline: extract -> IOC hunt -> behavioral hunt -> coverage -> verdict."""
    acquired = False
    try:
        # Phase 0: extract entities (fast, deterministic) before waiting for a slot
        _update(job_id, phase="Extracting indicators & TTPs")
        entities, entities_summary = _extract(narrative)
        _update(job_id, entities_json=json.dumps(entities_summary))

        _update(job_id, status="queued", phase="Waiting for a hunt slot")
        _slots.acquire()
        acquired = True
        _update(job_id, status="running")

        ioc_tools = [t for t in (options.get("ioc_tools") or DEFAULT_IOC_TOOLS) if t in IOC_TOOLS] or DEFAULT_IOC_TOOLS
        lookback = options.get("lookback") if options.get("lookback") in LOOKBACK_HOURS else DEFAULT_LOOKBACK
        hours = LOOKBACK_HOURS[lookback]
        do_behavioral = options.get("behavioral", True)

        # Phase 1: IOC fan-out (live) — "were we touched?"
        ioc_summary = None
        if entities is not None:
            _update(job_id, phase=f"Hunting IOCs across {', '.join(t.upper() for t in ioc_tools)}")
            ioc_summary = _ioc_hunt(entities, job_id, title, ioc_tools, hours)
            _update(job_id, ioc_json=json.dumps(ioc_summary))

        # Phase 2: behavioral TTP hunts (LLM-authored, executed live)
        behavioral_summary = None
        if do_behavioral:
            _update(job_id, phase="Authoring & running behavioral TTP hunts")
            behavioral_summary = _behavioral_hunt(job_id, title, narrative, hours)
            _update(job_id, behavioral_json=json.dumps(behavioral_summary))

        # Phase 3: detection-coverage map — "can we detect this?"
        _update(job_id, phase="Mapping detection coverage")
        coverage = _coverage(entities_summary.get("mitre_techniques", []))
        _update(job_id, coverage_json=json.dumps(coverage))

        # Phase 4: synthesize verdict
        _update(job_id, phase="Synthesizing verdict")
        verdict = _verdict(title, narrative, entities_summary, ioc_summary, behavioral_summary, coverage)
        _update(job_id, verdict_json=json.dumps(verdict))

        _update(job_id, status="done", phase="Complete",
                completed_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        logger.info("[HUNT-WB] job=%s done touched=%s detection=%s",
                    job_id, verdict.get("touched"), verdict.get("detection"))
    except Exception as e:
        logger.exception("[hunt-wb] job %s failed", job_id)
        _update(job_id, status="error", phase="Failed",
                error=f"{type(e).__name__}: {e}",
                completed_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    finally:
        if acquired:
            _slots.release()


# ── Pipeline steps ──────────────────────────────────────────────────────────────

def _extract(narrative: str):
    """Run the entity extractor; return (ExtractedEntities, compact summary dict)."""
    try:
        from src.utils.entity_extractor import extract_entities
        ent = extract_entities(narrative or "", include_apt_database=True)
    except Exception:
        logger.exception("[hunt-wb] entity extraction failed")
        return None, {"ips": [], "domains": [], "urls": [], "filenames": [],
                      "hashes": [], "cves": [], "mitre_techniques": [],
                      "malware_families": [], "threat_actors": [], "counts": {}}

    all_hashes = (
        list(ent.hashes.get("md5", []))
        + list(ent.hashes.get("sha1", []))
        + list(ent.hashes.get("sha256", []))
    )
    actors = []
    for a in (ent.threat_actors or []):
        actors.append(a.name if hasattr(a, "name") else str(a))

    summary = {
        "ips": ent.ips,
        "domains": ent.domains,
        "urls": ent.urls,
        "filenames": ent.filenames,
        "hashes": all_hashes,
        "cves": ent.cves,
        "mitre_techniques": ent.mitre_techniques,
        "malware_families": ent.malware_families,
        "threat_actors": actors,
        "counts": {
            "ips": len(ent.ips),
            "domains": len(ent.domains),
            "urls": len(ent.urls),
            "filenames": len(ent.filenames),
            "hashes": len(all_hashes),
            "cves": len(ent.cves),
            "mitre_techniques": len(ent.mitre_techniques),
            "malware_families": len(ent.malware_families),
            "threat_actors": len(actors),
        },
    }
    summary["counts"]["total_iocs"] = (
        summary["counts"]["ips"] + summary["counts"]["domains"]
        + summary["counts"]["urls"] + summary["counts"]["filenames"]
        + summary["counts"]["hashes"]
    )
    return ent, summary


def _ioc_hunt(entities, job_id: str, title: str, tools: List[str], hours: int) -> dict:
    """Fan IOCs out across the selected tools. Never raises — degrades to errors."""
    try:
        from src.components.tipper_analyzer.hunting import hunt_iocs
        result = hunt_iocs(
            entities, tipper_id=job_id, tipper_title=title,
            qradar_hours=hours, crowdstrike_hours=hours, xsiam_hours=hours,
            tools=tools,
        )
        return _compact_ioc(result)
    except Exception as e:
        logger.exception("[hunt-wb] IOC hunt failed")
        return {"total_hits": 0, "total_iocs_searched": 0, "errors": [f"{type(e).__name__}: {e}"],
                "access_issues": [], "tools": {}, "unique_hosts": 0, "unique_sources": []}


def _compact_ioc(r) -> dict:
    """Flatten an IOCHuntResult to a JSON-friendly summary the page can render."""
    def _tool(t):
        if not t:
            return None
        return {
            "tool_name": t.tool_name,
            "total_hits": t.total_hits,
            "ip_hits": (t.ip_hits or [])[:25],
            "domain_hits": (t.domain_hits or [])[:25],
            "url_hits": (t.url_hits or [])[:25],
            "filename_hits": (t.filename_hits or [])[:25],
            "hash_hits": (t.hash_hits or [])[:25],
            "email_hits": (t.email_hits or [])[:25],
            "errors": (t.errors or [])[:5],
            "queries": (t.queries or [])[:10],
        }

    return {
        "total_hits": r.total_hits,
        "total_iocs_searched": r.total_iocs_searched,
        "hunt_time": r.hunt_time,
        "unique_hosts": r.unique_hosts,
        "unique_sources": (r.unique_sources or [])[:20],
        "errors": (r.errors or [])[:10],
        "access_issues": r.access_issues or [],
        "searched": {
            "ips": r.searched_ips, "domains": r.searched_domains,
            "urls": r.searched_urls, "filenames": r.searched_filenames,
            "hashes": r.searched_hashes,
        },
        "tools": {
            "qradar": _tool(r.qradar),
            "crowdstrike": _tool(r.crowdstrike),
            "xsiam": _tool(r.xsiam),
            "abnormal": _tool(r.abnormal),
        },
    }


def _behavioral_hunt(job_id: str, title: str, narrative: str, hours: int) -> dict:
    """LLM-authors TTP hunt queries, validates, and executes them live."""
    try:
        from src.components.tipper_analyzer.hunting import run_behavioral_hunt
        result = run_behavioral_hunt(job_id, title, narrative, hours=hours,
                                     max_runtime_seconds=_BEHAVIORAL_DEADLINE)
        return {
            "queries_generated": result.queries_generated,
            "queries_executed": result.queries_executed,
            "total_hits": result.total_hits,
            "platform": result.platform,
            "llm_model": result.llm_model,
            "search_hours": result.search_hours,
            "errors": (result.errors or [])[:10],
            "hunts": [
                {
                    "title": h.title,
                    "hypothesis": h.hypothesis,
                    "attack_technique": h.attack_technique,
                    "query_type": h.query_type,
                    "query": h.query,
                    "status": h.status,
                    "hit_count": h.hit_count,
                    "hostnames": (h.hostnames or [])[:15],
                    "detail": h.detail,
                }
                for h in (result.hunts or [])
            ],
        }
    except Exception as e:
        logger.exception("[hunt-wb] behavioral hunt failed")
        return {"queries_generated": 0, "queries_executed": 0, "total_hits": 0,
                "platform": "", "llm_model": "", "hunts": [], "errors": [f"{type(e).__name__}: {e}"]}


def _coverage(techniques: List[str]) -> dict:
    """Map the report's MITRE techniques to our detection-rule catalog."""
    techniques = [t.upper() for t in (techniques or [])]
    out = {"techniques": techniques, "covered": [], "gaps": [], "rules": {},
           "catalog_technique_count": 0, "available": True, "note": ""}

    if not techniques:
        out["available"] = False
        out["note"] = "No explicit ATT&CK technique IDs (T####) found in the input — add them to map detection coverage."
        return out

    try:
        from src.components.tipper_analyzer.rules.catalog import RulesCatalog
        catalog = RulesCatalog()
        covered_set = catalog.get_covered_techniques()
        out["catalog_technique_count"] = len(covered_set)
    except Exception as e:
        logger.warning("[hunt-wb] rules catalog unavailable: %s", e)
        out["available"] = False
        out["note"] = "Detection-rule catalog is not available right now."
        return out

    for t in techniques:
        (out["covered"] if t in covered_set else out["gaps"]).append(t)

    if out["covered"]:
        try:
            rules_by_tech = catalog.get_rules_by_technique(out["covered"])
            for tech, rules in rules_by_tech.items():
                out["rules"][tech] = [
                    {"name": r.name, "platform": r.platform,
                     "rule_type": r.rule_type or "rule", "severity": r.severity or ""}
                    for r in rules[:5]
                ]
        except Exception as e:
            logger.warning("[hunt-wb] get_rules_by_technique failed: %s", e)

    return out


# ── Verdict ─────────────────────────────────────────────────────────────────────

def _deterministic_verdict(ioc: Optional[dict], behavioral: Optional[dict], coverage: dict) -> dict:
    """Ground-truth verdict from the numbers — also the fallback if the LLM is down."""
    ioc_hits = (ioc or {}).get("total_hits", 0) or 0
    beh_hits = (behavioral or {}).get("total_hits", 0) or 0
    total_hits = ioc_hits + beh_hits
    access_issues = list((ioc or {}).get("access_issues", []) or [])
    if (behavioral or {}).get("errors"):
        access_issues = access_issues  # behavioral errors noted separately

    if total_hits > 0:
        touched = "yes"
    elif access_issues or (ioc or {}).get("errors"):
        touched = "inconclusive"
    else:
        touched = "no"

    techniques = coverage.get("techniques", [])
    covered = coverage.get("covered", [])
    gaps = coverage.get("gaps", [])
    if not coverage.get("available") or not techniques:
        detection = "unknown"
    elif not gaps:
        detection = "full"
    elif covered:
        detection = "partial"
    else:
        detection = "gap"

    return {
        "touched": touched,
        "detection": detection,
        "total_hits": total_hits,
        "ioc_hits": ioc_hits,
        "behavioral_hits": beh_hits,
        "covered_count": len(covered),
        "gap_count": len(gaps),
        "access_issues": access_issues,
    }


def _verdict(title, narrative, entities, ioc, behavioral, coverage) -> dict:
    base = _deterministic_verdict(ioc, behavioral, coverage)

    # Build a concise, deterministic recommended-actions list as the floor.
    actions: List[str] = []
    if base["touched"] == "yes":
        actions.append("Triage the matched hosts/sources below — confirm scope and contain if validated.")
    elif base["touched"] == "inconclusive":
        actions.append("Re-run once tool access is restored — some sources reported errors (see access notes).")
    else:
        actions.append("No environment matches in the lookback window — consider widening the window or adding IOCs.")
    if base["gap_count"]:
        actions.append(f"Close detection gaps for {base['gap_count']} technique(s): {', '.join(coverage.get('gaps', [])[:8])}.")
    if (behavioral or {}).get("queries_generated"):
        actions.append("Review the LLM-authored TTP hunts below; promote useful ones into standing detections.")

    base["recommended_actions"] = actions
    base["summary"] = ""

    # Ask the in-house LLM for an executive summary + sharpened actions, bounded
    # by a tight timeout. The deterministic floor stays if the LLM is slow/down.
    base["llm_authored"] = False
    facts = {
        "title": title,
        "ioc_hits": base["ioc_hits"],
        "behavioral_hits": base["behavioral_hits"],
        "unique_hosts": (ioc or {}).get("unique_hosts", 0),
        "access_issues": base["access_issues"],
        "techniques": coverage.get("techniques", []),
        "covered": coverage.get("covered", []),
        "gaps": coverage.get("gaps", []),
        "entities": entities.get("counts", {}),
    }
    try:
        from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FTimeout
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="hunt-wb-verdict") as ex:
            resp = ex.submit(_llm_verdict, title, facts).result(timeout=_VERDICT_LLM_TIMEOUT)
        if resp is not None:
            base["touched_summary"] = resp.get("touched_summary") or base["touched_summary"]
            base["detection_summary"] = resp.get("detection_summary") or base["detection_summary"]
            if resp.get("recommended_actions"):
                base["recommended_actions"] = resp["recommended_actions"][:6]
            base["llm_authored"] = True
    except _FTimeout:
        logger.warning("[hunt-wb] verdict LLM exceeded %.0fs — using deterministic floor", _VERDICT_LLM_TIMEOUT)
    except Exception as e:
        logger.warning("[hunt-wb] verdict LLM unavailable, using deterministic floor: %s", e)

    return base


def _llm_verdict(title: str, facts: dict) -> Optional[dict]:
    """Run the verdict LLM call. Returns a plain dict (or None). Called under a
    bounded-timeout executor by ``_verdict`` so a slow model can't pin a job."""
    from pydantic import BaseModel, Field
    from typing import List as _List
    from src.components.tipper_analyzer.llm_init import get_llm_with_temperature
    from my_bot.utils.llm_factory import structured_output

    class _Verdict(BaseModel):
        touched_summary: str = Field(description="2-3 sentences: were we touched? Reference the concrete IOC/behavioral hits (or their absence) and any tool-access caveats. Do NOT invent hits.")
        detection_summary: str = Field(description="2-3 sentences: can we detect this? Reference covered techniques vs gaps. If no ATT&CK IDs were provided, say coverage can't be assessed.")
        recommended_actions: _List[str] = Field(description="3-5 concrete next actions for a SOC analyst/detection engineer, most important first.")

    prompt = (
        "You are a senior threat hunter writing a crisp verdict for a SOC. "
        "Use ONLY these computed facts — never invent matches or coverage.\n\n"
        f"FACTS:\n{json.dumps(facts, indent=2)}\n\n"
        "Write the verdict. Be direct and specific. If hits are zero, say so plainly."
    )
    llm = get_llm_with_temperature(0.2)
    resp = structured_output(llm, _Verdict).invoke(prompt)
    if resp is None:
        return None
    return {
        "touched_summary": resp.touched_summary,
        "detection_summary": resp.detection_summary,
        "recommended_actions": resp.recommended_actions,
    }
