"""Read-only accessors over the CVE-triage results DB for the web view.

The DB (``data/transient/cve_triage_results.db``) is written by
``services.cve_triage`` (batch + fill passes). This module only reads it, so the
``/vulnerability-deep-dive`` page reflects the batch live as rows land.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict, List

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "transient" / "cve_triage_results.db"


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def available() -> bool:
    return DB_PATH.exists()


def summary() -> Dict[str, Any]:
    """Headline counts for the leadership banner."""
    with _conn() as c:
        r = c.execute(
            """SELECT
                 COUNT(*)                                   AS triaged,
                 COALESCE(SUM(remediation_required), 0)     AS rem_required,
                 COALESCE(SUM(impact_count), 0)             AS total_impact,
                 COALESCE(SUM(location='application_dependency'), 0) AS app_dep,
                 COALESCE(SUM(location='base_image_os_package'), 0)  AS base_img,
                 COUNT(DISTINCT component)                  AS components
               FROM triage WHERE error IS NULL"""
        ).fetchone()
        errors = c.execute("SELECT COUNT(*) FROM triage WHERE error IS NOT NULL").fetchone()[0]
    out = dict(r)
    out["errors"] = errors
    return out


def leverage_by_component(limit: int = 80) -> List[Dict[str, Any]]:
    """Components needing remediation, ranked by how many CVEs each one retires.

    ``peak_impact`` is MAX(impact_count) across the component's CVEs — a
    lower-bound proxy for the asset population carrying it (we deliberately do
    NOT sum, which would double-count an asset that has many CVEs of the same
    component). With SQLite's MAX() bare-column rule, the cvss / location /
    recommended_action shown come from that peak-impact CVE.
    """
    with _conn() as c:
        rows = c.execute(
            """SELECT component,
                      COUNT(*)            AS cve_count,
                      MAX(impact_count)   AS peak_impact,
                      cvss, location, recommended_action, confidence
               FROM triage
               WHERE error IS NULL AND remediation_required = 1
                 AND component IS NOT NULL AND TRIM(component) != ''
               GROUP BY component
               ORDER BY cve_count DESC, peak_impact DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def _has_enrichment(c: sqlite3.Connection) -> bool:
    return c.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='enrichment'"
    ).fetchone() is not None


def _has_debate(c: sqlite3.Connection) -> bool:
    return c.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='debate'"
    ).fetchone() is not None


def _has_col(c: sqlite3.Connection, table: str, col: str) -> bool:
    return any(r[1] == col for r in c.execute(f"PRAGMA table_info({table})"))


_NO_PRECOND = {"none noted", "none", "n/a", "unknown", "not applicable", ""}


def _reachability(location, veracode_apps, preconditions) -> str:
    """Synthesize an honest reachability label from what we actually know.

    NOT a true code-path/runtime determination (that needs container
    introspection) — it reports the *evidence level* for whether the vulnerable
    component is reachable in our environment:
      - present-confirmed   : Veracode confirms the vulnerable component is in
                              our app portfolio (it IS here; deeper code-path
                              reachability still unproven).
      - present-conditional : confirmed present AND the CVE has limiting
                              preconditions (config/arch/version-gated).
      - pending-image       : base-image OS package — presence/reachability
                              can't be confirmed without pulling the image.
      - unknown             : no presence signal.
    """
    has_precond = bool(preconditions) and str(preconditions).strip().lower() not in _NO_PRECOND
    if (veracode_apps or 0) > 0:
        return "present-conditional" if has_precond else "present-confirmed"
    if location == "base_image_os_package":
        return "pending-image"
    return "unknown"


def list_rows(limit: int = 500) -> List[Dict[str, Any]]:
    """Per-CVE verdicts, P1-first then highest fleet impact. LEFT JOIN enrichment
    so un-enriched rows still appear (priority NULL, sorted last)."""
    with _conn() as c:
        if _has_enrichment(c):
            # must_act (enrichment) + the adversarial-debate verdict (debate) are
            # both newer than the original schema — select them only when present
            # so the page keeps working against an un-migrated DB.
            must_act_col = "e.must_act" if _has_col(c, "enrichment", "must_act") else "NULL AS must_act"
            if _has_debate(c):
                debate_cols = ("d.verdict_source, d.score_attacker, d.score_skeptic, "
                               "d.reachable_attacker, d.reachable_skeptic")
                debate_join = "LEFT JOIN debate d ON d.cve_id = t.cve_id"
            else:
                debate_cols = ("NULL AS verdict_source, NULL AS score_attacker, "
                               "NULL AS score_skeptic, NULL AS reachable_attacker, "
                               "NULL AS reachable_skeptic")
                debate_join = ""
            rows = c.execute(
                f"""SELECT t.cve_id, t.impact_count, t.component, t.location,
                          t.affected_versions, t.remediation_required,
                          t.recommended_action, t.preconditions, t.confidence,
                          t.cvss, t.veracode_apps, t.rationale,
                          e.epss, e.percentile, e.kev, e.pre_auth,
                          e.priority, e.sla_days, e.attack_layer,
                          {must_act_col}, {debate_cols}
                   FROM triage t LEFT JOIN enrichment e ON e.cve_id = t.cve_id
                   {debate_join}
                   WHERE t.error IS NULL
                   ORDER BY (e.priority IS NULL), e.priority ASC, t.impact_count DESC
                   LIMIT ?""",
                (limit,),
            ).fetchall()
        else:
            rows = c.execute(
                """SELECT cve_id, impact_count, component, location, affected_versions,
                          remediation_required, recommended_action, preconditions,
                          confidence, cvss, veracode_apps, rationale
                   FROM triage WHERE error IS NULL
                   ORDER BY impact_count DESC LIMIT ?""",
                (limit,),
            ).fetchall()
    out = [dict(r) for r in rows]
    for r in out:
        r["reachability"] = _reachability(
            r.get("location"), r.get("veracode_apps"), r.get("preconditions")
        )
    return out


def priority_summary() -> List[Dict[str, Any]]:
    """Counts by composite priority tier (P1..P4), with impact + KEV/pre-auth."""
    with _conn() as c:
        if not _has_enrichment(c):
            return []
        rows = c.execute(
            """SELECT COALESCE(e.priority, 'UNSCORED') AS tier,
                      COUNT(*) AS cve_count,
                      COALESCE(SUM(t.impact_count), 0) AS total_impact,
                      COALESCE(SUM(e.kev), 0) AS kev_count,
                      COALESCE(SUM(e.pre_auth), 0) AS pre_auth_count
               FROM triage t LEFT JOIN enrichment e ON e.cve_id = t.cve_id
               WHERE t.error IS NULL
               GROUP BY tier ORDER BY tier"""
        ).fetchall()
    return [dict(r) for r in rows]


def review_summary() -> Dict[str, Any]:
    """Counts for the adversarial-debate outcome: how many CVEs the two analysts
    split on (``needs_review``) and how many the deterministic MUST-ACT gate
    force-pinned to P1. Zeroes (and ``available=False``) when the debate/must_act
    columns aren't present yet (pre-v2 DB), so the page degrades gracefully."""
    out = {"available": False, "needs_review": 0, "must_act": 0, "auto": 0}
    with _conn() as c:
        if _has_debate(c):
            out["available"] = True
            for src, n in c.execute(
                """SELECT d.verdict_source, COUNT(*)
                   FROM triage t JOIN debate d ON d.cve_id = t.cve_id
                   WHERE t.error IS NULL GROUP BY d.verdict_source"""
            ).fetchall():
                if src == "needs_review":
                    out["needs_review"] = n
                elif src == "auto":
                    out["auto"] = n
        if _has_enrichment(c) and _has_col(c, "enrichment", "must_act"):
            out["available"] = True
            out["must_act"] = c.execute(
                """SELECT COUNT(*) FROM triage t JOIN enrichment e ON e.cve_id = t.cve_id
                   WHERE t.error IS NULL AND e.must_act IS NOT NULL"""
            ).fetchone()[0]
    return out


def reachability_summary() -> List[Dict[str, Any]]:
    """Counts by reachability label (computed at read time from triage fields)."""
    with _conn() as c:
        rows = c.execute(
            "SELECT location, veracode_apps, preconditions, impact_count "
            "FROM triage WHERE error IS NULL"
        ).fetchall()
    agg: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        k = _reachability(r["location"], r["veracode_apps"], r["preconditions"])
        a = agg.setdefault(k, {"reachability": k, "cve_count": 0, "total_impact": 0})
        a["cve_count"] += 1
        a["total_impact"] += (r["impact_count"] or 0)
    order = {"present-confirmed": 0, "present-conditional": 1, "pending-image": 2, "unknown": 3}
    return sorted(agg.values(), key=lambda x: order.get(x["reachability"], 9))
