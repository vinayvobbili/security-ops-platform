"""Automated per-CVE triage — replicate the war room's manual lookup-and-decide loop.

For one CVE this gathers the facts an analyst would look up by hand:

* **NVD** — description, CVSS, and the affected vendor:product + version ranges
  (``services.nvd.get_cve``).
* **Veracode SCA** — whether any application in the portfolio carries an
  open-source component affected by the CVE, and which versions
  (``services.veracode.cve_exposure``, reads the local SQLite index).

It then asks the LLM (``create_llm`` — GPT-4.1 primary, m1 GLM
fallback) whether remediation is required and what the action is, in the war room's terse
style. Veracode answers the application-dependency slice directly; base-image OS
packages fall through Veracode (it only scans the app portfolio) and are flagged
``base_image_os_package`` with reduced confidence pending image introspection.

PROTOTYPE / validation harness::

    python -m services.cve_triage

runs the four CVEs the war room already triaged by hand and prints the automated
verdict next to their note, so we can see whether the automation reproduces human
judgment before turning it loose on the full backlog. The harness runs *cold* —
it does NOT feed the human notes as examples, so it's an honest test.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field

from services.nvd import get_cve
from services.cve_org import get_cve_org


def _cve_exposure(cve_ids):
    """Optional SBOM/SCA exposure lookup. Wired when an SCA provider is
    configured; returns an empty result otherwise so triage runs without it."""
    try:
        from services.veracode import cve_exposure
        return cve_exposure(cve_ids)
    except ImportError:
        return {}
from my_bot.utils.llm_factory import create_llm, structured_output

logger = logging.getLogger(__name__)


# ── LLM output contract ────────────────────────────────────────────────────────
class TriageVerdict(BaseModel):
    """The decision the war room reaches per CVE."""
    component: str = Field(description="Best identification of the affected software/package, e.g. 'curl', 'Apache Tomcat', 'OpenSSL'")
    affected_versions: str = Field(description="Vulnerable version range if known, else 'unknown'")
    location: str = Field(description="Where it lives: 'application_dependency' (in our app portfolio), 'base_image_os_package' (OS-level, not an app dependency), or 'unknown'")
    remediation_required: bool = Field(description="True if action is needed; False if not present / not exploitable / no action warranted")
    recommended_action: str = Field(description="Concrete next step, e.g. 'Upgrade Tomcat to >= 9.0.99', 'Remove curl from the PROD base image', 'No action — component not present'")
    preconditions: str = Field(description="Exploitation preconditions from the CVE description, e.g. 'requires chaining with another flaw', '32-bit builds only', or 'none noted'")
    rationale: str = Field(description="2-3 sentence justification in a terse, analyst tone")
    confidence: str = Field(description="'high', 'medium', or 'low'")


# ── v2: adversarial two-analyst debate ──────────────────────────────────────────
# War-room direction (war-room lead, 2026-06): instead of one analyst, hand the same
# facts to TWO with opposing mandates — an attacker who assumes the flaw IS
# reachable and hunts the chain, and a skeptic who assumes it's noise until proven
# otherwise. A reconciler blends their scores; a large, high-severity disagreement
# is escalated to a human review queue. This is the bug-bounty triage pattern:
# adversarial pressure on both sides weeds out false positives far better than a
# single voice, and the disagreements that remain are exactly the ones worth a
# human's time.
class AnalystOpinion(BaseModel):
    """One analyst's read on a CVE for our fleet (attacker or skeptic mandate)."""
    component: str = Field(description="Best identification of the affected software/package, e.g. 'curl', 'Apache Tomcat'")
    affected_versions: str = Field(description="Vulnerable version range if known, else 'unknown'")
    location: str = Field(description="'application_dependency', 'base_image_os_package', or 'unknown'")
    preconditions: str = Field(description="Exploitation preconditions from the CVE, e.g. 'requires chaining', '32-bit builds only', or 'none noted'")
    reachable: bool = Field(description="Your judgment: is the vulnerable code actually reachable/exploitable in THIS containerized httpd/Java fleet?")
    remediation_required: bool = Field(description="Your verdict: is action needed?")
    recommended_action: str = Field(description="Concrete next step, e.g. 'Upgrade Tomcat to >= 9.0.99', 'Remove curl from base image', 'No action'")
    urgency_score: int = Field(description="0-100: how urgently YOU think this must be remediated in our fleet (0 = pure noise, 100 = drop-everything). Argue your mandate honestly.")
    reasoning: str = Field(description="2-3 sentences arguing your position in a terse, war-room tone")


_METHOD = """The fleet under review is a large estate of containerized services (httpd / Java app containers). You are given the facts an analyst would look up.

- Identify the affected component and whether our environment carries it. Distinguish an APPLICATION DEPENDENCY (a library bundled with our apps — Veracode SCA shows it) from a BASE-IMAGE OS PACKAGE (curl, openssl, glibc, krb5 — Veracode does NOT scan these, so absence from Veracode does NOT mean we're clean; it means presence is unconfirmed pending image introspection).
- Preferred remediation in a container fleet is often to UPGRADE the library or REMOVE/slim an unneeded package out of the base image.
- Weigh stated exploitation preconditions (requires chaining, specific config, 32-bit-only, attacker-controlled input reaching the sink).
- Weigh ACTIVE-EXPLOITATION evidence heavily: CISA KEV membership means the flaw is being exploited in the wild RIGHT NOW, and a high EPSS is a strong real-world exploitation signal. These describe what attackers ARE doing, not just what's theoretically possible — they raise the floor of urgency regardless of how narrow the preconditions look on paper."""

_SYSTEM_ATTACKER = f"""You are an offensive security analyst (red-team / bug-bounty mindset) in an incident war room. Your mandate: assume this vulnerability IS present and reachable until the facts prove otherwise, and figure out how an attacker would actually exploit it in our fleet.

{_METHOD}

Your bias: lean toward exploitability. Trace the realistic attack path — could an internet-facing httpd or Java service reach this sink, directly or via a simple chain? Name the worst plausible case.

Score honestly, though — urgency_score must reflect REAL reachability in THIS httpd/Java container fleet, not worst-case severity in the abstract. Calibrate it:
- 75–100: a credible path through an internet-facing app, OR active exploitation (CISA KEV / high EPSS), OR a confirmed application dependency (Veracode) with a realistic trigger.
- 40–70: plausible but gated — the path needs a config, usage pattern, or component we'd have to confirm we actually run.
- 10–40: present-but-not-realistically-reachable — a base-image OS package (curl, glibc, krb5, a RADIUS/mail/DB server we don't run as part of httpd/Java) whose vulnerable code path our app stack does not invoke, with NO active-exploitation signal. Installed ≠ reachable: a library sitting in the image that nothing calls at runtime is not a fire drill, no matter how high the CVSS.
A high CVSS alone is NOT a reason to score high — CVSS rates worst-case impact, not whether we can be reached. Don't inflate base-image findings to P1 on severity; if the realistic path is weak, say so and score it down."""

_SYSTEM_SKEPTIC = f"""You are a skeptical defensive analyst in an incident war room whose job is to weed out noise. Your mandate: assume this finding is a false positive or non-issue for our fleet until the facts prove it's genuinely reachable and exploitable here.

{_METHOD}

Your bias: lean toward "not reachable / no action." Scrutinize the preconditions — does the vulnerable code path actually get invoked by an httpd or Java app? Is this a base-image package nothing links against at runtime? Is exploitation gated on config we don't run, an arch we don't ship, or local access? A high CVSS does NOT mean reachable. If it's noise, say so and score urgency LOW. But stay honest — if it really is reachable and dangerous here, concede it and score accordingly.

One hard rule: do NOT dismiss a KNOWN-EXPLOITED (CISA KEV) or high-EPSS vulnerability as pure noise. Active exploitation in the wild is hard evidence the flaw is real and being used. You may still argue that OUR specific fleet doesn't expose the vulnerable path — but you must concede the vulnerability is genuine and keep your urgency_score off the floor (well above 0) whenever KEV is set, even when you believe our reachability is limited. Set urgency_score to reflect a defender's read after discounting genuinely unreachable findings."""


# Reconciliation thresholds (CONSERVATIVE queue, user-selected 2026-06-03): only
# escalate to a human when the analysts are far apart AND at least one of them
# rates it serious — otherwise auto-resolve toward the skeptic so the queue stays
# small. The severity test uses the TOP score, not the mean: a 95-vs-5 split
# (one analyst certain it's critical, the other certain it's noise) is exactly the
# standoff a human should settle — averaging it to 50 hid that and silently
# suppressed real P1s (the Tomcat CVE-2025-24813 validation miss, 2026-06-03).
# Tunable.
_DEBATE_GAP = 40        # |attacker - skeptic| urgency must exceed this to consider review
_DEBATE_SEVERITY = 60   # ...AND the HIGHER of the two scores must clear this


def _pick(primary: str, fallback: str) -> str:
    """Prefer a specific, non-empty/non-'unknown' value, else the fallback."""
    p = (primary or "").strip()
    if p and p.lower() not in {"unknown", "none", "n/a", ""}:
        return primary
    return fallback


def _reconcile(attacker: AnalystOpinion, skeptic: AnalystOpinion) -> Dict[str, Any]:
    """Blend the two opinions into a single verdict + debate metadata.

    Conservative routing:
      * large gap AND high combined severity  -> needs_review (flag for a human;
        default to acting pending review).
      * otherwise auto. When they disagree but it isn't review-worthy, trust the
        skeptic (deflationary) to suppress noise; when they agree, take that.
    """
    a, s = attacker.urgency_score, skeptic.urgency_score
    gap = abs(a - s)
    combined = (a + s) / 2.0
    top = max(a, s)
    agree = attacker.reachable == skeptic.reachable and gap < _DEBATE_GAP
    needs_review = gap >= _DEBATE_GAP and top >= _DEBATE_SEVERITY

    if needs_review:
        source, remediation = "needs_review", True
        action = (f"MANUAL REVIEW — analysts split (attacker {a} vs skeptic {s}). "
                  f"Attacker: {attacker.recommended_action}")
        confidence = "low"
        rationale = (f"Attacker ({a}): {attacker.reasoning} || "
                     f"Skeptic ({s}): {skeptic.reasoning} || "
                     f"Escalated: large disagreement at high severity.")
    elif agree:
        source = "auto"
        remediation = attacker.remediation_required and skeptic.remediation_required
        winner = attacker if a >= s else skeptic
        action = winner.recommended_action
        confidence = "high"
        rationale = f"Both analysts agree. {winner.reasoning}"
    else:
        # disagree but not review-worthy -> trust the skeptic (weed noise)
        source = "auto"
        remediation = skeptic.remediation_required
        action = skeptic.recommended_action
        confidence = "medium"
        rationale = (f"Attacker ({a}): {attacker.reasoning} || "
                     f"Skeptic ({s}): {skeptic.reasoning} || "
                     f"Auto-resolved to skeptic (gap/severity below review bar).")

    return {
        # TriageVerdict-compatible fields (so the triage table + page are unchanged)
        "component": _pick(attacker.component, skeptic.component),
        "affected_versions": _pick(attacker.affected_versions, skeptic.affected_versions),
        "location": _pick(attacker.location, skeptic.location),
        "preconditions": _pick(skeptic.preconditions, attacker.preconditions),
        "remediation_required": bool(remediation),
        "recommended_action": action,
        "rationale": rationale,
        "confidence": confidence,
        # debate metadata (separate `debate` table)
        "debate": {
            "score_attacker": a,
            "score_skeptic": s,
            "reachable_attacker": int(attacker.reachable),
            "reachable_skeptic": int(skeptic.reachable),
            "gap": gap,
            "combined": round(combined, 1),
            "verdict_source": source,
            "attacker_reasoning": attacker.reasoning,
            "skeptic_reasoning": skeptic.reasoning,
        },
    }


_SYSTEM = """You are a vulnerability triage analyst in an incident war room. The fleet under review is a large estate of containerized services (httpd / Java app containers). For each CVE you are given the facts an analyst would look up, and you must decide whether remediation is required and what the action is.

Method:
- Identify the affected component and whether our environment actually carries it.
- Distinguish an APPLICATION DEPENDENCY (a library bundled with our apps — Veracode SCA portfolio data will show it) from a BASE-IMAGE OS PACKAGE (curl, openssl, perl, glibc, krb5, etc. — Veracode does NOT scan these, so absence from Veracode does NOT mean we're clean; it means we can't confirm presence yet from this data alone).
- The preferred remediation in a container fleet is frequently to UPGRADE the library or to REMOVE/slim an unneeded package out of the base image — not necessarily to patch in place. Say so when it applies.
- Weigh exploitation preconditions stated in the CVE description (requires chaining, specific config, 32-bit-only, attacker-controlled input reaching the sink). Strong limiting preconditions lower urgency.
- Be terse and decisive, like a war-room note. Do not hedge beyond setting the confidence field.

Confidence:
- 'high' when Veracode confirms presence/versions or the description is unambiguous.
- 'medium'/'low' for base-image OS packages whose presence we cannot confirm from Veracode alone (note that image introspection is still pending)."""


def _cpe_products(nvd: Optional[dict]) -> List[str]:
    """Pull distinct vendor:product pairs from NVD CPE matches."""
    out: List[str] = []
    seen = set()
    for m in (nvd or {}).get("cpe_matches", []) or []:
        cpe = m.get("cpe") or ""
        parts = cpe.split(":")
        if len(parts) > 5:
            vp = f"{parts[3]}:{parts[4]}"
            if vp not in seen:
                seen.add(vp)
                out.append(vp)
    return out


def gather_facts(cve_id: str, impact_count: Optional[int] = None) -> Dict[str, Any]:
    """Look up everything we know about one CVE from the plumbing we own.

    NVD is the primary enrichment (CPE applicability + normalized CVSS). When NVD
    has no record or is sparse (no description / no CPE products — common for very
    recent CVEs still in NVD's analysis backlog), fall back to CVE.org, which
    carries the CNA description + affected package names. CVE.org is only consulted
    when NVD is insufficient, so the ~95% NVD covers well incur no second call.
    """
    cve_id = cve_id.upper().strip()
    nvd = get_cve(cve_id)  # None if NVD has no record / fetch failed
    vc = _cve_exposure([cve_id])
    exposures = vc.get("cves", {}).get(cve_id, []) or []

    # Active-exploitation evidence — surfaced to the analysts so the debate isn't
    # blind to KEV/EPSS (the enrichment pass runs AFTER triage, so without this the
    # skeptic can dismiss a known-exploited critical as "unreachable"). Both are
    # cheap: KEV is an O(1) cached-set hit, EPSS is a 1-day on-disk cache.
    from services.cve_priority import is_kev as _is_kev
    from services.epss import get_epss as _get_epss
    try:
        kev = _is_kev(cve_id)
    except Exception:  # noqa: BLE001 — never let an enrichment signal break triage
        kev = False
    try:
        epss = (_get_epss(cve_id) or {}).get("epss")
    except Exception:  # noqa: BLE001
        epss = None

    nvd_desc = (nvd or {}).get("description", "")
    cpe_products = _cpe_products(nvd)

    org = None
    if nvd is None or not nvd_desc or not cpe_products:
        org = get_cve_org(cve_id)
    org_products: List[str] = []
    for p in (org or {}).get("products", []):
        label = p.get("package") or p.get("product") or p.get("vendor")
        if label:
            org_products.append(label)
        for cpe in p.get("cpes", []):
            parts = cpe.split(":")
            if len(parts) > 4 and parts[3] and parts[4]:
                org_products.append(f"{parts[3]}:{parts[4]}")
    org_products = sorted(set(org_products))

    return {
        "cve_id": cve_id,
        "impact_count": impact_count,
        "nvd_found": nvd is not None,
        "cveorg_found": org is not None,
        "source": "nvd" if nvd else ("cve.org" if org else "none"),
        "description": nvd_desc or (org or {}).get("description", ""),
        "cvss": (nvd or {}).get("severity") or (org or {}).get("severity"),
        "cpe_products": cpe_products or org_products,
        "kev": kev,
        "epss": epss,
        "veracode_matched": bool(exposures),
        "veracode_affected_app_count": vc.get("affected_app_count", 0),
        "veracode_components": sorted({e["component"] for e in exposures}),
        "veracode_versions": sorted({e["version"] for e in exposures if e.get("version")}),
    }


def _facts_prompt(facts: Dict[str, Any]) -> str:
    cvss = facts.get("cvss") or {}
    kev = facts.get("kev")
    epss = facts.get("epss")
    epss_txt = f"{epss:.1%}" if isinstance(epss, (int, float)) else "unknown"
    kev_txt = (
        "YES — on CISA KEV, KNOWN-EXPLOITED IN THE WILD (active attacks observed)"
        if kev else "no (not on CISA's known-exploited catalog)"
    )
    lines = [
        f"CVE: {facts['cve_id']}",
        f"Fleet impact count (asset-instances flagged): {facts.get('impact_count', 'n/a')}",
        f"CVSS: {cvss.get('base_score', '?')} ({cvss.get('base_severity', '?')}) {cvss.get('vector', '')}".strip(),
        f"Known-exploited (CISA KEV): {kev_txt}",
        f"EPSS (probability of exploitation in next 30 days): {epss_txt}",
        f"Affected products (NVD CPE / CVE.org CNA package): {', '.join(facts['cpe_products']) or 'none listed'}",
        "",
        "Veracode SCA (application portfolio):",
        f"  matched: {facts['veracode_matched']}",
        f"  affected applications: {facts['veracode_affected_app_count']}",
        f"  components: {', '.join(facts['veracode_components']) or 'none'}",
        f"  versions present: {', '.join(facts['veracode_versions']) or 'none'}",
        "",
        f"Description (source: {facts.get('source', 'nvd')}):",
        facts["description"] or "(no CVE record found in NVD or CVE.org)",
    ]
    return "\n".join(lines)


def _debate_chain():
    """Build the shared AnalystOpinion chain (reused for both mandates)."""
    return structured_output(create_llm(temperature=0), AnalystOpinion)


def triage_cve(
    cve_id: str,
    impact_count: Optional[int] = None,
    examples: Optional[List[Dict[str, str]]] = None,
    chain: Any = None,
) -> Dict[str, Any]:
    """Gather facts for a CVE and return an automated triage verdict via debate.

    v2: the same facts are judged by two adversarial analysts (attacker mandate +
    skeptic mandate) and reconciled. The returned ``verdict`` keeps every field
    the old single-analyst verdict had (so the DB/page are unchanged), plus a
    ``debate`` block with both scores and the routing (``auto`` / ``needs_review``).

    Args:
        cve_id: e.g. ``"CVE-2025-24813"``.
        impact_count: optional fleet asset-instance count from the war-room sheet.
        examples: optional few-shot (reserved; not used by the debate path).
        chain: optional pre-built ``_debate_chain()`` to reuse across a batch
            (avoids rebuilding the client per CVE). Both mandates share it — only
            the system message differs per invoke.
    """
    facts = gather_facts(cve_id, impact_count)
    facts_msg = HumanMessage(content=_facts_prompt(facts))
    if chain is None:
        chain = _debate_chain()

    attacker = chain.invoke([SystemMessage(content=_SYSTEM_ATTACKER), facts_msg])
    skeptic = chain.invoke([SystemMessage(content=_SYSTEM_SKEPTIC), facts_msg])
    reconciled = _reconcile(attacker, skeptic)
    debate = reconciled.pop("debate")

    return {"facts": facts, "verdict": reconciled, "debate": debate}


# ── batch over the full war-room sheet ──────────────────────────────────────────
import sqlite3  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

import openpyxl  # noqa: E402

import services.nvd as _nvd  # noqa: E402

_RESULTS_DB = Path(__file__).resolve().parent.parent / "data" / "transient" / "cve_triage_results.db"
_BATCH_COLS = (
    "component", "affected_versions", "location", "remediation_required",
    "recommended_action", "preconditions", "confidence", "rationale",
)


def _results_conn() -> sqlite3.Connection:
    _RESULTS_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_RESULTS_DB), timeout=30)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS triage (
            cve_id TEXT PRIMARY KEY, impact_count INTEGER,
            component TEXT, affected_versions TEXT, location TEXT,
            remediation_required INTEGER, recommended_action TEXT,
            preconditions TEXT, confidence TEXT, rationale TEXT,
            nvd_found INTEGER, cvss REAL, veracode_matched INTEGER,
            veracode_apps INTEGER, error TEXT, triaged_at INTEGER
        )"""
    )
    # Separate enrichment table so the no-LLM EPSS/priority pass never touches
    # the positional `triage` INSERT (which must stay 16-col while a batch runs).
    conn.execute(
        """CREATE TABLE IF NOT EXISTS enrichment (
            cve_id TEXT PRIMARY KEY, epss REAL, percentile REAL,
            kev INTEGER, pre_auth INTEGER, priority TEXT, sla_days INTEGER,
            attack_layer TEXT, cvss_vector TEXT, enriched_at INTEGER
        )"""
    )
    # must_act: the deterministic MUST-ACT rule name that forced P1 (or NULL).
    # Self-migrate older DBs that predate the column.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(enrichment)")}
    if "must_act" not in cols:
        conn.execute("ALTER TABLE enrichment ADD COLUMN must_act TEXT")
    # v2 adversarial debate: both analysts' scores + the routing decision. Keyed
    # by cve_id, written by the batch alongside the triage row. Read-time only
    # for the page (the 'Needs Review' queue + score columns).
    conn.execute(
        """CREATE TABLE IF NOT EXISTS debate (
            cve_id TEXT PRIMARY KEY,
            score_attacker INTEGER, score_skeptic INTEGER,
            reachable_attacker INTEGER, reachable_skeptic INTEGER,
            gap INTEGER, combined REAL, verdict_source TEXT,
            attacker_reasoning TEXT, skeptic_reasoning TEXT, debated_at INTEGER
        )"""
    )
    return conn


def _write_debate(conn: sqlite3.Connection, cve_id: str, debate: Dict[str, Any]) -> None:
    """Upsert one adversarial-debate record (no-op if the verdict had no debate)."""
    if not debate:
        return
    conn.execute(
        """INSERT OR REPLACE INTO debate
           (cve_id, score_attacker, score_skeptic, reachable_attacker,
            reachable_skeptic, gap, combined, verdict_source,
            attacker_reasoning, skeptic_reasoning, debated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (cve_id, debate["score_attacker"], debate["score_skeptic"],
         debate["reachable_attacker"], debate["reachable_skeptic"],
         debate["gap"], debate["combined"], debate["verdict_source"],
         debate["attacker_reasoning"], debate["skeptic_reasoning"], int(time.time())),
    )


def _load_sheet(path: str) -> List[tuple]:
    """Return [(cve_id, impact_count), ...] sorted by impact desc."""
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    ws = wb.active
    rows = []
    for r in list(ws.iter_rows(values_only=True))[1:]:
        if r and r[0] and str(r[0]).upper().startswith("CVE-"):
            rows.append((str(r[0]).strip().upper(), r[1] if isinstance(r[1], (int, float)) else 0))
    return sorted(rows, key=lambda x: -x[1])


def batch_triage(sheet_path: str, limit: Optional[int] = None, force: bool = False) -> None:
    """Triage every CVE in the sheet, resumable, impact-ordered, incremental.

    Writes one row per CVE into ``cve_triage_results.db``. Re-running skips CVEs
    already done (resume). Throttles uncached NVD fetches to respect the
    unauthenticated 5-req/30s limit; no throttle when an API key is configured.

    ``force=True`` re-processes EVERY row even if already triaged — used to roll a
    new engine (e.g. the adversarial debate) over a DB triaged by an older one.
    Each row is rewritten in place via ``INSERT OR REPLACE``, so the table is
    never emptied: callers reading the page see each CVE flip old->new as it goes,
    rather than the page going dark during a full re-run.
    """
    has_key = bool(_nvd._headers())
    nvd_delay = 0.0 if has_key else 6.5
    rows = _load_sheet(sheet_path)
    if limit:
        rows = rows[:limit]

    conn = _results_conn()
    done = set() if force else {r[0] for r in conn.execute("SELECT cve_id FROM triage WHERE error IS NULL")}
    todo = [(c, i) for c, i in rows if c not in done]
    chain = _debate_chain()

    print(f"[batch] sheet={len(rows)} CVEs | already done={len(done)} | to do={len(todo)} | "
          f"force={'YES (re-debate all)' if force else 'no'} | "
          f"nvd_key={'yes' if has_key else 'NO (6.5s throttle)'} | mode=debate (2 LLM calls/CVE)", flush=True)
    started = time.time()
    for n, (cve_id, impact) in enumerate(todo, 1):
        cached = _nvd._load_cached(cve_id) is not None
        try:
            out = triage_cve(cve_id, impact_count=impact, chain=chain)
            v, f = out["verdict"], out["facts"]
            conn.execute(
                "INSERT OR REPLACE INTO triage VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (cve_id, impact, v["component"], v["affected_versions"], v["location"],
                 int(v["remediation_required"]), v["recommended_action"], v["preconditions"],
                 v["confidence"], v["rationale"], int(f["nvd_found"]),
                 (f["cvss"] or {}).get("base_score"), int(f["veracode_matched"]),
                 f["veracode_affected_app_count"], None, int(time.time())),
            )
            _write_debate(conn, cve_id, out.get("debate"))
        except Exception as e:  # noqa: BLE001 — record + continue; resumable retries later
            conn.execute(
                "INSERT OR REPLACE INTO triage (cve_id, impact_count, error, triaged_at) VALUES (?,?,?,?)",
                (cve_id, impact, f"{type(e).__name__}: {e}", int(time.time())),
            )
        conn.commit()
        if n % 25 == 0 or n == len(todo):
            rate = n / max(time.time() - started, 1)
            eta_min = (len(todo) - n) / max(rate, 1e-6) / 60
            print(f"[batch] {n}/{len(todo)} done | {rate*60:.0f}/min | ETA {eta_min:.0f} min", flush=True)
        if not cached and nvd_delay:
            time.sleep(nvd_delay)
    print(f"[batch] complete: {len(todo)} processed in {(time.time()-started)/60:.0f} min", flush=True)


def fill_holes(limit: Optional[int] = None) -> None:
    """Re-triage rows where NVD had no record (``nvd_found=0``), now that
    ``gather_facts`` consults CVE.org. Updates those rows in place; rows NVD
    already covered are left untouched. Run AFTER the main batch completes.
    """
    conn = _results_conn()
    holes = conn.execute(
        "SELECT cve_id, impact_count FROM triage WHERE nvd_found = 0 ORDER BY impact_count DESC"
    ).fetchall()
    if limit:
        holes = holes[:limit]
    chain = _debate_chain()
    print(f"[fill] {len(holes)} nvd_found=0 holes to re-triage via CVE.org", flush=True)
    rescued = 0
    started = time.time()
    for n, (cve_id, impact) in enumerate(holes, 1):
        try:
            out = triage_cve(cve_id, impact_count=impact, chain=chain)
            v, f = out["verdict"], out["facts"]
            if f.get("cveorg_found"):
                rescued += 1
            conn.execute(
                "INSERT OR REPLACE INTO triage VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (cve_id, impact, v["component"], v["affected_versions"], v["location"],
                 int(v["remediation_required"]), v["recommended_action"], v["preconditions"],
                 v["confidence"], v["rationale"], int(f["nvd_found"]),
                 (f["cvss"] or {}).get("base_score"), int(f["veracode_matched"]),
                 f["veracode_affected_app_count"], None, int(time.time())),
            )
            _write_debate(conn, cve_id, out.get("debate"))
        except Exception as e:  # noqa: BLE001
            conn.execute(
                "INSERT OR REPLACE INTO triage (cve_id, impact_count, error, triaged_at) VALUES (?,?,?,?)",
                (cve_id, impact, f"{type(e).__name__}: {e}", int(time.time())),
            )
        conn.commit()
        if n % 25 == 0 or n == len(holes):
            rate = n / max(time.time() - started, 1)
            print(f"[fill] {n}/{len(holes)} | {rate*60:.0f}/min | CVE.org-rescued so far={rescued}", flush=True)
    print(f"[fill] complete: {len(holes)} re-triaged, {rescued} had a CVE.org record", flush=True)


# ── priority enrichment (EPSS + KEV + pre-auth + attack layer; NO LLM) ───────────
_CWE_LAYER = {
    "502": "deserialization",
    "287": "auth-mechanism", "306": "auth-mechanism", "522": "auth-mechanism",
    "444": "http-parsing", "113": "http-parsing",
    "94": "app-logic", "77": "app-logic", "78": "app-logic", "89": "app-logic", "79": "app-logic",
}


def classify_attack_layer(cwes: List[str], description: str, products: List[str]) -> str:
    """Cheap heuristic: where does the CVE fire relative to our controls?"""
    for cwe in cwes or []:
        num = "".join(ch for ch in str(cwe) if ch.isdigit())
        if num in _CWE_LAYER:
            return _CWE_LAYER[num]
    text = " ".join([description or "", " ".join(p for p in (products or []) if p)]).lower()
    checks = [
        (("tls", "ssl", "handshake", "x.509", "certificate", "cipher"), "tls-handshake"),
        (("http/2", "http/3", "hpack", "websocket", "stream reset", "rapid reset"), "protocol-framing"),
        (("request smuggling", "header injection", "chunked encoding"), "http-parsing"),
        (("radius", "ldap", "dns", "snmp", "ntp", "smb", "kerberos", "bgp"), "network-protocol"),
        (("deserial", "objectmapper", "gadget chain", "readobject"), "deserialization"),
        (("jwt", "saml", "oauth", "authentication bypass", "password"), "auth-mechanism"),
        (("base image", "supply chain", "typosquat", "malicious package", "transitive dep"), "supply-chain"),
        (("kernel", "glibc", "systemd", "container runtime", "runc", "containerd"), "os-runtime"),
    ]
    for needles, layer in checks:
        if any(n in text for n in needles):
            return layer
    return "app-logic"


def _rce_dos(description: str, cwes: List[str]) -> tuple[bool, bool]:
    t = (description or "").lower() + " " + " ".join(str(c) for c in (cwes or [])).lower()
    nums = {"".join(ch for ch in str(c) if ch.isdigit()) for c in (cwes or [])}
    is_rce = ("remote code execution" in t or "arbitrary code" in t
              or bool(nums & {"94", "77", "78", "502"}))
    is_dos = ("denial of service" in t or "cwe-400" in t or "400" in nums)
    return is_rce, is_dos


def enrich_priorities(limit: Optional[int] = None, refresh_epss: bool = False) -> None:
    """No-LLM pass: attach EPSS + KEV + pre-auth + composite priority + attack
    layer to every triaged CVE, into the separate ``enrichment`` table. Recovers
    the CVSS vector / CWEs offline from the NVD + CVE.org caches (no network for
    those). Safe to run concurrently with the batch (separate table). Idempotent.
    """
    from services import epss as _epss
    from services import cve_priority as _prio
    import services.cve_org as _cveorg
    from services.cve_triage_db import _reachability

    # Real EAI internet-facing flag per CVE (V_APP_INFO.Internet_Facing_Indicator),
    # via the cgr eaiCode join. Absent for CVEs with no cgr/EAI linkage -> the
    # priority ceiling degrades to code-path-only for those. Best-effort: if cgr
    # data isn't present in this worktree, every CVE is exposure-unknown.
    try:
        from services import cgr as _cgr
        ext_map = _cgr.external_facing_map()
    except Exception as e:  # noqa: BLE001
        logger.warning("enrich: EAI internet-facing map unavailable (%s)", e)
        ext_map = {}

    conn = _results_conn()
    rows = conn.execute(
        "SELECT cve_id, impact_count, cvss, location, veracode_apps, preconditions "
        "FROM triage WHERE error IS NULL ORDER BY impact_count DESC"
    ).fetchall()
    if limit:
        rows = rows[:limit]
    ids = [r[0] for r in rows]
    print(f"[enrich] {len(ids)} triaged CVEs | EAI internet-facing links={len(ext_map)} | "
          f"bulk EPSS fetch…", flush=True)
    scores = _epss.get_epss_bulk(ids, force_refresh=refresh_epss)
    started = time.time()
    for n, (cve_id, impact, cvss_score, location, veracode_apps, preconditions) in enumerate(rows, 1):
        vector, cwes, desc, products = None, [], "", []
        nc = _nvd._load_cached(cve_id)
        if nc:
            sev = nc.get("severity") or {}
            vector = sev.get("vector")
            desc = nc.get("description", "")
        oc = _cveorg._load_cached(cve_id)
        if oc and oc.get("found"):
            vector = vector or (oc.get("severity") or {}).get("vector")
            cwes = oc.get("cwes") or []
            desc = desc or oc.get("description", "")
            products = [p.get("package") or p.get("product") for p in oc.get("products", [])]
        sc = scores.get(cve_id) or {}
        epss_v = sc.get("epss")
        kev = _prio.is_kev(cve_id)
        pre_auth = _prio.pre_auth_from_cvss_vector(vector)
        is_rce, is_dos = _rce_dos(desc, cwes)
        reachability = _reachability(location, veracode_apps, preconditions)
        prio = _prio.composite_priority(
            cvss_score=cvss_score, epss=epss_v or 0.0, kev=kev, pre_auth=pre_auth,
            in_environment=(impact or 0) > 0, is_rce=is_rce, is_dos=is_dos,
            reachability=reachability, internet_facing=ext_map.get(cve_id),
        )
        layer = classify_attack_layer(cwes, desc, products)
        conn.execute(
            """INSERT OR REPLACE INTO enrichment
               (cve_id, epss, percentile, kev, pre_auth, priority, sla_days,
                attack_layer, cvss_vector, must_act, enriched_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (cve_id, epss_v, sc.get("percentile"), int(kev), int(pre_auth),
             prio["tier"], prio["sla_days"], layer, vector,
             prio.get("must_act"), int(time.time())),
        )
        conn.commit()
        if n % 100 == 0 or n == len(rows):
            print(f"[enrich] {n}/{len(rows)} | {n/max(time.time()-started,1)*60:.0f}/min", flush=True)
    dist = dict(conn.execute("SELECT priority, COUNT(*) FROM enrichment GROUP BY priority").fetchall())
    ma = conn.execute("SELECT COUNT(*) FROM enrichment WHERE must_act IS NOT NULL").fetchone()[0]
    print(f"[enrich] complete: tier distribution {dist} | MUST-ACT forced P1 on {ma}", flush=True)


# ── validation harness ─────────────────────────────────────────────────────────
# The four CVEs the war room reviewed by hand, with their note as ground truth.
_REVIEWED = [
    ("CVE-2026-5773", 5586, "Curl; requires chaining; curl needs to be removed from the base build for PROD"),
    ("CVE-2026-6276", 5568, "Curl"),
    ("CVE-2025-24813", 551, "Tomcat; 9.8 severity — the war room's P1 case"),
    ("CVE-2024-3596", 38, "radius; Can be removed"),
    ("CVE-2026-5450", 0, "glibc scanf heap overflow; CVSS 9.8 but NOT reachable in httpd/Java — must NOT be urgent"),
]


def _run_validation() -> None:
    logging.basicConfig(level=logging.WARNING)
    print("=" * 88)
    print("COLD VALIDATION — adversarial debate vs. war-room hand notes (notes NOT shown to model)")
    print("=" * 88)
    for cve_id, impact, human_note in _REVIEWED:
        print(f"\n### {cve_id}  (impact={impact})")
        print(f"  HUMAN  : {human_note}")
        try:
            out = triage_cve(cve_id, impact_count=impact)
            v, f, d = out["verdict"], out["facts"], out["debate"]
            print(f"  DEBATE : attacker={d['score_attacker']} (reachable={bool(d['reachable_attacker'])}) "
                  f"vs skeptic={d['score_skeptic']} (reachable={bool(d['reachable_skeptic'])}) "
                  f"| gap={d['gap']} combined={d['combined']} -> {d['verdict_source'].upper()}")
            print(f"  VERDICT: component={v['component']!r} | location={v['location']} | "
                  f"remediation_required={v['remediation_required']} | confidence={v['confidence']}")
            print(f"           action : {v['recommended_action']}")
            print(f"           why    : {v['rationale']}")
            print(f"           [facts: nvd_found={f['nvd_found']} cvss={(f['cvss'] or {}).get('base_score')} "
                  f"veracode_matched={f['veracode_matched']} apps={f['veracode_affected_app_count']}]")
        except Exception as e:  # noqa: BLE001 — harness: surface any failure inline
            print(f"  AUTO   : FAILED — {type(e).__name__}: {e}")


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Automated per-CVE triage")
    ap.add_argument("--batch", metavar="SHEET", help="path to the war-room xlsx; triage every CVE")
    ap.add_argument("--fill-holes", action="store_true", help="re-triage nvd_found=0 rows via CVE.org")
    ap.add_argument("--enrich", action="store_true", help="attach EPSS+KEV+pre-auth+priority (no LLM)")
    ap.add_argument("--limit", type=int, default=None, help="only the top-N by impact (smoke test)")
    ap.add_argument("--force", action="store_true", help="with --batch: re-triage rows already done (roll a new engine over the whole DB)")
    args = ap.parse_args()
    if args.fill_holes:
        fill_holes(limit=args.limit)
    elif args.enrich:
        enrich_priorities(limit=args.limit)
    elif args.batch:
        batch_triage(args.batch, limit=args.limit, force=args.force)
    else:
        _run_validation()
