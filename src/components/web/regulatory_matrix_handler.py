"""Regulatory Acceleration Matrix — handler for AI intake submission #7.

v1 scope: a crosswalk of regulations (GDPR / CCPA / HIPAA) against NIST CSF 2.0
control families, with a handful of cells backed by live evidence pulled from
CrowdStrike and ServiceNow. Everything else is seeded so the stakeholder can react to
shape, not numbers.

v2 questions (kept on-page so stakeholders can answer in one place) live in
``V2_QUESTIONS`` below.
"""

import logging
import threading
import time
from threading import Lock
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

REGULATIONS = [
    {"id": "GDPR", "name": "GDPR", "scope": "EU / EEA personal data"},
    {"id": "CCPA", "name": "CCPA / CPRA", "scope": "California consumer data"},
    {"id": "HIPAA", "name": "HIPAA Security Rule", "scope": "US PHI / ePHI"},
]

CONTROL_FAMILIES = [
    {"id": "GV.PO", "name": "Governance — Policy", "function": "Govern"},
    {"id": "GV.RR", "name": "Governance — Roles & Responsibilities", "function": "Govern"},
    {"id": "ID.AM", "name": "Identify — Asset Management", "function": "Identify"},
    {"id": "ID.RA", "name": "Identify — Risk Assessment", "function": "Identify"},
    {"id": "PR.AA", "name": "Protect — Identity & Access", "function": "Protect"},
    {"id": "PR.DS", "name": "Protect — Data Security", "function": "Protect"},
    {"id": "PR.PS", "name": "Protect — Platform Security", "function": "Protect"},
    {"id": "DE.CM", "name": "Detect — Continuous Monitoring", "function": "Detect"},
    {"id": "DE.AE", "name": "Detect — Anomaly & Event Analysis", "function": "Detect"},
    {"id": "RS.RP", "name": "Respond — Incident Response", "function": "Respond"},
    {"id": "RS.MI", "name": "Respond — Mitigation", "function": "Respond"},
    {"id": "RC.RP", "name": "Recover — Recovery Planning", "function": "Recover"},
]

# Coverage levels: covered | partial | gap | unknown
# Each cell carries regulation citations + evidence source ids (resolved at request time).
CROSSWALK: Dict[str, Dict[str, Dict[str, Any]]] = {
    "GV.PO":  {
        "GDPR":  {"coverage": "covered",  "citations": ["Art 5(2) accountability", "Art 24"], "evidence_ids": ["seed_policy_catalog"]},
        "CCPA":  {"coverage": "covered",  "citations": ["§1798.100(b)"], "evidence_ids": ["seed_policy_catalog"]},
        "HIPAA": {"coverage": "covered",  "citations": ["§164.316(a)"], "evidence_ids": ["seed_policy_catalog"]},
    },
    "GV.RR":  {
        "GDPR":  {"coverage": "partial",  "citations": ["Art 24, 37–39 (DPO)"], "evidence_ids": ["seed_rr_dpo_gap"]},
        "CCPA":  {"coverage": "covered",  "citations": ["§1798.105(c) intake roles"], "evidence_ids": ["seed_policy_catalog"]},
        "HIPAA": {"coverage": "covered",  "citations": ["§164.308(a)(2) Security Official"], "evidence_ids": ["seed_policy_catalog"]},
    },
    "ID.AM":  {
        "GDPR":  {"coverage": "partial",  "citations": ["Art 30 records of processing"], "evidence_ids": ["seed_cmdb_total"]},
        "CCPA":  {"coverage": "partial",  "citations": ["§1798.100(a) data inventory"], "evidence_ids": ["seed_cmdb_total"]},
        "HIPAA": {"coverage": "covered",  "citations": ["§164.310(d)(1) device & media"], "evidence_ids": ["seed_cmdb_total"]},
    },
    "ID.RA":  {
        "GDPR":  {"coverage": "partial",  "citations": ["Art 35 DPIA"], "evidence_ids": ["seed_dpia_coverage"]},
        "CCPA":  {"coverage": "gap",      "citations": ["§7150 risk assessment (CPRA)"], "evidence_ids": ["seed_dpia_coverage"]},
        "HIPAA": {"coverage": "covered",  "citations": ["§164.308(a)(1)(ii)(A)"], "evidence_ids": ["seed_risk_program"]},
    },
    "PR.AA":  {
        "GDPR":  {"coverage": "covered",  "citations": ["Art 32(1)(b)"], "evidence_ids": ["seed_iam_mfa_rate"]},
        "CCPA":  {"coverage": "covered",  "citations": ["§1798.150 reasonable security"], "evidence_ids": ["seed_iam_mfa_rate"]},
        "HIPAA": {"coverage": "covered",  "citations": ["§164.312(a)(1)"], "evidence_ids": ["seed_iam_mfa_rate"]},
    },
    "PR.DS":  {
        "GDPR":  {"coverage": "partial",  "citations": ["Art 32(1)(a) pseudonymization & encryption"], "evidence_ids": ["seed_varonis_classified_pct", "seed_dlp_alerts"]},
        "CCPA":  {"coverage": "partial",  "citations": ["§1798.150 reasonable security"], "evidence_ids": ["seed_varonis_classified_pct"]},
        "HIPAA": {"coverage": "covered",  "citations": ["§164.312(a)(2)(iv) encryption", "§164.312(e)(1)"], "evidence_ids": ["seed_encryption_at_rest"]},
    },
    "PR.PS":  {
        "GDPR":  {"coverage": "covered",  "citations": ["Art 32(1)(b)"], "evidence_ids": ["live_cs_fleet"]},
        "CCPA":  {"coverage": "covered",  "citations": ["§1798.150"], "evidence_ids": ["live_cs_fleet"]},
        "HIPAA": {"coverage": "covered",  "citations": ["§164.308(a)(5)(ii)(B) malicious software"], "evidence_ids": ["live_cs_fleet"]},
    },
    "DE.CM":  {
        "GDPR":  {"coverage": "covered",  "citations": ["Art 32(1)(d) regular testing"], "evidence_ids": ["live_cs_rule_count", "seed_siem_volume"]},
        "CCPA":  {"coverage": "covered",  "citations": ["§1798.150 reasonable security"], "evidence_ids": ["live_cs_rule_count"]},
        "HIPAA": {"coverage": "covered",  "citations": ["§164.308(a)(1)(ii)(D) info system activity review"], "evidence_ids": ["live_cs_rule_count", "seed_siem_volume"]},
    },
    "DE.AE":  {
        "GDPR":  {"coverage": "partial",  "citations": ["Art 33(1) awareness of breach"], "evidence_ids": ["seed_anomaly_program"]},
        "CCPA":  {"coverage": "partial",  "citations": ["§1798.82 breach notification"], "evidence_ids": ["seed_anomaly_program"]},
        "HIPAA": {"coverage": "covered",  "citations": ["§164.308(a)(6)(ii)"], "evidence_ids": ["seed_anomaly_program"]},
    },
    "RS.RP":  {
        "GDPR":  {"coverage": "covered",  "citations": ["Art 33 breach notification (72h)"], "evidence_ids": ["live_snow_mim", "seed_ir_playbook"]},
        "CCPA":  {"coverage": "covered",  "citations": ["§1798.82(a) breach notice"], "evidence_ids": ["live_snow_mim", "seed_ir_playbook"]},
        "HIPAA": {"coverage": "covered",  "citations": ["§164.308(a)(6) security incident procedures"], "evidence_ids": ["live_snow_mim", "seed_ir_playbook"]},
    },
    "RS.MI":  {
        "GDPR":  {"coverage": "partial",  "citations": ["Art 32(1)(c) restore availability"], "evidence_ids": ["seed_containment_rate"]},
        "CCPA":  {"coverage": "partial",  "citations": ["§1798.150"], "evidence_ids": ["seed_containment_rate"]},
        "HIPAA": {"coverage": "covered",  "citations": ["§164.308(a)(6)(ii) response & reporting"], "evidence_ids": ["seed_containment_rate"]},
    },
    "RC.RP":  {
        "GDPR":  {"coverage": "partial",  "citations": ["Art 32(1)(c)"], "evidence_ids": ["seed_dr_test_cadence"]},
        "CCPA":  {"coverage": "unknown",  "citations": ["—"], "evidence_ids": ["seed_dr_test_cadence"]},
        "HIPAA": {"coverage": "covered",  "citations": ["§164.308(a)(7) contingency plan"], "evidence_ids": ["seed_dr_test_cadence"]},
    },
}

# Evidence registry: 'live' entries call a getter (cached); 'seeded' entries
# return a static placeholder so the cell still has a number for the stakeholder.
EVIDENCE_TTL_SECONDS = 600  # 10 minutes
_EVIDENCE_CACHE: Dict[str, Dict[str, Any]] = {}
_EVIDENCE_LOCK = Lock()


def _cache_get(key: str) -> Optional[Dict[str, Any]]:
    entry = _EVIDENCE_CACHE.get(key)
    if entry and (time.time() - entry["ts"]) < EVIDENCE_TTL_SECONDS:
        return entry["value"]
    return None


def _cache_put(key: str, value: Dict[str, Any]) -> None:
    with _EVIDENCE_LOCK:
        _EVIDENCE_CACHE[key] = {"ts": time.time(), "value": value}


def _evidence_cs_fleet() -> Dict[str, Any]:
    """Live: total endpoints under CrowdStrike management.

    Falls back to a 'service unreachable' marker if auth fails — we don't want
    the page to die because the corp network blocked us at request time.
    """
    cached = _cache_get("live_cs_fleet")
    if cached is not None:
        return cached
    try:
        from services.crowdstrike import CrowdStrikeClient
        client = CrowdStrikeClient()
        if not client.validate_auth():
            value = {"label": "CrowdStrike endpoints", "value": "unavailable", "status": "unreachable", "source": "CrowdStrike Falcon"}
        else:
            # Cheap aggregate: hit the device IDs endpoint with limit=1 and read total from meta
            token = client.get_access_token()
            import requests
            resp = requests.get(
                f"https://{client.base_url}/devices/queries/devices/v1",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": 1},
                timeout=15,
                proxies=getattr(client, "proxies", None),
                verify=False,
            )
            resp.raise_for_status()
            total = resp.json().get("meta", {}).get("pagination", {}).get("total")
            value = {
                "label": "CrowdStrike-managed endpoints",
                "value": f"{total:,}" if isinstance(total, int) else "unknown",
                "status": "live",
                "source": "CrowdStrike Falcon /devices/queries/devices/v1",
            }
    except Exception as e:
        logger.warning("CS fleet evidence failed: %s", e)
        value = {"label": "CrowdStrike endpoints", "value": "unavailable", "status": "error", "source": "CrowdStrike Falcon", "error": str(e)[:200]}
    _cache_put("live_cs_fleet", value)
    return value


def _evidence_cs_rule_count() -> Dict[str, Any]:
    """Live: count of custom IOA rule groups + IOC indicators (detective controls)."""
    cached = _cache_get("live_cs_rule_count")
    if cached is not None:
        return cached
    try:
        from services.crowdstrike import CrowdStrikeClient
        client = CrowdStrikeClient()
        if not client.validate_auth():
            value = {"label": "Custom CS detections", "value": "unavailable", "status": "unreachable", "source": "CrowdStrike Falcon"}
        else:
            ioa = client.list_custom_ioa_rule_groups() or {}
            ioa_count = ioa.get("count") if "error" not in ioa else None
            # IOC count: hit the query endpoint and read pagination.total (avoids pulling all rows)
            ioc_total = None
            try:
                import requests as _r
                token = client.get_access_token()
                r = _r.get(
                    f"https://{client.base_url}/iocs/queries/indicators/v1",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"limit": 1},
                    timeout=15,
                    proxies=getattr(client, "proxies", None),
                    verify=False,
                )
                if r.status_code == 200:
                    ioc_total = (r.json().get("meta") or {}).get("pagination", {}).get("total")
            except Exception as inner:
                logger.debug("IOC total lookup failed: %s", inner)
            parts = []
            if isinstance(ioa_count, int): parts.append(f"{ioa_count} IOA rule groups")
            if isinstance(ioc_total, int): parts.append(f"{ioc_total:,} IOC indicators")
            value = {
                "label": "Active CS detective controls",
                "value": " · ".join(parts) if parts else "unknown",
                "status": "live",
                "source": "CrowdStrike Falcon /ioarules + /iocs",
            }
    except Exception as e:
        logger.warning("CS rule count evidence failed: %s", e)
        value = {"label": "Active CS detective controls", "value": "unavailable", "status": "error", "source": "CrowdStrike Falcon", "error": str(e)[:200]}
    _cache_put("live_cs_rule_count", value)
    return value


def _evidence_snow_mim() -> Dict[str, Any]:
    """Live: incidents in MIM assignment groups over the last 7 days — proves IR process is running."""
    cached = _cache_get("live_snow_mim")
    if cached is not None:
        return cached
    try:
        from services.service_now import ServiceNowClient
        client = ServiceNowClient()
        total = 0
        groups_polled: List[str] = []
        for group in ("GTO-Major Incident management-US", "GTO-Major Incident management-EMEA"):
            try:
                rows = client.get_recent_incidents_by_group_name(group, minutes=10080)  # 7d
                if isinstance(rows, list):
                    total += len(rows)
                    groups_polled.append(group)
            except Exception as inner:
                logger.debug("SNOW group %s failed: %s", group, inner)
        value = {
            "label": "MIM incidents (last 7d)",
            "value": f"{total} across {len(groups_polled)} group(s)" if groups_polled else "unavailable",
            "status": "live" if groups_polled else "unreachable",
            "source": "ServiceNow /api/now/table/incident",
        }
    except Exception as e:
        logger.warning("SNOW MIM evidence failed: %s", e)
        value = {"label": "MIM incidents (last 7d)", "value": "unavailable", "status": "error", "source": "ServiceNow", "error": str(e)[:200]}
    _cache_put("live_snow_mim", value)
    return value


# Live evidence is wired by id; seeded evidence is inlined.
LIVE_EVIDENCE: Dict[str, Callable[[], Dict[str, Any]]] = {
    "live_cs_fleet": _evidence_cs_fleet,
    "live_cs_rule_count": _evidence_cs_rule_count,
    "live_snow_mim": _evidence_snow_mim,
}

# Human-readable labels used in the 'loading' placeholder until the real
# value lands. Mirrors the labels the fetchers return so cells don't visually
# jump when they refresh.
_LIVE_EVIDENCE_LABELS: Dict[str, str] = {
    "live_cs_fleet": "CrowdStrike-managed endpoints",
    "live_cs_rule_count": "Active CS detective controls",
    "live_snow_mim": "MIM incidents (last 7d)",
}
_LIVE_EVIDENCE_SOURCES: Dict[str, str] = {
    "live_cs_fleet": "CrowdStrike Falcon",
    "live_cs_rule_count": "CrowdStrike Falcon",
    "live_snow_mim": "ServiceNow",
}

# Tracks which evidence ids currently have a background fetch in flight so
# we don't fire concurrent duplicates. The lock guards both the set and the
# transition from 'check cache → schedule fetch'.
_EVIDENCE_IN_FLIGHT: set = set()
_EVIDENCE_IN_FLIGHT_LOCK = Lock()


def _fetch_live_evidence_async(eid: str) -> None:
    """Spawn a daemon thread that runs the live-evidence fetcher, if one isn't already running."""
    fetcher = LIVE_EVIDENCE.get(eid)
    if not fetcher:
        return
    with _EVIDENCE_IN_FLIGHT_LOCK:
        if eid in _EVIDENCE_IN_FLIGHT:
            return
        _EVIDENCE_IN_FLIGHT.add(eid)

    def _run() -> None:
        try:
            fetcher()  # populates _EVIDENCE_CACHE as a side effect
        except Exception:
            logger.exception("Background evidence fetch failed for %s", eid)
        finally:
            with _EVIDENCE_IN_FLIGHT_LOCK:
                _EVIDENCE_IN_FLIGHT.discard(eid)

    threading.Thread(target=_run, name=f"ram-evidence-{eid}", daemon=True).start()


def _live_evidence_snapshot(eid: str) -> Dict[str, Any]:
    """Non-blocking accessor: returns the cached value, or a 'loading' placeholder
    while a background fetch fills it in. The request thread never makes the network call."""
    cached = _cache_get(eid)
    if cached is not None:
        return cached
    _fetch_live_evidence_async(eid)
    return {
        "label": _LIVE_EVIDENCE_LABELS.get(eid, eid),
        "value": "loading…",
        "status": "loading",
        "source": _LIVE_EVIDENCE_SOURCES.get(eid, "live"),
    }


def _start_evidence_warmup_once() -> None:
    """Kick off all live-evidence fetchers in parallel (idempotent — already-running ones are skipped)."""
    for eid in LIVE_EVIDENCE:
        _fetch_live_evidence_async(eid)

SEEDED_EVIDENCE: Dict[str, Dict[str, Any]] = {
    "seed_policy_catalog":      {"label": "Published policies", "value": "Sec-Pol catalog v2026.Q1 (demo)", "source": "Security Policy team (placeholder)"},
    "seed_rr_dpo_gap":          {"label": "EU DPO assignment", "value": "Designated for DE/IE only (demo)", "source": "Legal/Privacy (placeholder)"},
    "seed_cmdb_total":          {"label": "CMDB asset count",  "value": "~42,000 CIs (demo)", "source": "ServiceNow CMDB (placeholder — wire to live in v2)"},
    "seed_dpia_coverage":       {"label": "DPIAs completed",   "value": "63% of in-scope systems (demo)", "source": "Privacy Office (placeholder)"},
    "seed_risk_program":        {"label": "Annual risk assessment", "value": "FY26 complete (demo)", "source": "Risk Mgmt (placeholder)"},
    "seed_iam_mfa_rate":        {"label": "MFA enforcement",   "value": "98.4% of workforce (demo)", "source": "IAM team (placeholder — wire to PAM in v2)"},
    "seed_varonis_classified_pct": {"label": "Sensitive data classified", "value": "71% of file shares (demo)", "source": "Varonis (placeholder — wire to live in v2; client today is per-incident)"},
    "seed_dlp_alerts":          {"label": "DLP alerts last 30d", "value": "1,247 triaged (demo)", "source": "DLP platform (placeholder)"},
    "seed_encryption_at_rest":  {"label": "Encryption at rest", "value": "AES-256 fleet-wide (demo)", "source": "Endpoint team (placeholder)"},
    "seed_siem_volume":         {"label": "SIEM ingest",       "value": "~14 TB/day (demo)", "source": "QRadar/Splunk (placeholder)"},
    "seed_anomaly_program":     {"label": "UEBA coverage",     "value": "Vectra + Varonis (demo)", "source": "Detection eng (placeholder)"},
    "seed_ir_playbook":         {"label": "IR playbooks",      "value": "XSOAR — 47 active (demo)", "source": "XSOAR (placeholder — wire to live in v2)"},
    "seed_containment_rate":    {"label": "Containment MTTR",  "value": "median 38 min (demo)", "source": "XSOAR metrics (placeholder)"},
    "seed_dr_test_cadence":     {"label": "DR test cadence",   "value": "Semi-annual (demo)", "source": "Resilience team (placeholder)"},
}


def _resolve_evidence(evidence_ids: List[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for eid in evidence_ids:
        if eid in LIVE_EVIDENCE:
            ev = dict(_live_evidence_snapshot(eid))
            ev["id"] = eid
            ev["kind"] = "live"
            out.append(ev)
        elif eid in SEEDED_EVIDENCE:
            ev = dict(SEEDED_EVIDENCE[eid])
            ev["id"] = eid
            ev["kind"] = "seeded"
            ev["status"] = "seeded"
            out.append(ev)
        else:
            logger.warning("Unknown evidence id: %s", eid)
    return out


def get_matrix_data() -> Dict[str, Any]:
    """Return the full crosswalk with evidence resolved (live or seeded).

    Live evidence is read from cache and returned as a 'loading' placeholder
    if absent; a background warmup is triggered for any missing entries so
    the next poll lands the real value. The request thread never blocks on
    CrowdStrike / ServiceNow.
    """
    _start_evidence_warmup_once()
    cells: Dict[str, Dict[str, Any]] = {}
    for family in CONTROL_FAMILIES:
        fid = family["id"]
        cells[fid] = {}
        for reg in REGULATIONS:
            rid = reg["id"]
            base = CROSSWALK.get(fid, {}).get(rid, {"coverage": "unknown", "citations": [], "evidence_ids": []})
            cells[fid][rid] = {
                "coverage": base["coverage"],
                "citations": base["citations"],
                "evidence": _resolve_evidence(base.get("evidence_ids", [])),
            }

    # Counts for header chips
    covered = partial = gap = unknown = 0
    for fam_cells in cells.values():
        for cell in fam_cells.values():
            cov = cell["coverage"]
            if cov == "covered":   covered += 1
            elif cov == "partial": partial += 1
            elif cov == "gap":     gap += 1
            else:                  unknown += 1

    return {
        "regulations": REGULATIONS,
        "control_families": CONTROL_FAMILIES,
        "cells": cells,
        "summary": {
            "covered": covered,
            "partial": partial,
            "gap": gap,
            "unknown": unknown,
            "total_cells": covered + partial + gap + unknown,
        },
    }


# Regulatory pulse — mock updates that look like what a real ingestion feed would
# surface. Marked clearly as demo content; production would pull from a real
# regulatory-change source (OneTrust, LexisNexis, Federal Register, etc.).
PULSE_FEED: List[Dict[str, Any]] = [
    {
        "id": "ccpa_ab947",
        "regulation": "CCPA",
        "title": "CCPA Amendment AB-947 — expanded \"sensitive personal information\"",
        "summary": "California AB-947 expands SPI to include immigration status and citizenship; controllers must update consumer notices, opt-out flows, and data inventories.",
        "effective_date": "2026-08-01",
        "source_url": "https://leginfo.legislature.ca.gov/ (demo placeholder)",
        "published": "2026-05-02",
        "likely_affects": ["ID.AM", "PR.DS", "GV.PO"],
    },
    {
        "id": "eu_ai_act_impl",
        "regulation": "EU AI Act",
        "title": "EU AI Act — high-risk biometric systems implementing acts",
        "summary": "Commission published implementing acts under Art 6 covering high-risk biometric categorization; impacts any internal authn/UEBA platform using biometric features for EU subjects.",
        "effective_date": "2026-09-15",
        "source_url": "https://eur-lex.europa.eu/ (demo placeholder)",
        "published": "2026-04-29",
        "likely_affects": ["PR.AA", "DE.AE", "GV.RR"],
    },
    {
        "id": "hhs_hipaa_modern",
        "regulation": "HIPAA",
        "title": "HHS HIPAA Security Rule Modernization (NPRM)",
        "summary": "Proposed amendments make several previously \"addressable\" implementation specifications mandatory: encryption at rest, MFA for ePHI access, vulnerability scanning cadence.",
        "effective_date": "Proposed — comment period ends 2026-Q3",
        "source_url": "https://www.federalregister.gov/ (demo placeholder)",
        "published": "2026-04-18",
        "likely_affects": ["PR.DS", "PR.AA", "ID.RA"],
    },
    {
        "id": "nydfs_500_ai",
        "regulation": "NYDFS Part 500",
        "title": "NYDFS Cybersecurity Reg — AI Governance amendment",
        "summary": "Covered entities must establish documented AI governance with risk classification, model inventory, and CISO-attested controls over AI-assisted decisioning.",
        "effective_date": "2026-11-01",
        "source_url": "https://www.dfs.ny.gov/ (demo placeholder)",
        "published": "2026-04-25",
        "likely_affects": ["GV.PO", "GV.RR", "ID.RA"],
    },
]


def get_pulse_feed() -> List[Dict[str, Any]]:
    _start_pulse_warmup_once()
    return PULSE_FEED


# Cached LLM impact analyses, keyed by pulse id. the stakeholder should see the AI
# output upfront (per his ask) — the cache lets us pre-render on the page
# instead of forcing a click + 30s wait every time.
_IMPACT_CACHE: Dict[str, Dict[str, Any]] = {}
_IMPACT_CACHE_LOCK = Lock()
_WARMUP_STARTED = False
_WARMUP_LOCK = Lock()


def get_pulse_impacts() -> Dict[str, Dict[str, Any]]:
    """Snapshot of the cached impact analyses (pulse_id → impact or pending marker)."""
    _start_pulse_warmup_once()
    with _IMPACT_CACHE_LOCK:
        snapshot = {pid: dict(v) for pid, v in _IMPACT_CACHE.items()}
    # Mark any pulse that doesn't have an entry as 'pending' so the UI can show a spinner.
    for p in PULSE_FEED:
        snapshot.setdefault(p["id"], {"status": "pending"})
    return snapshot


def _start_pulse_warmup_once() -> None:
    """Kick off a background thread that pre-computes all pulse impacts.

    Idempotent: only the first caller starts the thread; subsequent calls
    are no-ops. Failures inside the worker fall back to leaving the cache
    empty for that pulse — the UI will treat that as 'pending' and the user
    can click Re-analyze to retry.
    """
    global _WARMUP_STARTED
    with _WARMUP_LOCK:
        if _WARMUP_STARTED:
            return
        _WARMUP_STARTED = True

    def _worker():
        logger.info("Pulse impact warmup starting (%d items)", len(PULSE_FEED))
        for pulse in PULSE_FEED:
            try:
                analyze_pulse_impact(pulse["id"], force=False)
            except Exception:
                logger.exception("Warmup failed for pulse %s", pulse["id"])
        logger.info("Pulse impact warmup complete")

    threading.Thread(target=_worker, name="ram-pulse-warmup", daemon=True).start()


def analyze_pulse_impact(pulse_id: str, force: bool = False) -> Dict[str, Any]:
    """Ask the LLM which crosswalk cells the regulatory update touches.

    The "AI wedge" of this product — everything else is GRC workflow.
    Cached by pulse_id; pass force=True to bust the cache (the Re-analyze button).
    """
    if not force:
        with _IMPACT_CACHE_LOCK:
            cached = _IMPACT_CACHE.get(pulse_id)
        if cached and cached.get("status") == "ready":
            return cached

    pulse = next((p for p in PULSE_FEED if p["id"] == pulse_id), None)
    if not pulse:
        return {"error": "unknown pulse id"}

    matrix = get_matrix_data()
    families_compact = "\n".join(f"- {f['id']}: {f['name']}" for f in matrix["control_families"])

    prompt = (
        "You are a regulatory analyst helping map a new regulatory update onto an existing control framework.\n\n"
        "## New regulatory update\n"
        f"- Regulation: {pulse['regulation']}\n"
        f"- Title: {pulse['title']}\n"
        f"- Summary: {pulse['summary']}\n"
        f"- Effective: {pulse['effective_date']}\n\n"
        "## Available control families (NIST CSF 2.0)\n"
        f"{families_compact}\n\n"
        "## Task\n"
        "Identify the 2–4 control families most affected. For each, give:\n"
        "1. The family id (exact, from the list above)\n"
        "2. A one-sentence rationale tying the regulation text to the control\n"
        "3. A specific suggested action (e.g., 'update data inventory schema to flag immigration-status fields')\n\n"
        "Respond as compact JSON: {\"affected\":[{\"family_id\":\"...\",\"rationale\":\"...\",\"action\":\"...\"}],\"headline\":\"one-sentence impact summary\"}\n"
        "JSON only — no prose, no code fences."
    )

    try:
        from my_bot.utils.llm_factory import create_llm
        llm = create_llm(temperature=0.1, max_tokens=2048)
        resp = llm.invoke(prompt)
        text = getattr(resp, "content", None) if resp else None
        if not text:
            result = {"status": "error", "pulse_id": pulse_id, "error": "empty LLM response"}
        else:
            import json, re
            m = re.search(r"\{.*\}", text, re.DOTALL)
            if not m:
                result = {"status": "error", "pulse_id": pulse_id, "error": "no JSON in LLM response", "raw": text[:500]}
            else:
                parsed = json.loads(m.group(0))
                result = {
                    "status": "ready",
                    "pulse_id": pulse_id,
                    "generated_at": time.strftime("%Y-%m-%d %H:%M"),
                    **parsed,
                }
    except Exception as e:
        logger.exception("Pulse impact analysis failed")
        result = {"status": "error", "pulse_id": pulse_id, "error": str(e)[:300]}

    with _IMPACT_CACHE_LOCK:
        _IMPACT_CACHE[pulse_id] = result
    return result


V2_QUESTIONS: List[Dict[str, str]] = [
    {
        "id": "control_inventory",
        "question": "Which control inventory should v2 join against?",
        "context": "v1 uses NIST CSF 2.0 as a proxy. If the company has an internal control catalog (e.g., from the Security Policy team or GRC tool), v2 should map to that so the rows match how the control-owner teams already speak.",
    },
    {
        "id": "posture_portal_overlap",
        "question": "How does this relate to the existing posture-management portal?",
        "context": "Potential overlap. If the posture portal already validates controls against frameworks, v2 should either (a) add a regulatory ingestion layer on top of it, or (b) carve a clean boundary (regulatory intelligence vs control posture).",
    },
    {
        "id": "regulation_scope",
        "question": "Which regulations matter most beyond GDPR / CCPA / HIPAA?",
        "context": "Candidates: NYDFS Part 500, SOX, GLBA, EU AI Act, state privacy laws (CO, VA, CT, TX), sector-specific (e.g., NAIC Model Law for insurance). Tell us which 5–10 to anchor the matrix.",
    },
    {
        "id": "update_feed",
        "question": "What's the source-of-truth feed for regulatory updates?",
        "context": "v1 uses 4 mock updates. Production candidates: OneTrust DataGuidance, LexisNexis Regulatory, Federal Register API, agency-specific RSS. Or does Legal/Compliance already curate a feed we should consume?",
    },
    {
        "id": "row_ownership",
        "question": "Who owns each control family row?",
        "context": "v1 has no owners. Gaps don't close without accountability — should ownership come from the EAI app inventory, the GRC tool, or a separate mapping?",
    },
    {
        "id": "gap_workflow",
        "question": "When a gap is identified, what's the workflow?",
        "context": "Options: (a) auto-create ServiceNow GRC ticket assigned to row owner, (b) propose ticket + require analyst sign-off, (c) read-only dashboard with no workflow. v1 has no workflow — pick the v2 shape.",
    },
    {
        "id": "deliverable_cadence",
        "question": "What's the deliverable cadence and audience?",
        "context": "Live dashboard for leadership? Quarterly board pack PDF? Event-driven Webex when a regulation lands? Drives whether v2 invests in scheduled exports vs interactive UI.",
    },
    {
        "id": "ai_value_check",
        "question": "Where is AI doing real work in v2?",
        "context": "v1 puts AI on the impact-diff loop (new regulation → affected control rows + suggested actions). Other candidates: auto-summarizing legal text, extracting obligations from policy PDFs, drafting gap-remediation tickets. Confirm before scope creeps.",
    },
]


def get_v2_questions() -> List[Dict[str, str]]:
    return V2_QUESTIONS
