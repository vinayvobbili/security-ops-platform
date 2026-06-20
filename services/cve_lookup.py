"""Conversational CVE lookups for the Pokedex bot and MCP server.

Two read-mostly capabilities a SOC analyst would ask for in chat:

  * :func:`triage_lookup` — "what's our verdict / how bad is CVE-X for us?"
    Returns the stored triage verdict (priority P1-P4, remediation action, SLA,
    attack layer) when the CVE has already been triaged; otherwise falls back to
    the live, no-LLM facts (NVD CVSS, CISA KEV, EPSS, affected products, and the
    Veracode SCA affected-app count). The slow two-analyst LLM debate is NOT run
    here — that stays on the Vulnerability Deep Dive page / the batch job.

  * :func:`app_exposure` — "which of our applications are affected by CVE-X (or
    package Y)?" Thin wrapper over the Veracode SCA index (open findings only).

Each capability has a structured form (for MCP) and a ``*_text`` form (for the
Pokedex LLM). This module owns the formatting so both surfaces stay identical.
"""

import re
from typing import Optional

from services import cve_triage, veracode

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _norm_cve(cve_id: Optional[str]) -> Optional[str]:
    if cve_id is None or cve_id == "":
        return None
    m = _CVE_RE.search(str(cve_id).strip())
    return m.group(0).upper() if m else None


# ───────────────────────────── triage verdict ──────────────────────────────
def triage_lookup(cve_id: Optional[str]) -> dict:
    """Our triage verdict for a CVE, or the live facts if not yet triaged.

    Returns ``{found, cve_id, source, triaged, verdict?, facts?, error?}`` where
    ``source`` is "cached_verdict" or "live_facts".
    """
    cve = _norm_cve(cve_id)
    if not cve:
        return {"found": False, "query": cve_id,
                "error": "not a valid CVE id (expected e.g. 'CVE-2025-24813')"}

    cached = cve_triage.get_cached_triage(cve)
    if cached:
        return {
            "found": True,
            "cve_id": cve,
            "source": "cached_verdict",
            "triaged": True,
            "verdict": {
                "priority": cached.get("priority"),
                "sla_days": cached.get("sla_days"),
                "remediation_required": bool(cached.get("remediation_required")),
                "recommended_action": cached.get("recommended_action"),
                "component": cached.get("component"),
                "affected_versions": cached.get("affected_versions"),
                "attack_layer": cached.get("attack_layer"),
                "confidence": cached.get("confidence"),
                "rationale": cached.get("rationale"),
                "must_act": cached.get("must_act"),
                "kev": bool(cached.get("kev")),
                "epss": cached.get("epss"),
                "cvss": cached.get("cvss"),
                "veracode_affected_apps": cached.get("veracode_apps"),
            },
        }

    # Not triaged yet — gather the live, no-LLM facts an analyst would look up.
    try:
        facts = cve_triage.gather_facts(cve)
    except Exception as e:  # noqa: BLE001 — never let an upstream fetch break the tool
        return {"found": False, "cve_id": cve, "error": f"fact lookup failed: {e}"}

    return {
        "found": facts.get("nvd_found") or facts.get("cveorg_found"),
        "cve_id": cve,
        "source": "live_facts",
        "triaged": False,
        "facts": facts,
    }


def triage_text(cve_id: Optional[str]) -> str:
    """Human-readable :func:`triage_lookup` for the Pokedex LLM."""
    r = triage_lookup(cve_id)
    if not r.get("found"):
        return f"CVE triage lookup for '{cve_id}': {r.get('error', 'no record found in NVD or CVE.org')}."

    cve = r["cve_id"]
    if r["source"] == "cached_verdict":
        v = r["verdict"]
        lines = [f"{cve} — our triage verdict (already triaged):"]
        if v.get("priority"):
            sla = f", SLA {v['sla_days']}d" if v.get("sla_days") is not None else ""
            lines.append(f"  Priority: {v['priority']}{sla}")
        lines.append(f"  Remediation required: {'YES' if v['remediation_required'] else 'no'}")
        if v.get("recommended_action"):
            lines.append(f"  Recommended action: {v['recommended_action']}")
        if v.get("component"):
            ver = f" ({v['affected_versions']})" if v.get("affected_versions") else ""
            lines.append(f"  Affected component: {v['component']}{ver}")
        if v.get("attack_layer"):
            lines.append(f"  Attack layer: {v['attack_layer']}")
        risk = []
        if v.get("cvss") is not None:
            risk.append(f"CVSS {v['cvss']}")
        if v.get("kev"):
            risk.append("on CISA KEV (known-exploited)")
        if isinstance(v.get("epss"), (int, float)):
            risk.append(f"EPSS {v['epss']:.1%}")
        if risk:
            lines.append(f"  Risk signals: {', '.join(risk)}")
        if v.get("veracode_affected_apps"):
            lines.append(f"  Veracode SCA: {v['veracode_affected_apps']} application(s) affected "
                         f"(use the app-exposure lookup for the list)")
        if v.get("confidence"):
            lines.append(f"  Confidence: {v['confidence']}")
        if v.get("rationale"):
            lines.append(f"  Rationale: {v['rationale']}")
        return "\n".join(lines)

    # live facts (not yet triaged)
    f = r["facts"]
    cvss = f.get("cvss") or {}
    lines = [f"{cve} — not yet triaged; live facts (NVD/CVE.org):"]
    score = cvss.get("base_score")
    sev = cvss.get("base_severity")
    if score is not None or sev:
        lines.append(f"  CVSS: {score if score is not None else '?'} ({sev or '?'})")
    lines.append(f"  Known-exploited (CISA KEV): {'YES' if f.get('kev') else 'no'}")
    if isinstance(f.get("epss"), (int, float)):
        lines.append(f"  EPSS (30-day exploit probability): {f['epss']:.1%}")
    prods = f.get("cpe_products") or []
    if prods:
        lines.append(f"  Affected products: {', '.join(prods[:8])}{' …' if len(prods) > 8 else ''}")
    if f.get("veracode_matched"):
        lines.append(f"  Veracode SCA: {f.get('veracode_affected_app_count', 0)} application(s) carry "
                     f"an affected component (use the app-exposure lookup for the list)")
    else:
        lines.append("  Veracode SCA: no application in the portfolio matched (per open SCA findings)")
    desc = (f.get("description") or "").strip()
    if desc:
        lines.append(f"  Description: {desc[:400]}{' …' if len(desc) > 400 else ''}")
    lines.append("  (No remediation verdict yet — run it on the Vulnerability Deep Dive page for a full LLM triage.)")
    return "\n".join(lines)


# ──────────────────────────── app exposure (SCA) ───────────────────────────
def app_exposure(query: Optional[str]) -> dict:
    """Which applications are affected by a CVE or carry a named package.

    Routes a CVE-looking query to the CVE axis and anything else to the package
    axis of the Veracode SCA index. Returns the raw Veracode exposure dict
    (``{affected_app_count, exposed, cves|packages, summary_text, ...}``).
    """
    raw = "" if query is None else str(query).strip()
    if not raw:
        return {"exposed": False, "error": "empty query"}
    cve = _norm_cve(raw)
    try:
        if cve:
            return veracode.cve_exposure([cve])
        return veracode.component_exposure([raw])
    except Exception as e:  # noqa: BLE001
        return {"exposed": False, "error": f"Veracode exposure lookup failed: {e}"}


def app_exposure_text(query: Optional[str]) -> str:
    """Human-readable :func:`app_exposure` for the Pokedex LLM."""
    r = app_exposure(query)
    if r.get("error"):
        return f"App-exposure lookup for '{query}': {r['error']}."
    if r.get("indexing"):
        return "The Veracode SCA index is building — check back in a few minutes."

    n = r.get("affected_app_count", 0)
    if not n:
        return (f"No applications in the Veracode portfolio carry a component matching "
                f"'{query}' (per open SCA findings). Note: a miss is not proof the package "
                f"is absent from every app's full SBOM.")

    # Flatten the exposures from whichever axis was queried.
    rows = []
    for _key, items in {**r.get("cves", {}), **r.get("packages", {})}.items():
        rows.extend(items)
    seen = set()
    lines = [f"'{query}' — {n} affected application(s) per Veracode SCA:"]
    for it in rows:
        app = it.get("application") or it.get("app_id") or "?"
        key = (app, it.get("component"), it.get("version"))
        if key in seen:
            continue
        seen.add(key)
        comp = it.get("component") or ""
        ver = f" {it['version']}" if it.get("version") else ""
        bu = f" — {it['business_unit']}" if it.get("business_unit") else ""
        sev = f" [{it['severity_label']}]" if it.get("severity_label") else ""
        lines.append(f"  • {app}{bu}: {comp}{ver}{sev}".rstrip())
        if len(lines) > 40:
            lines.append(f"  … (+{len(rows) - 40} more)")
            break
    return "\n".join(lines)
