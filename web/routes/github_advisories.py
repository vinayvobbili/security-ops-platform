"""Cyber Security Advisories triage UI (multi-source).

Reads are public so a reviewer clicking through from the alert email lands
straight on the advisory; the mutating actions (save notes, close, escalate to
the Package Compromise Assessment Teams channel) require a logged-in user, who
becomes the recorded reviewer/reporter.

Advisories come from several feeds — GitHub reviewed/malware, OSV malicious
packages (per ecosystem), CISA KEV, plus any user-added RSS feeds or OSV
ecosystems managed from the Sources modal. Each row is addressed by its native
id (GHSA-…, MAL-…, CVE-…); the DB resolves that to the internal uid via the
alias table, so old ``/cs-advisories/GHSA-xxxx`` links keep working. The page
was renamed from ``/gh-advisory`` → ``/cs-advisories``; the old paths 301-redirect.

Routes:
    GET  /cs-advisories                       queue / list page
    GET  /cs-advisories/<key>                 detail page (key = native id or uid)
    GET  /api/cs-advisories/sources           list sources + enabled state
    POST /api/cs-advisories/sources/<key>     enable/disable a source
    POST /api/cs-advisories/sources/add       add an RSS feed or OSV ecosystem
    POST /api/cs-advisories/sources/remove    remove a user-added source
    POST /api/cs-advisories/sources/request   ping the team for a source needing code
    POST /api/cs-advisories/<key>/notes       save reviewer notes
    POST /api/cs-advisories/<key>/close       close as not-worth-reporting
    POST /api/cs-advisories/<key>/reopen      back to under_review
    POST /api/cs-advisories/<key>/report      notify Teams + mark reported (idempotent)
    GET  /gh-advisory[/<key>]                 legacy 301 → /cs-advisories
"""
from __future__ import annotations

import logging
import re

from flask import Blueprint, abort, jsonify, redirect, render_template, request, url_for

from my_config import get_config
from services import github_advisories as ga
from services import github_advisories_db as db
from src.utils.logging_utils import log_web_activity
from web.auth.helpers import current_user, login_required
from web.auth.rbac import require_capability, SEND_EXTERNAL

logger = logging.getLogger(__name__)
CONFIG = get_config()

github_advisories_bp = Blueprint("github_advisories", __name__)

MAX_NOTES_LEN = 5000


def _label_for(source: str) -> str:
    return ga.source_labels_map().get(source, source or "—")


# ---------------------------------------------------------------------------
# Legacy redirects — the page was renamed /gh-advisory → /cs-advisories.
# Old email/Webex links and bookmarks 301 to the new path so they keep working.
# ---------------------------------------------------------------------------
@github_advisories_bp.route("/gh-advisory")
def _legacy_list():
    return redirect(url_for("github_advisories.advisory_list"), code=301)


@github_advisories_bp.route("/gh-advisory/<key>")
def _legacy_detail(key):
    return redirect(url_for("github_advisories.advisory_detail", key=key), code=301)


# ---------------------------------------------------------------------------
# Pages (public read)
# ---------------------------------------------------------------------------
@github_advisories_bp.route("/cs-advisories")
@log_web_activity
def advisory_list():
    advisories = db.list_advisories()
    labels = ga.source_labels_map()
    for a in advisories:
        a["source_label"] = labels.get(a.get("source"), a.get("source") or "—")
    src_counts = db.source_counts()
    sources_state = _sources_state()
    # Source-filter chips: only sources that actually have visible rows.
    source_labels = {s["key"]: s["label"] for s in sources_state if s["count"]}
    counts = db.status_counts()
    return render_template(
        "gh_advisory_list.html",
        advisories=advisories,
        counts=counts,
        source_counts=src_counts,
        source_labels=source_labels,
        sources_state=sources_state,
        addable_ecosystems=list(ga.OSV_ADDABLE_ECOSYSTEMS),
        chat_context=_list_chat_context(advisories, counts),
    )


@github_advisories_bp.route("/cs-advisories/<key>")
@log_web_activity
def advisory_detail(key):
    adv = db.get_advisory(key)
    if not adv:
        abort(404)
    adv["source_label"] = _label_for(adv.get("source"))
    vulns = _affected(adv)
    cvss = _cvss(adv)
    references = _references(adv)
    cwes = _cwes(adv)
    return render_template(
        "gh_advisory_detail.html",
        adv=adv,
        vulns=vulns,
        cvss=cvss,
        references=references,
        cwes=cwes,
        teams_channel=CONFIG.package_compromise_teams_channel or "Package Compromise Assessment",
        veracode_cves=ga._advisory_cves(adv),
        veracode_packages=ga._advisory_packages(adv),
        chat_context=_detail_chat_context(adv, vulns, cvss, references, cwes),
    )


def _list_chat_context(advisories: list[dict], counts: dict) -> str:
    lines = [
        "This is the Cyber Security Advisories triage queue. It aggregates "
        "advisories from GitHub (reviewed + malware), OSV malicious packages, "
        "CISA KEV, and any user-added RSS/OSV sources.",
        f"Status counts: {counts}.",
        f"Showing {len(advisories)} advisories:",
    ]
    for a in advisories[:200]:
        pkgs = ", ".join(a.get("packages") or [])[:140]
        lines.append(
            f"- [{a.get('source_label')}] {a.get('source_id')} "
            f"({a.get('cve_id') or 'no CVE'}) status={a.get('status')} "
            f"severity={a.get('severity')} packages=[{pkgs}] :: {a.get('summary')}"
        )
    return "\n".join(lines)


def _detail_chat_context(adv: dict, vulns: list, cvss: dict, references: list, cwes: list) -> str:
    pkgs = "; ".join(f"{v['package']} (vuln: {v['vulnerable_range']}, fixed: {v['first_patched']})" for v in vulns)
    return (
        f"Cyber Security Advisory {adv.get('source_id')} from {adv.get('source_label')}.\n"
        f"CVE: {adv.get('cve_id') or 'none'} | Severity: {adv.get('severity')} | "
        f"Ecosystem: {adv.get('ecosystem') or 'n/a'} | Published: {(adv.get('published_at') or '')[:10]}\n"
        f"CVSS: {cvss.get('score') or ''} {cvss.get('vector') or ''}\n"
        f"CWEs: {', '.join(cwes) or 'none'}\n"
        f"Aliases: {', '.join(adv.get('aliases') or [])}\n"
        f"Status: {adv.get('status')} | Reviewer notes: {adv.get('notes') or '(none)'}\n\n"
        f"Summary: {adv.get('summary')}\n\n"
        f"Affected packages: {pkgs or 'n/a'}\n\n"
        f"Description:\n{adv.get('description') or '(none)'}\n\n"
        f"References: {', '.join(references[:15])}"
    )


# ---------------------------------------------------------------------------
# Sources modal — list / toggle / add / remove / request
# ---------------------------------------------------------------------------
def _sources_state() -> list[dict]:
    counts = db.source_counts()
    specs = ga.get_source_specs()
    enabled = db.get_sources_enabled([s["key"] for s in specs])
    out = []
    for s in specs:
        out.append({
            "key": s["key"], "label": s["label"], "type": s["type"],
            "builtin": s.get("builtin", False), "config": s.get("config") or {},
            "enabled": enabled.get(s["key"], True), "count": counts.get(s["key"], 0),
        })
    return out


@github_advisories_bp.route("/api/cs-advisories/sources")
@log_web_activity
def api_sources():
    return jsonify({"ok": True, "sources": _sources_state(),
                    "addable_ecosystems": list(ga.OSV_ADDABLE_ECOSYSTEMS)})


@github_advisories_bp.route("/api/cs-advisories/sources/add", methods=["POST"])
@login_required
def api_add_source():
    body = request.get_json(silent=True) or {}
    stype = (body.get("type") or "").strip()
    keys = {s["key"] for s in ga.get_source_specs()}

    if stype == "osv":
        eco = (body.get("ecosystem") or "").strip()
        if eco not in ga.OSV_ADDABLE_ECOSYSTEMS:
            return jsonify({"ok": False, "error": "unsupported ecosystem"}), 400
        key = "osv_" + re.sub(r"[^a-z0-9]+", "_", eco.lower()).strip("_")
        if key in keys:
            return jsonify({"ok": False, "error": "source already exists"}), 409
        db.add_custom_source(key, "osv", f"OSV {eco}", {"ecosystem": eco}, _user_email())

    elif stype == "rss":
        url = (body.get("url") or "").strip()
        label = (body.get("label") or "").strip()
        if not re.match(r"^https?://", url):
            return jsonify({"ok": False, "error": "a valid http(s) feed URL is required"}), 400
        if not label:
            return jsonify({"ok": False, "error": "a label is required"}), 400
        key = "rss_" + re.sub(r"[^a-z0-9]+", "_", url.lower()).strip("_")[:48]
        if key in keys:
            return jsonify({"ok": False, "error": "that feed is already a source"}), 409
        db.add_custom_source(key, "rss", label, {"url": url}, _user_email())

    else:
        return jsonify({"ok": False, "error": "type must be 'osv' or 'rss'"}), 400

    logger.info("[Advisories] Source %r (%s) added by %s", key, stype, _user_email())
    return jsonify({"ok": True, "sources": _sources_state()})


@github_advisories_bp.route("/api/cs-advisories/sources/remove", methods=["POST"])
@login_required
def api_remove_source():
    key = (request.get_json(silent=True) or {}).get("key", "")
    if ga.is_builtin(key):
        return jsonify({"ok": False, "error": "built-in sources can't be removed — disable it instead"}), 400
    if not db.remove_custom_source(key):
        return jsonify({"ok": False, "error": "source not found"}), 404
    logger.info("[Advisories] Source %r removed by %s", key, _user_email())
    return jsonify({"ok": True, "sources": _sources_state()})


@github_advisories_bp.route("/api/cs-advisories/sources/request", methods=["POST"])
@require_capability(SEND_EXTERNAL)
def api_request_source():
    desc = ((request.get_json(silent=True) or {}).get("description") or "").strip()
    if len(desc) < 5:
        return jsonify({"ok": False, "error": "describe the source you want"}), 400
    try:
        sent = ga.notify_source_request(desc, _user_email())
    except Exception as e:
        logger.error("[Advisories] Source request notify failed: %s", e, exc_info=True)
        return jsonify({"ok": False, "error": f"could not send request: {e}"}), 502
    if not sent:
        return jsonify({"ok": False, "error": "Webex not configured; request not sent"}), 503
    return jsonify({"ok": True})


@github_advisories_bp.route("/api/cs-advisories/sources/<key>", methods=["POST"])
@login_required
def api_set_source(key):
    if key not in {s["key"] for s in ga.get_source_specs()}:
        return jsonify({"ok": False, "error": "unknown source"}), 404
    enabled = bool((request.get_json(silent=True) or {}).get("enabled", True))
    db.set_source_enabled(key, enabled)
    logger.info("[Advisories] Source %r %s by %s", key, "enabled" if enabled else "disabled", _user_email())
    return jsonify({"ok": True, "key": key, "enabled": enabled})


# ---------------------------------------------------------------------------
# Mutations (login required)
# ---------------------------------------------------------------------------
@github_advisories_bp.route("/api/cs-advisories/<key>/notes", methods=["POST"])
@login_required
def api_save_notes(key):
    notes = (request.get_json(silent=True) or {}).get("notes", "")
    if not isinstance(notes, str):
        return jsonify({"ok": False, "error": "notes must be a string"}), 400
    notes = notes.strip()[:MAX_NOTES_LEN]
    if not db.save_notes(key, notes, _user_email()):
        return jsonify({"ok": False, "error": "advisory not found"}), 404
    return jsonify({"ok": True, "advisory": db.get_advisory(key)})


@github_advisories_bp.route("/api/cs-advisories/<key>/close", methods=["POST"])
@login_required
def api_close(key):
    if not db.get_advisory(key):
        return jsonify({"ok": False, "error": "advisory not found"}), 404
    # Persist any notes sent alongside the close in the same request.
    notes = (request.get_json(silent=True) or {}).get("notes")
    if isinstance(notes, str):
        db.save_notes(key, notes.strip()[:MAX_NOTES_LEN], _user_email())
    db.set_status(key, "closed_not_reported", _user_email())
    return jsonify({"ok": True, "advisory": db.get_advisory(key)})


@github_advisories_bp.route("/api/cs-advisories/<key>/reopen", methods=["POST"])
@login_required
def api_reopen(key):
    adv = db.get_advisory(key)
    if not adv:
        return jsonify({"ok": False, "error": "advisory not found"}), 404
    if adv["status"] == "reported":
        return jsonify({"ok": False, "error": "already reported — cannot reopen"}), 409
    db.set_status(key, "under_review", _user_email())
    return jsonify({"ok": True, "advisory": db.get_advisory(key)})


@github_advisories_bp.route("/api/cs-advisories/<key>/ai-triage", methods=["POST"])
@login_required
def api_ai_triage(key):
    """Generate (and cache) an LLM triage assessment for one advisory."""
    adv = db.get_advisory(key)
    if not adv:
        return jsonify({"ok": False, "error": "advisory not found"}), 404
    try:
        assessment = ga.generate_ai_triage(adv)
    except Exception as e:
        logger.error("[Advisories] AI triage error for %s: %s", key, e, exc_info=True)
        return jsonify({"ok": False, "error": f"AI triage failed: {e}"}), 502
    db.save_ai_assessment(adv["uid"], assessment)
    return jsonify({"ok": True, "assessment": assessment})


@github_advisories_bp.route("/api/cs-advisories/<key>/veracode-check", methods=["POST"])
@login_required
def api_veracode_check(key):
    """On-demand Veracode SCA check: which of our apps carry the vulnerable component."""
    adv = db.get_advisory(key)
    if not adv:
        return jsonify({"ok": False, "error": "advisory not found"}), 404
    cves = ga._advisory_cves(adv)
    packages = ga._advisory_packages(adv)
    if not cves and not packages:
        return jsonify({"ok": False, "error": "advisory has no CVE or package to check"}), 400
    try:
        from services.veracode import get_client
        client = get_client()
        if not client.is_configured():
            return jsonify({"ok": False, "error": "Veracode API not configured"}), 503
        result = client.exposure(cve_ids=cves, packages=packages)
    except Exception as e:
        logger.error("[Advisories] Veracode check error for %s: %s", key, e, exc_info=True)
        return jsonify({"ok": False, "error": f"Veracode check failed: {e}"}), 502
    db.save_veracode_enrichment(adv["uid"], result)
    return jsonify({"ok": True, "veracode": result})


@github_advisories_bp.route("/api/cs-advisories/<key>/report", methods=["POST"])
@require_capability(SEND_EXTERNAL)
def api_report(key):
    """Escalate to the Package Compromise Assessment Teams channel, then mark
    reported. Idempotent: a second click won't re-send to Teams."""
    adv = db.get_advisory(key)
    if not adv:
        return jsonify({"ok": False, "error": "advisory not found"}), 404

    # The UI button is disabled in dev; this guards the API path too, so a
    # non-prod instance can never fire a real Teams escalation (the Teams send
    # always hits prod XSOAR regardless of which instance calls it).
    if not CONFIG.is_production:
        return jsonify({"ok": False, "error": "escalation_disabled_in_dev",
                        "warning": f"Teams escalation is disabled on the {CONFIG.environment} instance."}), 403

    user = _user_email()
    notes = (request.get_json(silent=True) or {}).get("notes")
    if isinstance(notes, str):
        db.save_notes(key, notes.strip()[:MAX_NOTES_LEN], user)
        adv = db.get_advisory(key)

    # Claim the report first; if it's already reported, mark_reported returns
    # False and we don't double-send to Teams.
    if not db.mark_reported(key, user):
        return jsonify({"ok": False, "error": "already_reported",
                        "advisory": adv}), 409

    channel = CONFIG.package_compromise_teams_channel
    if not channel:
        logger.warning("[Advisories] PACKAGE_COMPROMISE_TEAMS_CHANNEL not set — marked reported without Teams send")
        return jsonify({"ok": True, "teams_sent": False,
                        "warning": "Teams channel not configured; marked reported only.",
                        "advisory": db.get_advisory(key)})

    try:
        from services.xsoar_teams import send_teams_message  # lazy: pulls XSOAR client
        send_teams_message(
            _teams_message(adv, user),
            channel=channel,
            team=CONFIG.package_compromise_teams_team or None,
        )
    except Exception as e:
        logger.error("[Advisories] Teams escalation failed for %s: %s", key, e, exc_info=True)
        return jsonify({"ok": False, "error": f"Teams send failed: {e}",
                        "advisory": db.get_advisory(key)}), 502

    logger.info("[Advisories] %s escalated to Teams channel %r by %s", adv.get("uid"), channel, user)
    return jsonify({"ok": True, "teams_sent": True, "advisory": db.get_advisory(key)})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _user_email() -> str:
    user = current_user()
    return (user or {}).get("email") or "unknown"


def _teams_message(adv: dict, user: str) -> str:
    cvss = _cvss(adv)
    score = f" · CVSS {cvss['score']}" if cvss.get("score") else ""
    source = _label_for(adv.get("source"))
    pkgs = ", ".join(adv.get("packages") or [])[:300] or "—"
    notes = (adv.get("notes") or "").strip()
    notes_block = f"\n\n**Reviewer notes:**\n{notes}" if notes else ""
    return (
        f"🚨 **Package Compromise Assessment requested**\n\n"
        f"**{adv['source_id']}** ({adv.get('cve_id') or 'no CVE'}){score} · _{source}_\n"
        f"{adv.get('summary') or ''}\n\n"
        f"**Affected packages:** {pkgs}\n"
        f"**Advisory:** {adv.get('html_url') or ''}"
        f"{notes_block}\n\n"
        f"_Escalated by {user}._"
    )


def _affected(adv: dict) -> list[dict]:
    """Affected-package rows. GitHub advisories carry version ranges; OSV/KEV
    just give package names, so the range columns fall back to em-dashes."""
    raw = adv.get("raw") or {}
    rows = []
    if raw.get("vulnerabilities"):  # GitHub shape
        for v in raw["vulnerabilities"]:
            pkg = v.get("package") or {}
            name = pkg.get("name") or "?"
            eco = pkg.get("ecosystem") or ""
            rows.append({
                "package": f"{name} ({eco})" if eco else name,
                "vulnerable_range": v.get("vulnerable_version_range") or "—",
                "first_patched": v.get("first_patched_version") or "—",
            })
        return rows
    if raw.get("affected"):  # OSV shape
        for aff in raw["affected"]:
            pkg = aff.get("package") or {}
            name = pkg.get("name") or "?"
            eco = pkg.get("ecosystem") or ""
            rows.append({"package": f"{name} ({eco})" if eco else name,
                         "vulnerable_range": "—", "first_patched": "—"})
        return rows
    # Fallback to the normalized package list (e.g. CISA KEV vendor/product).
    return [{"package": p, "vulnerable_range": "—", "first_patched": "—"} for p in adv.get("packages") or []]


def _cvss(adv: dict) -> dict:
    raw = adv.get("raw") or {}
    cvss = raw.get("cvss")
    if isinstance(cvss, dict) and (cvss.get("score") or cvss.get("vector_string")):
        return {"score": cvss.get("score"), "vector": cvss.get("vector_string")}
    # OSV carries severity as a LIST of {type, score(=vector string)} entries;
    # GitHub carries it as a plain string (e.g. "critical"), so guard the type.
    sev = raw.get("severity")
    if isinstance(sev, list):
        for s in sev:
            if isinstance(s, dict) and s.get("score"):
                return {"score": None, "vector": s.get("score")}
    return {"score": None, "vector": None}


def _references(adv: dict) -> list[str]:
    raw = adv.get("raw") or {}
    out = []
    for r in raw.get("references") or []:
        url = r.get("url") if isinstance(r, dict) else r
        if url:
            out.append(url)
    return out


def _cwes(adv: dict) -> list[str]:
    raw = adv.get("raw") or {}
    out = []
    for c in raw.get("cwes") or []:
        if isinstance(c, dict):
            label = c.get("cwe_id") or ""
            name = c.get("name") or ""
            out.append(f"{label} — {name}".strip(" —"))
    return out
