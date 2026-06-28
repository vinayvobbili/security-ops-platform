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
import math
import re
from datetime import datetime, timedelta, timezone
from functools import wraps
from io import BytesIO

from flask import (Blueprint, abort, jsonify, make_response, redirect,
                   render_template, request, send_file, url_for)

from my_config import get_config
from web.config import EASTERN
from services import github_advisories as ga
from services import github_advisories_db as db
from src.utils.logging_utils import log_web_activity
from web.auth.helpers import current_user, is_admin, login_required
from web.auth.rbac import require_capability, has_capability, SEND_EXTERNAL

logger = logging.getLogger(__name__)
CONFIG = get_config()

github_advisories_bp = Blueprint("github_advisories", __name__)


def _parse_iso(raw):
    """Parse an ISO-8601 timestamp (with or without a trailing Z) to an aware
    UTC datetime, or None if it can't be parsed."""
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _owner_block(key):
    """Owner-only gate for advisory actions. Returns a JSON error response tuple
    when the logged-in user isn't the advisory's owner (admins always bypass),
    else None. Discussion (comments) and ownership-claim (assign) endpoints
    intentionally skip this — anyone signed in can join the discussion."""
    adv = db.get_advisory(key)
    if not adv:
        return jsonify({"ok": False, "error": "advisory not found"}), 404
    if is_admin():
        return None
    email = (_user_email() or "").strip().lower()
    owner = (adv.get("owner") or "").strip()
    if not owner:
        return jsonify({"ok": False, "error": "not_owned",
                        "warning": "Assign this advisory to yourself before acting on it."}), 403
    if owner.lower() != email:
        return jsonify({"ok": False, "error": "not_owner",
                        "warning": f"Only the owner ({owner}) can act on this advisory."}), 403
    return None


def owner_required(fn):
    """Decorator: enforce _owner_block before an advisory-action view runs.
    Stacks under @login_required so unauthenticated users are handled first."""
    @wraps(fn)
    def wrapper(key, *args, **kwargs):
        blocked = _owner_block(key)
        if blocked:
            return blocked
        return fn(key, *args, **kwargs)
    return wrapper

MAX_NOTES_LEN = 5000
MAX_TEAMS_MSG_LEN = 4000  # generous cap on an owner-edited Teams escalation body
MAX_XSOAR_DESC_LEN = 8000  # cap on an owner-edited XSOAR incident description

# Advisory severity → XSOAR numeric severity (0 unknown … 4 critical).
_XSOAR_SEV_NUM = {"critical": 4, "high": 3, "moderate": 2, "medium": 2, "low": 1}
MAX_COMMENT_LEN = 5000


def _label_for(source: str) -> str:
    return ga.source_labels_map().get(source, source or "—")


def _vc_app_count(vc):
    """Mirror the detail page's vcCount(): how many of our apps carry the
    affected package per Veracode SCA — the explicit count if present, else
    derived from the cve/package→application sets. None when Veracode never ran."""
    if not isinstance(vc, dict):
        return None
    n = vc.get("affected_app_count")
    if isinstance(n, int):
        return n
    apps = set()
    for group in ("cves", "packages"):
        for arr in (vc.get(group) or {}).values():
            for a in (arr or []):
                if isinstance(a, dict) and a.get("application"):
                    apps.add(a["application"])
    return len(apps)


def _exposure_verdict(adv: dict) -> dict:
    """Server-side twin of the detail page's exposure-band verdict, from the
    cached Veracode SCA signal ONLY (no lens is run here). Returns
    ``{"state": "exposed"|"clear"|"unchecked", "apps": int}``.

    - exposed:  Veracode SCA shows >=1 affected app.
    - clear:    Veracode SCA ran and found no affected app.
    - unchecked: Veracode hasn't run yet (the common case for a row nobody has
      opened) — we deliberately never imply "safe" from a non-check.
    """
    vc = adv.get("veracode_enrichment")
    vc_apps = _vc_app_count(vc)
    if (vc_apps or 0) > 0:
        return {"state": "exposed", "apps": int(vc_apps)}
    return {"state": "clear" if vc is not None else "unchecked", "apps": 0}


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
    archived_view = request.args.get("archived") in ("1", "true", "yes")
    advisories = db.list_advisories(only_archived=archived_view)
    labels = ga.source_labels_map()
    # Cross-source corroboration computed over the full active corpus (not just
    # the filtered view) so a row still shows it was confirmed elsewhere.
    corr_corpus = advisories if archived_view else db.list_advisories()
    corr = ga.compute_corroboration(corr_corpus)
    # Exposure verdict surfaced at the list level from the cached Veracode SCA
    # signal on each row (no lens re-run), so the "How does this affect us?"
    # answer is visible without opening every advisory.
    exposure_count = 0
    _now = datetime.now(timezone.utc)
    for a in advisories:
        a["source_label"] = labels.get(a.get("source"), a.get("source") or "—")
        a["corroboration"] = corr.get(a.get("uid") or a.get("source_id"))
        a["exposure"] = _exposure_verdict(a)
        if a["exposure"]["state"] == "exposed":
            exposure_count += 1
        # Per-row age + auto-archive countdown. Age is from first_seen_at; the
        # countdown only applies to rows the daily job will actually archive
        # (unowned, not seeded/reported) — cutoff = first_seen + 3 days.
        a["age_days"] = a["archive_in_days"] = None
        _seen = _parse_iso(a.get("first_seen_at"))
        if _seen:
            a["age_days"] = max(0, (_now - _seen).days)
            archivable = (not (a.get("owner") or "").strip()
                          and a.get("status") not in ("seeded", "reported"))
            if archivable and not archived_view:
                a["archive_in_days"] = math.ceil(
                    (_seen + timedelta(days=3) - _now).total_seconds() / 86400)
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
        archived_view=archived_view,
        archived_count=db.archived_count(),
        assessment_statuses=ASSESSMENT_STATUSES,
        signoff_teams=db.list_signoff_teams(),
        kpis=db.risk_kpis(),
        exposure_count=exposure_count,
        outcome_counts=db.escalation_outcome_counts(),
        is_authenticated=bool(current_user()),
        current_owner=((_user_email() or "").strip().lower() if current_user() else ""),
        posture=db.posture_kpis(),
        # Campaigns over the active corpus on the live queue; over the archived
        # corpus in the archive view so past/expired campaigns stay viewable
        # (list_advisories caps at 500, so the clustering stays cheap).
        campaigns=ga.compute_campaigns(corr_corpus),
        aging_cutoff=(datetime.now(timezone.utc) - timedelta(days=3)).isoformat(
            timespec="seconds").replace("+00:00", "Z"),
        chat_context=_list_chat_context(advisories, counts),
    )


@github_advisories_bp.route("/cs-advisories/export.csv")
@log_web_activity
def advisory_export_csv():
    """Export the advisory queue as CSV for offline triage / reporting. Honors the
    ``archived`` view; one row per advisory with the fields analysts ask for."""
    import csv
    from io import StringIO
    archived_view = request.args.get("archived") in ("1", "true", "yes")
    advisories = db.list_advisories(only_archived=archived_view)
    labels = ga.source_labels_map()
    corr = ga.compute_corroboration(db.list_advisories())
    buf = StringIO()
    w = csv.writer(buf)
    team_labels = {t["team"]: t["label"] for t in db.list_signoff_teams()}
    w.writerow(["source", "source_id", "cve_id", "severity", "status", "owner",
                "published_at", "first_seen_at", "packages", "package_urls",
                "repo_urls", "team_signoffs", "teams_cleared", "corroborated_sources",
                "summary", "url"])
    for a in advisories:
        c = corr.get(a.get("uid") or a.get("source_id"))
        links = ga.advisory_package_links(a)
        pkg_urls = "; ".join(f"{l['name']} {l['registry_url']}".strip()
                             for l in links if l.get("registry_url"))
        repo_urls = "; ".join(sorted({l["repo_url"] for l in links if l.get("repo_url")}))
        sos = db.get_team_signoffs(a.get("source_id") or a.get("uid"))
        signoff_cell = "; ".join(
            f"{team_labels.get(team, team)}:{so.get('status', 'pending')}"
            for team, so in sos.items() if so.get("status") and so.get("status") != "pending")
        teams_cleared = sum(1 for so in sos.values() if so.get("status") == "clear")
        w.writerow([
            labels.get(a.get("source"), a.get("source") or ""),
            a.get("source_id") or "", a.get("cve_id") or "", a.get("severity") or "",
            a.get("status") or "", a.get("owner") or "",
            (a.get("published_at") or "")[:10], (a.get("first_seen_at") or "")[:10],
            "; ".join(a.get("packages") or []),
            pkg_urls,
            repo_urls,
            signoff_cell,
            teams_cleared,
            "; ".join(c["sources"]) if c else "",
            (a.get("summary") or "").replace("\n", " ")[:500],
            a.get("html_url") or "",
        ])
    ts = datetime.now(EASTERN).strftime("%Y%m%d-%H%M")
    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = (
        f'attachment; filename="cs-advisories{"-archived" if archived_view else ""}-{ts}.csv"')
    return resp


def _metrics_payload() -> dict:
    """Compose the metrics dashboard / BI-feed payload: aggregate breakdowns
    (db.metrics_summary) + operating-tempo medians (db.posture_kpis), with raw
    source keys mapped to friendly labels."""
    m = db.metrics_summary()
    labels = ga.source_labels_map()
    m["by_source"] = {labels.get(k, k): v for k, v in m["by_source"].items()}
    m["tempo"] = db.posture_kpis()
    return m


@github_advisories_bp.route("/cs-advisories/metrics")
@log_web_activity
def advisory_metrics():
    """Analytics/visualization tab for the advisory queue — counts, breakdowns,
    operating tempo and throughput. Read-only; open to any viewer (the queue's
    write actions stay login-gated)."""
    return render_template("gh_advisory_metrics.html", metrics=_metrics_payload())


@github_advisories_bp.route("/api/cs-advisories/metrics.json")
@log_web_activity
def advisory_metrics_json():
    """The same metrics as a JSON feed, for BI tools / external dashboards.
    This is the queryable backend location partners asked about."""
    return jsonify(_metrics_payload())


def _detail_ribbon(adv: dict, cvss: dict, vulns: list, cap_results: dict) -> list[dict]:
    """Decision ribbon for the detail masthead — the few facts that drive the
    triage call (EPSS · CISA KEV · exploited-in-wild · patch · internet-facing).
    Derived ONLY from data already loaded for this page; makes no new network
    calls. EPSS is recovered from a cached CAPD scorecard's evidence text when
    one exists, otherwise it shows '—' (unknown, never a fabricated number)."""
    def _cap(name):
        c = cap_results.get(name) if isinstance(cap_results, dict) else None
        return c.get("result") if isinstance(c, dict) else None

    sc = _cap("capd_scorecard")
    cats: dict[str, dict] = {}
    if isinstance(sc, dict):
        for c in (sc.get("categories") or []):
            if isinstance(c, dict) and c.get("key"):
                cats[c["key"]] = c

    # EPSS — parse "EPSS 38%" out of the cached exploitability evidence.
    epss_v, epss_tone = "—", "neutral"
    ev = (cats.get("exploitability") or {}).get("evidence") or ""
    m = re.search(r"EPSS\s+(\d+)\s*%", ev)
    if m:
        p = int(m.group(1))
        epss_v = f"{p}%"
        epss_tone = "hot" if p >= 70 else "warm" if p >= 40 else "cool"

    # CISA KEV — source/severity, corroborated by a cached scorecard.
    kev = adv.get("source") == "cisa_kev" or adv.get("severity") == "known_exploited"
    for k in ("exploitability", "active_threat"):
        c = cats.get(k) or {}
        if c.get("source") == "CISA KEV" and c.get("score") == 4:
            kev = True
    kev_v, kev_tone = ("Yes", "hot") if kev else ("No", "cool")

    # Exploited in wild — KEV is definitive; else the active-threat category.
    at = cats.get("active_threat") or {}
    if kev:
        exp_v, exp_tone = "Yes", "hot"
    elif isinstance(at.get("score"), (int, float)):
        s = at["score"]
        exp_v, exp_tone = ("Yes", "hot") if s >= 3 else ("Likely", "warm") if s == 2 else ("No", "cool")
    else:
        exp_v, exp_tone = "—", "neutral"

    # Patch availability — note "—" is the advisory's "no fix" sentinel.
    has_fix = any((v or {}).get("first_patched") not in (None, "", "—") for v in (vulns or []))
    if has_fix:
        patch_v, patch_tone = "Available", "cool"
    elif vulns:
        patch_v, patch_tone = "None yet", "hot"
    else:
        patch_v, patch_tone = "—", "neutral"

    return [
        {"k": "EPSS", "v": epss_v, "tone": epss_tone},
        {"k": "CISA KEV", "v": kev_v, "tone": kev_tone},
        {"k": "Exploited in wild", "v": exp_v, "tone": exp_tone},
        {"k": "Patch", "v": patch_v, "tone": patch_tone},
    ]


@github_advisories_bp.route("/cs-advisories/<key>")
@log_web_activity
def advisory_detail(key):
    adv = db.get_advisory(key)
    if not adv:
        # Publish-lag fallback: a GHSA/CVE not yet pulled by the poller. Fetch it
        # live from GitHub/NVD/OSV, ingest it, then render the freshly-added card.
        if ga.live_lookup(key):
            adv = db.get_advisory(key)
    if not adv:
        abort(404)
    adv["source_label"] = _label_for(adv.get("source"))
    # Cross-source corroboration for this advisory (computed over the active corpus).
    try:
        corroboration = ga.compute_corroboration(db.list_advisories()).get(
            adv.get("uid") or adv.get("source_id"))
    except Exception:  # noqa: BLE001 — corroboration is best-effort
        corroboration = None
    vulns = _affected(adv)
    cvss = _cvss(adv)
    references = _references(adv)
    cwes = _cwes(adv)
    _u = current_user()
    is_owner = bool(is_admin() or (_u and adv.get("owner") and _u.get("email") == adv.get("owner")))
    capability_results = db.get_capability_results(key)
    return render_template(
        "gh_advisory_detail.html",
        adv=adv,
        is_owner=is_owner,
        is_authenticated=bool(_u),
        corroboration=corroboration,
        assessment_statuses=ASSESSMENT_STATUSES,
        signoff_teams=db.list_signoff_teams(),
        signoff_statuses=SIGNOFF_STATUSES,
        team_signoffs=db.get_team_signoffs(key),
        vulns=vulns,
        cvss=cvss,
        references=references,
        cwes=cwes,
        teams_channel=CONFIG.package_compromise_teams_channel or "Package Compromise Assessment",
        teams_draft=_teams_message(adv, _user_email()),
        xsoar_draft=_xsoar_description(adv),
        veracode_cves=ga._advisory_cves(adv),
        veracode_packages=ga._advisory_packages(adv),
        package_links=ga.advisory_package_links(adv),
        comments=db.list_comments(key),
        capability_links=ga.advisory_capability_links(adv),
        capability_results=capability_results,
        ribbon=_detail_ribbon(adv, cvss, vulns, capability_results),
        ta_audiences=_ta_audiences(),
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
# Email-digest subscription (self-service)
# ---------------------------------------------------------------------------
@github_advisories_bp.route("/api/cs-advisories/subscription")
def api_subscription_status():
    """Login-aware subscription state for the signup button. Public so the page
    can render even when logged out (returns authed=False)."""
    user = current_user()
    if not user:
        return jsonify({"ok": True, "authed": False, "subscribed": False, "email": None})
    email = user.get("email") or ""
    return jsonify({"ok": True, "authed": True,
                    "subscribed": db.is_subscribed(email), "email": email})


@github_advisories_bp.route("/api/cs-advisories/subscribe", methods=["POST"])
@login_required
def api_subscribe():
    email = _user_email()
    if not email or "@" not in email:
        return jsonify({"ok": False, "error": "no valid email on your account"}), 400
    added = db.add_subscriber(email)
    logger.info("[Advisories] %s %s the email digest", email,
                "subscribed to" if added else "was already subscribed to")
    return jsonify({"ok": True, "subscribed": True, "already": not added, "email": email})


@github_advisories_bp.route("/api/cs-advisories/unsubscribe", methods=["POST"])
@login_required
def api_unsubscribe():
    email = _user_email()
    db.remove_subscriber(email)
    logger.info("[Advisories] %s unsubscribed from the email digest", email)
    return jsonify({"ok": True, "subscribed": False, "email": email})


# ---------------------------------------------------------------------------
# Mutations (login required)
# ---------------------------------------------------------------------------
@github_advisories_bp.route("/api/cs-advisories/<key>/notes", methods=["POST"])
@login_required
@owner_required
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
@owner_required
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
@owner_required
def api_reopen(key):
    adv = db.get_advisory(key)
    if not adv:
        return jsonify({"ok": False, "error": "advisory not found"}), 404
    if adv["status"] == "reported":
        return jsonify({"ok": False, "error": "already reported — cannot reopen"}), 409
    db.set_status(key, "under_review", _user_email())
    return jsonify({"ok": True, "advisory": db.get_advisory(key)})


ASSESSMENT_STATUSES = {
    "assessing":   {"label": "Assessing",    "emoji": "🔍"},
    "no_exposure": {"label": "No exposure",  "emoji": "✅"},
    "remediating": {"label": "Remediating",  "emoji": "🔧"},
    "closed":      {"label": "Closed",       "emoji": "🏁"},
}


@github_advisories_bp.route("/api/cs-advisories/<key>/assessment", methods=["POST"])
@login_required
def api_set_assessment(key):
    """Assessment-team back-channel: record their work status (assessing / no
    exposure / remediating / closed) + an optional note. Any verified user can
    set it — the assessment team isn't necessarily the SOC advisory owner."""
    if not db.get_advisory(key):
        return jsonify({"ok": False, "error": "advisory not found"}), 404
    body = request.get_json(silent=True) or {}
    status = (body.get("status") or "").strip()
    note = body.get("note") or ""
    if status and status not in ASSESSMENT_STATUSES:
        return jsonify({"ok": False, "error": f"invalid status {status!r}"}), 400
    if not db.set_assessment_status(key, status, note, _user_email()):
        return jsonify({"ok": False, "error": "could not save"}), 500
    return jsonify({"ok": True, "advisory": db.get_advisory(key)})


SIGNOFF_STATUSES = {
    "pending":   {"label": "Pending",   "emoji": "⏳"},
    "clear":     {"label": "Clear",     "emoji": "✅"},
    "not_clear": {"label": "Not clear", "emoji": "⚠️"},
}


@github_advisories_bp.route("/api/cs-advisories/<key>/signoff", methods=["POST"])
@login_required
def api_set_signoff(key):
    """Multi-team validation sign-off: one validating team marks whether it has
    cleared this advisory (clear / not_clear / pending) with an optional note.
    Any verified user may record it on any team's behalf — these are shared
    war-room sign-offs, not personal ownership."""
    if not db.get_advisory(key):
        return jsonify({"ok": False, "error": "advisory not found"}), 404
    body = request.get_json(silent=True) or {}
    team = (body.get("team") or "").strip()
    status = (body.get("status") or "pending").strip()
    note = body.get("note") or ""
    valid_teams = {t["team"] for t in db.list_signoff_teams()}
    if team not in valid_teams:
        return jsonify({"ok": False, "error": f"unknown team {team!r}"}), 400
    if status not in SIGNOFF_STATUSES:
        return jsonify({"ok": False, "error": f"invalid status {status!r}"}), 400
    if not db.set_team_signoff(key, team, status, note, _user_email()):
        return jsonify({"ok": False, "error": "could not save"}), 500
    return jsonify({"ok": True, "signoffs": db.get_team_signoffs(key)})


@github_advisories_bp.route("/api/cs-advisories/group")
@log_web_activity
def api_package_group():
    """Advisories whose packages match a search token (e.g. an npm scope). Read
    only — ungated, like the rest of the queue views."""
    group = ga.package_group(request.args.get("q", ""))
    return jsonify({"ok": True, "group": group})


@github_advisories_bp.route("/api/cs-advisories/group/check")
@log_web_activity
def api_package_group_check():
    """Run the Veracode SCA presence check across the whole matched group at once.
    Read only (cached index) — ungated."""
    group = ga.package_group(request.args.get("q", ""))
    check = ga.group_environment_check(group["packages"])
    return jsonify({"ok": True,
                    "advisory_count": group["advisory_count"],
                    "package_count": group["package_count"],
                    "check": check})


@github_advisories_bp.route("/api/cs-advisories/group/clear", methods=["POST"])
@login_required
def api_package_group_clear():
    """Bulk-clear a campaign: mark one team's sign-off = clear across every
    advisory matching the query. Login-gated (it writes). The group is recomputed
    server-side from the query, so the client can't target arbitrary advisories."""
    body = request.get_json(silent=True) or {}
    q = (body.get("q") or "").strip()
    team = (body.get("team") or "").strip()
    note = (body.get("note") or "").strip()
    if not q:
        return jsonify({"ok": False, "error": "empty query"}), 400
    if team not in {t["team"] for t in db.list_signoff_teams()}:
        return jsonify({"ok": False, "error": f"unknown team {team!r}"}), 400
    group = ga.package_group(q)
    if not group["members"]:
        return jsonify({"ok": False, "error": "no advisories match that query"}), 404
    auto = note or f"Bulk-cleared via group search '{q}' — not present in environment."
    keys = [m["source_id"] or m["uid"] for m in group["members"]]
    n = db.bulk_set_team_signoff(keys, team, "clear", auto, _user_email())
    return jsonify({"ok": True, "cleared": n, "advisory_count": group["advisory_count"]})


@github_advisories_bp.route("/api/cs-advisories/<key>/faq", methods=["POST"])
@login_required
@owner_required
def api_faq(key):
    """Generate (and cache) the CAPD-decision FAQ answers for an advisory."""
    adv = db.get_advisory(key)
    if not adv:
        return jsonify({"ok": False, "error": "advisory not found"}), 404
    try:
        faq = ga.generate_advisory_faq(adv)
    except Exception as e:
        logger.error("[Advisories] FAQ error for %s: %s", key, e, exc_info=True)
        return jsonify({"ok": False, "error": f"FAQ generation failed: {e}"}), 502
    db.save_capability_result(key, "faq", faq, _user_email())
    return jsonify({"ok": True, "faq": faq})


@github_advisories_bp.route("/cs-advisories/<key>/report")
@log_web_activity
def advisory_report(key):
    """Standalone, self-contained HTML report for an advisory (downloadable)."""
    adv = db.get_advisory(key)
    if not adv:
        abort(404)
    adv["source_label"] = _label_for(adv.get("source"))
    caps = db.get_capability_results(key)
    html = render_template(
        "gh_advisory_report.html",
        adv=adv,
        vulns=_affected(adv),
        cvss=_cvss(adv),
        references=_references(adv),
        cwes=_cwes(adv),
        comments=db.list_comments(key),
        capability_results=caps,
        faq=(caps.get("faq") or {}).get("result"),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", adv.get("source_id") or "advisory")
    resp = make_response(html)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="advisory_{safe}.html"'
    return resp


@github_advisories_bp.route("/cs-advisories/<key>/report.pdf")
@log_web_activity
def advisory_report_pdf(key):
    """Branded, shareable PDF snapshot of an advisory — facts, AI assessment +
    extracted IOCs/TTPs, the CAPD verdict, Veracode SCA exposure, the QRadar
    'were we touched?' result, and reviewer notes. Pulls only what's already on
    the record (incl. cached capability results); no new scans."""
    adv = db.get_advisory(key)
    if not adv:
        abort(404)
    adv["source_label"] = _label_for(adv.get("source"))
    caps = db.get_capability_results(key)
    capd = (caps.get("capd_scorecard") or {}).get("result") if isinstance(caps.get("capd_scorecard"), dict) else None
    qradar = (caps.get("qradar") or {}).get("result") if isinstance(caps.get("qradar"), dict) else None
    fleet = (caps.get("fleet_posture") or {}).get("result") if isinstance(caps.get("fleet_posture"), dict) else None
    threat_analysis = (caps.get("threat_analysis") or {}).get("result") if isinstance(caps.get("threat_analysis"), dict) else None
    vc = adv.get("veracode_enrichment") if isinstance(adv.get("veracode_enrichment"), dict) else None

    from services.advisory_report import build_pdf, flatten_veracode_apps
    ctx = {
        "adv": adv,
        "cvss": _cvss(adv),
        "source_label": adv.get("source_label"),
        "affected": _affected(adv),
        "capd": capd,
        "qradar": qradar,
        "fleet_posture": fleet,
        "threat_analysis": threat_analysis,
        "veracode": vc,
        "veracode_apps": flatten_veracode_apps(vc),
        "ai": adv.get("ai_assessment"),
        "generated_at": datetime.now(EASTERN).strftime("%m/%d/%Y %-I:%M %p %Z"),
        "generated_by": (_user_email() if current_user() else None),
    }
    try:
        pdf_bytes = build_pdf(ctx)
    except Exception as e:
        logger.exception("[Advisories] PDF report generation failed for %s", key)
        return jsonify({"ok": False, "error": f"PDF generation failed: {type(e).__name__}: {e}"}), 500
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", adv.get("source_id") or "advisory")
    return send_file(BytesIO(pdf_bytes), mimetype="application/pdf",
                     as_attachment=True, download_name=f"advisory_{safe}.pdf")


@github_advisories_bp.route("/api/cs-advisories/<key>/capability/<cap>", methods=["POST"])
@login_required
@owner_required
def api_run_capability(key, cap):
    """Run a server-side capability check (e.g. JFrog Xray) and persist the result."""
    adv = db.get_advisory(key)
    if not adv:
        return jsonify({"ok": False, "error": "advisory not found"}), 404
    res = ga.run_advisory_capability(adv, cap)
    if not res.get("ok"):
        return jsonify({"ok": False, "error": res.get("error", "capability failed")}), 502
    db.save_capability_result(key, cap, res["result"], _user_email())
    saved = db.get_capability_results(key).get(cap, {})
    return jsonify({"ok": True, "capability": cap, "result": res["result"],
                    "run_by": saved.get("run_by"), "run_at": saved.get("run_at")})


@github_advisories_bp.route("/api/cs-advisories/<key>/capability/<cap>/start", methods=["POST"])
@login_required
@owner_required
def api_start_capability(key, cap):
    """Kick off a slow capability (e.g. QRadar) as a background job. Poll
    ``/capability/<cap>/status`` for the result."""
    adv = db.get_advisory(key)
    if not adv:
        return jsonify({"ok": False, "error": "advisory not found"}), 404
    body = request.get_json(silent=True) or {}
    opts = {"audience": body["audience"]} if body.get("audience") else None
    state = ga.start_capability_job(adv, cap, _user_email(), opts=opts)
    return jsonify({"ok": True, **state})


@github_advisories_bp.route("/api/cs-advisories/<key>/capability/<cap>/status")
@login_required
def api_capability_status(key, cap):
    """Status of a background capability job. Falls back to a previously-persisted
    result so a reload mid-flight (or after completion) still shows it."""
    adv = db.get_advisory(key)
    if not adv:
        return jsonify({"ok": False, "error": "advisory not found"}), 404
    job = ga.get_capability_job(adv, cap)
    if job:
        return jsonify({"ok": True, **job})
    saved = db.get_capability_results(key).get(cap)
    if saved:
        return jsonify({"ok": True, "state": "done", "result": saved.get("result")})
    return jsonify({"ok": True, "state": "idle"})


@github_advisories_bp.route("/api/cs-advisories/<key>/threat-analysis/export/<fmt>")
@login_required
def api_threat_analysis_export(key, fmt):
    """Download a cached Threat Analysis as a STIX 2.1 bundle, an ATT&CK Navigator
    layer, or a Markdown intelligence brief."""
    adv = db.get_advisory(key)
    if not adv:
        return abort(404)
    saved = db.get_capability_results(key).get("threat_analysis")
    result = (saved or {}).get("result")
    if not isinstance(result, dict) or result.get("error"):
        return abort(404, "no threat analysis to export — run it first")
    from services.advisory_threat_analysis import build_export
    out = build_export(result, adv, fmt)
    if not out:
        return abort(400, "unknown export format")
    body, mimetype, filename = out
    resp = make_response(body)
    resp.headers["Content-Type"] = f"{mimetype}; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp


@github_advisories_bp.route("/api/cs-advisories/<key>/comments")
def api_list_comments(key):
    """Discussion thread for an advisory (public read)."""
    if not db.get_advisory(key):
        return jsonify({"ok": False, "error": "advisory not found"}), 404
    return jsonify({"ok": True, "comments": db.list_comments(key)})


@github_advisories_bp.route("/api/cs-advisories/<key>/comments", methods=["POST"])
@login_required
def api_add_comment(key):
    body = (request.get_json(silent=True) or {}).get("body", "")
    if not isinstance(body, str) or not body.strip():
        return jsonify({"ok": False, "error": "comment body required"}), 400
    comment = db.add_comment(key, _user_email(), body.strip()[:MAX_COMMENT_LEN])
    if comment is None:
        return jsonify({"ok": False, "error": "advisory not found"}), 404
    logger.info("[Advisories] comment added to %s by %s", key, _user_email())
    return jsonify({"ok": True, "comment": comment})


@github_advisories_bp.route("/api/cs-advisories/<key>/assign", methods=["POST"])
@login_required
def api_assign(key):
    """Claim ownership of an advisory (the current user becomes the owner)."""
    if not db.assign_owner(key, _user_email()):
        return jsonify({"ok": False, "error": "advisory not found"}), 404
    logger.info("[Advisories] %s assigned to %s", key, _user_email())
    return jsonify({"ok": True, "advisory": db.get_advisory(key)})


@github_advisories_bp.route("/api/cs-advisories/<key>/release", methods=["POST"])
@login_required
def api_release(key):
    """Release ownership (back to unowned)."""
    if not db.release_owner(key):
        return jsonify({"ok": False, "error": "advisory not found"}), 404
    logger.info("[Advisories] %s released by %s", key, _user_email())
    return jsonify({"ok": True, "advisory": db.get_advisory(key)})


@github_advisories_bp.route("/api/cs-advisories/<key>/archive", methods=["POST"])
@login_required
@owner_required
def api_archive(key):
    if not db.archive_advisory(key, _user_email()):
        return jsonify({"ok": False, "error": "advisory not found"}), 404
    logger.info("[Advisories] %s archived by %s", key, _user_email())
    return jsonify({"ok": True, "advisory": db.get_advisory(key)})


@github_advisories_bp.route("/api/cs-advisories/<key>/unarchive", methods=["POST"])
@login_required
@owner_required
def api_unarchive(key):
    if not db.unarchive_advisory(key, _user_email()):
        return jsonify({"ok": False, "error": "advisory not found"}), 404
    logger.info("[Advisories] %s restored from archive by %s", key, _user_email())
    return jsonify({"ok": True, "advisory": db.get_advisory(key)})


@github_advisories_bp.route("/api/cs-advisories/<key>/ai-triage", methods=["POST"])
@login_required
@owner_required
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
@owner_required
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


@github_advisories_bp.route("/api/cs-advisories/<key>/verify-remediation", methods=["POST"])
@login_required
@owner_required
def api_verify_remediation(key):
    """Confirm (or refute) an app team's remediation claim. Re-runs the exposure
    lenses live, persists the result as a durable snapshot, and diffs it against
    the previous snapshot — so the page can show "N apps cleared (was X, now Y)"
    with the specific apps that cleared vs. those that remain. Closes the loop on
    the assessment side, mirroring how the XSOAR sync closes it on the ticket side."""
    adv = db.get_advisory(key)
    if not adv:
        return jsonify({"ok": False, "error": "advisory not found"}), 404
    # Grab the prior snapshot BEFORE inserting this one, so the diff is before/after.
    prev = db.latest_exposure_snapshot(key)
    try:
        snap = ga.exposure_snapshot(adv)
    except Exception as e:  # ga.exposure_snapshot already degrades, belt-and-suspenders
        logger.error("[Advisories] Verify-remediation failed for %s: %s", key, e, exc_info=True)
        return jsonify({"ok": False, "error": f"exposure re-check failed: {e}"}), 502
    user = _user_email()
    snap["taken_at"] = datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")
    snap["taken_by"] = user
    db.add_exposure_snapshot(key, snap)
    diff = ga.diff_exposure_snapshots(prev, snap)
    payload = {
        "current": snap,
        "previous": prev,
        "diff": diff,
        "checked_at": snap["taken_at"],
        "checked_by": user,
        "history_count": db.exposure_snapshot_count(key),
    }
    # Persist the latest verdict so it re-renders on reload and flows into reports.
    db.save_capability_result(key, "verify_remediation", payload, user)
    logger.info("[Advisories] Verify-remediation %s by %s → %s",
                key, user, diff.get("verdict"))
    return jsonify({"ok": True, **payload})


@github_advisories_bp.route("/api/cs-advisories/<key>/verify-remediation/history")
@log_web_activity
def api_verify_remediation_history(key):
    """Full remediation-verification snapshot history for an advisory (public
    read, like the rest of the queue views)."""
    if not db.get_advisory(key):
        return jsonify({"ok": False, "error": "advisory not found"}), 404
    return jsonify({"ok": True, "snapshots": db.list_exposure_snapshots(key, limit=50)})


@github_advisories_bp.route("/api/cs-advisories/<key>/report", methods=["POST"])
@require_capability(SEND_EXTERNAL)
@owner_required
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
    payload = request.get_json(silent=True) or {}
    notes = payload.get("notes")
    if isinstance(notes, str):
        db.save_notes(key, notes.strip()[:MAX_NOTES_LEN], user)
        adv = db.get_advisory(key)

    # The owner can edit the draft in the Notify modal; send their version
    # verbatim. Falls back to the generated draft for the legacy/direct path.
    custom = payload.get("message")
    message = (custom.strip()[:MAX_TEAMS_MSG_LEN]
               if isinstance(custom, str) and custom.strip()
               else _teams_message(adv, user))

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
            message,
            channel=channel,
            team=CONFIG.package_compromise_teams_team or None,
        )
    except Exception as e:
        logger.error("[Advisories] Teams escalation failed for %s: %s", key, e, exc_info=True)
        return jsonify({"ok": False, "error": f"Teams send failed: {e}",
                        "advisory": db.get_advisory(key)}), 502

    logger.info("[Advisories] %s escalated to Teams channel %r by %s", adv.get("uid"), channel, user)
    return jsonify({"ok": True, "teams_sent": True, "advisory": db.get_advisory(key)})


MAX_BULK = 100  # safety cap on advisories acted on in one bulk request


def _send_advisory_to_teams(adv: dict, user: str) -> bool:
    """Post a single advisory's escalation card to the Package Compromise
    Assessment Teams channel. Returns True if sent. Raises on send failure so
    the bulk loop records it per-advisory. Mirrors the single-advisory path."""
    channel = CONFIG.package_compromise_teams_channel
    if not channel:
        logger.warning("[Advisories] PACKAGE_COMPROMISE_TEAMS_CHANNEL not set — marked reported without Teams send")
        return False
    from services.xsoar_teams import send_teams_message  # lazy: pulls XSOAR client
    send_teams_message(_teams_message(adv, user), channel=channel,
                       team=CONFIG.package_compromise_teams_team or None)
    return True


@github_advisories_bp.route("/api/cs-advisories/bulk", methods=["POST"])
@login_required
def api_bulk_action():
    """Apply one action to several advisories at once for fast triage.

    Body: ``{"action": "assign"|"close"|"escalate", "keys": [...], "note": "?"}``.

    - assign:   claim each (current user becomes owner).
    - close:    claim-if-needed then close as not-reported, recording the shared
                note — so a batch of new/unowned rows can be cleared in one pass.
    - escalate: idempotent Teams escalation of each (already-reported are
                skipped); outward-facing, so prod-only + the SEND_EXTERNAL
                capability, same gate as the single-advisory report.

    Always returns 200 with per-key done/skipped/errors so a partial batch is
    reported faithfully rather than failing the whole request."""
    body = request.get_json(silent=True) or {}
    action = (body.get("action") or "").strip()
    keys = body.get("keys")
    note = body.get("note")
    if action not in ("assign", "close", "escalate"):
        return jsonify({"ok": False, "error": f"unknown action {action!r}"}), 400
    if not isinstance(keys, list) or not keys:
        return jsonify({"ok": False, "error": "no advisories selected"}), 400
    keys = [str(k) for k in keys][:MAX_BULK]
    user = _user_email()
    note_clean = note.strip()[:MAX_NOTES_LEN] if isinstance(note, str) and note.strip() else None

    # Escalation is outward-facing — guard the bulk path exactly like the single
    # report endpoint (capability + prod-only) before doing any work.
    if action == "escalate":
        if not has_capability(current_user(), SEND_EXTERNAL):
            return jsonify({"ok": False, "error": "forbidden",
                            "warning": "You don't have permission to escalate."}), 403
        if not CONFIG.is_production:
            return jsonify({"ok": False, "error": "escalation_disabled_in_dev",
                            "warning": f"Teams escalation is disabled on the {CONFIG.environment} instance."}), 403

    def _owns(adv):
        return is_admin() or (adv.get("owner") or "").strip().lower() == (user or "").strip().lower()

    done, skipped, errors = [], [], []
    for key in keys:
        adv = db.get_advisory(key)
        if not adv:
            errors.append({"key": key, "error": "not found"})
            continue
        try:
            if action == "assign":
                db.assign_owner(key, user)
                done.append(key)
            elif action == "close":
                if not _owns(adv):
                    db.assign_owner(key, user)  # claim so the close is permitted
                if note_clean:
                    db.save_notes(key, note_clean, user)
                db.set_status(key, "closed_not_reported", user)
                done.append(key)
            elif action == "escalate":
                if adv.get("status") == "reported":
                    skipped.append(key)  # idempotent — never double-post
                    continue
                if not _owns(adv):
                    db.assign_owner(key, user)
                if note_clean:
                    db.save_notes(key, note_clean, user)
                adv = db.get_advisory(key)
                if not db.mark_reported(key, user):
                    skipped.append(key)
                    continue
                _send_advisory_to_teams(adv, user)
                done.append(key)
        except Exception as e:  # one bad advisory shouldn't sink the batch
            logger.error("[Advisories] bulk %s failed for %s: %s", action, key, e, exc_info=True)
            errors.append({"key": key, "error": str(e)})
    logger.info("[Advisories] bulk %s by %s — done=%d skipped=%d errors=%d",
                action, user, len(done), len(skipped), len(errors))
    return jsonify({"ok": True, "action": action, "done": done, "skipped": skipped,
                    "errors": errors,
                    "counts": {"done": len(done), "skipped": len(skipped), "errors": len(errors)}})


@github_advisories_bp.route("/api/cs-advisories/<key>/report-draft", methods=["GET"])
@login_required
def api_report_draft(key):
    """Freshly-built escalation draft, reflecting any capability checks (CAPD
    scorecard / Veracode / QRadar) run since the page loaded. The Notify modal
    fetches this on open so the draft always carries the latest assessment
    evidence. Read-only — sending is still owner-gated on api_report."""
    adv = db.get_advisory(key)
    if not adv:
        return jsonify({"ok": False, "error": "advisory not found"}), 404
    return jsonify({"ok": True, "draft": _teams_message(adv, _user_email())})


@github_advisories_bp.route("/api/cs-advisories/<key>/xsoar-ticket", methods=["POST"])
@login_required
@owner_required
def api_create_xsoar_ticket(key):
    """Create an XSOAR incident from this advisory using the owner-edited draft
    description. Idempotent: once a ticket exists for the advisory a second click
    returns the existing one instead of creating a duplicate. Hard-disabled on
    non-prod (the create always targets XSOAR Prod)."""
    adv = db.get_advisory(key)
    if not adv:
        return jsonify({"ok": False, "error": "advisory not found"}), 404

    if not CONFIG.is_production:
        return jsonify({"ok": False, "error": "xsoar_disabled_in_dev",
                        "warning": f"XSOAR ticket creation is disabled on the {CONFIG.environment} instance."}), 403

    if adv.get("xsoar_ticket_id"):
        return jsonify({"ok": False, "error": "already_created",
                        "ticket_id": adv.get("xsoar_ticket_id"),
                        "ticket_url": adv.get("xsoar_ticket_url"),
                        "advisory": adv}), 409

    user = _user_email()
    body = request.get_json(silent=True) or {}
    desc = body.get("description")
    description = (desc.strip()[:MAX_XSOAR_DESC_LEN]
                  if isinstance(desc, str) and desc.strip()
                  else _xsoar_description(adv))
    sev = _XSOAR_SEV_NUM.get((adv.get("severity") or "").lower(), 2)
    name = f"{adv.get('source_id')} — {adv.get('cve_id') or 'advisory'} (Pkg/Advisory triage)"
    incident = {"name": name[:200], "severity": sev, "details": description}

    try:
        from services.xsoar.ticket_handler import TicketHandler
        resp = TicketHandler().create(incident)
    except Exception as e:
        logger.error("[Advisories] XSOAR ticket create failed for %s: %s", key, e, exc_info=True)
        return jsonify({"ok": False, "error": f"XSOAR create failed: {e}"}), 502

    tid = str((resp or {}).get("id") or "").strip()
    if not tid:
        logger.error("[Advisories] XSOAR create returned no id for %s: %r", key, resp)
        return jsonify({"ok": False, "error": "XSOAR did not return a ticket id"}), 502

    base = (CONFIG.xsoar_prod_ui_base_url or "").rstrip("/")
    ticket_url = f"{base}/Custom/caseinfoid/{tid}" if base else ""
    db.set_xsoar_ticket(key, tid, ticket_url, user)
    # Seed the outcome as 'open' so the row closes the loop immediately; the
    # periodic sync then advances it (in progress / resolved) as the case moves.
    db.set_xsoar_status(adv["uid"], "open")
    logger.info("[Advisories] %s -> XSOAR incident #%s by %s", adv.get("uid"), tid, user)
    return jsonify({"ok": True, "ticket_id": tid, "ticket_url": ticket_url,
                    "advisory": db.get_advisory(key)})


@github_advisories_bp.route("/api/cs-advisories/sync-outcomes", methods=["POST"])
@login_required
def api_sync_outcomes():
    """Force-refresh escalation outcomes (XSOAR ticket state) on demand instead of
    waiting for the hourly sync. Read-only against XSOAR Prod; on non-prod the
    sync degrades to a no-op (no client), so it's safe to expose everywhere."""
    try:
        result = ga.sync_xsoar_outcomes()
    except Exception as e:  # noqa: BLE001
        logger.error("[Advisories] manual outcome sync failed: %s", e, exc_info=True)
        return jsonify({"ok": False, "error": str(e)}), 502
    return jsonify({"ok": True, **result, "counts": db.escalation_outcome_counts()})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _user_email() -> str:
    user = current_user()
    return (user or {}).get("email") or "unknown"


def _ta_audiences() -> list[dict]:
    """Audience choices for the Threat Analysis brief selector. Degrades to an
    empty list if the service can't be imported (tile just hides the selector)."""
    try:
        from services.advisory_threat_analysis import audience_options
        return audience_options()
    except Exception:  # noqa: BLE001
        return []


def _teams_message(adv: dict, user: str) -> str:
    cvss = _cvss(adv)
    score = f" · CVSS {cvss['score']}" if cvss.get("score") else ""
    source = _label_for(adv.get("source"))
    pkgs = ", ".join(adv.get("packages") or [])[:300] or "—"
    notes = (adv.get("notes") or "").strip()
    notes_block = f"\n\n**Reviewer notes:**\n{notes}" if notes else ""
    evidence = _assessment_evidence(adv)
    return (
        f"🚨 **Package Compromise Assessment requested**\n\n"
        f"**{adv['source_id']}** ({adv.get('cve_id') or 'no CVE'}){score} · _{source}_\n"
        f"{adv.get('summary') or ''}\n\n"
        f"**Affected packages:** {pkgs}\n"
        f"**Advisory:** {adv.get('html_url') or ''}"
        f"{notes_block}"
        f"{evidence}\n\n"
        f"_Escalated by {user}._"
    )


def _xsoar_description(adv: dict) -> str:
    """Default editable description for an XSOAR incident raised from an advisory —
    the advisory facts + summary + whatever assessment evidence has been gathered,
    as plain text the owner can edit before creating the ticket."""
    cvss = _cvss(adv)
    score = f" · CVSS {cvss['score']}" if cvss.get("score") else ""
    source = _label_for(adv.get("source"))
    pkgs = ", ".join(adv.get("packages") or [])[:300] or "—"
    notes = (adv.get("notes") or "").strip()
    notes_block = f"\n\nReviewer notes:\n{notes}" if notes else ""
    evidence = _assessment_evidence(adv)
    return (
        f"Cyber Security Advisory triage — {adv['source_id']} "
        f"({adv.get('cve_id') or 'no CVE'}){score} · {source}\n"
        f"Severity: {adv.get('severity') or 'n/a'}\n\n"
        f"{adv.get('summary') or ''}\n\n"
        f"Affected packages: {pkgs}\n"
        f"Advisory: {adv.get('html_url') or ''}"
        f"{notes_block}"
        f"{evidence}\n\n"
        f"Raised from the Cyber Security Advisories triage queue ({adv['source_id']})."
    )


def _veracode_app_names(vc: dict, limit: int = 6) -> list[str]:
    """Distinct application names out of a Veracode exposure result, capped — so
    the escalation names the actually-affected apps, not just a count."""
    names: list[str] = []
    for bucket in ("cves", "packages"):
        for rows in (vc.get(bucket) or {}).values():
            for r in rows or []:
                n = (r or {}).get("application")
                if n and n not in names:
                    names.append(n)
    return names[:limit]


def _assessment_evidence(adv: dict) -> str:
    """Concise 'Assessment evidence' block built from whatever native checks have
    already been run + cached for this advisory — the CAPD scorecard verdict +
    reachability, Veracode SCA software exposure, and the QRadar 'were we touched?'
    SIEM check. Reads only cached results (triggers NO new scans), and returns ''
    when nothing has been run so an un-enriched draft stays clean. This makes the
    Teams escalation self-contained: the assessment team gets the exposure answers
    in the ping instead of coming back to ask 'what apps, what hosts?'."""
    uid = adv.get("uid") or adv.get("source_id") or ""
    try:
        cached = db.get_capability_results(uid)
    except Exception:  # noqa: BLE001 — evidence is best-effort, never block the draft
        cached = {}

    lines: list[str] = []

    capd = (cached.get("capd_scorecard") or {}).get("result") if isinstance(cached.get("capd_scorecard"), dict) else None
    if isinstance(capd, dict) and isinstance(capd.get("score"), int):
        band = capd.get("band_label") or capd.get("band") or ""
        lines.append(f"**CAPD score:** {capd['score']}/100 → {band}")
        verdict = (capd.get("verdict") or "").strip()
        if verdict:
            lines.append(verdict)
        for cat in capd.get("categories") or []:
            if cat.get("key") == "reachability" and cat.get("sufficient"):
                lines.append(f"- _External reachability:_ {cat.get('evidence')}")

    vc = adv.get("veracode_enrichment")
    if isinstance(vc, dict) and vc.get("affected_app_count"):
        names = _veracode_app_names(vc)
        extra = f" — {', '.join(names)}" if names else ""
        lines.append(f"**Veracode SCA:** {vc.get('summary_text') or ''}{extra}".rstrip())

    qr = (cached.get("qradar") or {}).get("result") if isinstance(cached.get("qradar"), dict) else None
    if isinstance(qr, dict) and qr.get("summary_text") and not qr.get("error"):
        lines.append(f"**SIEM (QRadar, last 1h):** {qr['summary_text']}")

    fp = (cached.get("fleet_posture") or {}).get("result") if isinstance(cached.get("fleet_posture"), dict) else None
    if isinstance(fp, dict) and fp.get("summary_text") and not fp.get("error"):
        # summary_text already carries the "🛰️ Fleet posture (Power BI · …):" prefix.
        lines.append(f"**{fp['summary_text']}**" if not fp["summary_text"].startswith("**") else fp["summary_text"])

    ta = (cached.get("threat_analysis") or {}).get("result") if isinstance(cached.get("threat_analysis"), dict) else None
    if isinstance(ta, dict) and not ta.get("error"):
        tcount = len(ta.get("techniques") or [])
        rcount = len(ta.get("detection_rules") or [])
        lines.append(f"**🛡️ Threat analysis:** {tcount} ATT&CK technique(s) mapped, "
                     f"{rcount} detection rule(s) generated.")
        action = ((ta.get("brief") or {}).get("threat_action") or "").strip()
        if action:
            lines.append(f"- {action}")

    # Cross-source corroboration — independent confirmation strengthens the case.
    try:
        cor = ga.compute_corroboration(db.list_advisories()).get(uid)
    except Exception:  # noqa: BLE001
        cor = None
    if cor:
        lines.append(f"**🔗 Corroboration:** seen across {cor['source_count']} sources "
                     f"({', '.join(cor['sources'])})" +
                     (f" — matched on {', '.join(cor['via'])}" if cor.get("via") else "") + ".")

    if not lines:
        return ""
    return "\n\n**🔎 Assessment evidence**\n" + "\n".join(lines)


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
