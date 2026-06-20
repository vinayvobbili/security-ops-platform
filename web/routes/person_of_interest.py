"""Person-of-Interest OSINT investigation web views.

List + detail pages backed by services.poi_scanner's SQLite store.
Read-only — investigations are launched via the Aide bot (or Sleuth).
"""

import logging
from datetime import datetime

from flask import Blueprint, abort, jsonify, render_template

from services.poi_scanner import get_investigation, get_investigation_status, list_investigations
from src.utils.logging_utils import log_web_activity


# Per-stage labels for the detail-page progress strip. Kept in route layer
# so it stays a UI concern, not baked into the scanner.
_PHASE_LABELS = {
    "hibp":      "🚨 HIBP breaches",
    "holehe":    "📧 holehe accounts",
    "maigret":   "🌐 maigret usernames",
    "dorks":     "🔗 Name dorks",
    "commentary": "💡 LLM commentary",
}


def _build_chat_context(inv: dict) -> str:
    """Markdown blob fed to the page-chat widget — full scan context so the LLM
    can answer pointed questions about THIS investigation."""
    L: list[str] = [f"# POI Investigation #{inv.get('id')}", ""]
    L.append(f"- **Target name:** {inv.get('target_name') or '(unknown)'}")
    if inv.get("target_username"):
        L.append(f"- **Username searched:** `{inv['target_username']}`")
    if inv.get("target_email"):
        L.append(f"- **Email searched:** `{inv['target_email']}`")
    if inv.get("reason"):
        L.append(f"- **Reason for investigation:** {inv['reason']}")
    L.append(f"- **Status:** {inv.get('status')}")
    L.append("")

    if inv.get("commentary"):
        L += ["## Analyst commentary", inv["commentary"], ""]

    r = inv.get("results") or {}

    hibp = r.get("hibp") or {}
    if hibp.get("ok"):
        L.append(f"## HIBP breaches: {hibp.get('breach_count', 0)}")
        for b in (hibp.get("breaches") or [])[:40]:
            if not isinstance(b, dict):
                continue
            line = f"- **{b.get('title') or b.get('name')}**"
            if b.get("date"):       line += f" ({b['date']})"
            if b.get("pwn_count"):  line += f" — {b['pwn_count']:,} accounts"
            dc = b.get("data_classes") or []
            if dc:                  line += f" — exposed: {', '.join(dc[:6])}"
            L.append(line)
        L.append("")
    elif hibp:
        L += [f"## HIBP: unavailable ({hibp.get('error', 'error')})", ""]

    holehe = r.get("holehe") or {}
    if holehe.get("ok"):
        hits = holehe.get("hits") or []
        L.append(f"## Email-account hits via holehe: {len(hits)}")
        for h in hits[:50]:
            L.append(f"- {h}")
        L.append("")

    # maigret — separate high-signal hits (user URL contains the handle) from
    # noise (Discord-style homepage URLs and name-search hits like SO).
    maigret = r.get("maigret") or {}
    if maigret.get("ok"):
        claimed = maigret.get("claimed") or []
        u = (maigret.get("username") or "").lower()
        high, noisy = [], []
        for c in claimed:
            url = c.get("url") or ""
            ulow = url.lower()
            is_search = "search=" in ulow or "query=" in ulow or "?q=" in ulow
            if url and u and u in ulow and not is_search:
                high.append((c.get("site"), url))
            else:
                noisy.append(c.get("site"))
        L.append(f"## maigret claimed sites: {len(claimed)} of {maigret.get('sites_checked', '?')} checked "
                 f"(high-signal: {len(high)}, low-signal: {len(noisy)})")
        for site, url in high[:50]:
            L.append(f"- **{site}** — {url}")
        if noisy:
            L.append(f"\n_Low-signal sites (homepage URL or name-search, not a specific profile): "
                     f"{', '.join(s for s in noisy if s)[:600]}_")
        L.append("")

    dorks = (r.get("dorks") or {}).get("links") or []
    if dorks:
        L.append("## Name-search dorks (Google links the analyst can click)")
        for d in dorks:
            L.append(f"- {d.get('label')}: {d.get('url')}")
        L.append("")

    return "\n".join(L)

logger = logging.getLogger(__name__)

person_of_interest_bp = Blueprint("person_of_interest", __name__)


def _fmt_utc(iso: str | None) -> str:
    if not iso:
        return ""
    try:
        dt = datetime.fromisoformat(iso)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return iso


@person_of_interest_bp.route("/person-of-interest")
@log_web_activity
def list_page():
    rows = list_investigations(limit=200)
    for r in rows:
        r["created_at_fmt"] = _fmt_utc(r.get("created_at"))
        r["completed_at_fmt"] = _fmt_utc(r.get("completed_at"))
    return render_template("person_of_interest.html", investigations=rows)


@person_of_interest_bp.route("/person-of-interest/<int:inv_id>")
@log_web_activity
def detail_page(inv_id: int):
    inv = get_investigation(inv_id)
    if not inv:
        abort(404)
    inv["created_at_fmt"] = _fmt_utc(inv.get("created_at"))
    inv["completed_at_fmt"] = _fmt_utc(inv.get("completed_at"))

    # Pre-compute breaches grouped by year for the mermaid timeline tab. We
    # only include breaches with a parseable date; undated ones drop into a
    # separate "Undated" bucket so the analyst doesn't lose them silently.
    timeline_years: dict[str, list[dict]] = {}
    undated: list[dict] = []
    breaches = ((inv.get("results") or {}).get("hibp") or {}).get("breaches") or []
    for b in breaches:
        if not isinstance(b, dict):
            continue
        date = (b.get("date") or "").strip()
        year = date[:4] if len(date) >= 4 and date[:4].isdigit() else ""
        if year:
            timeline_years.setdefault(year, []).append(b)
        else:
            undated.append(b)
    timeline_years_sorted = sorted(timeline_years.items())
    has_timeline = bool(timeline_years_sorted) or bool(undated)

    # Phases the worker will actually run for this investigation — drives the
    # progress strip rendered by the detail template + polled status.json.
    expected_phases: list[dict[str, str]] = []
    if inv.get("target_email"):
        expected_phases.append({"id": "hibp",   "label": _PHASE_LABELS["hibp"]})
        expected_phases.append({"id": "holehe", "label": _PHASE_LABELS["holehe"]})
    if inv.get("target_username"):
        expected_phases.append({"id": "maigret", "label": _PHASE_LABELS["maigret"]})
    if inv.get("target_name"):
        expected_phases.append({"id": "dorks",  "label": _PHASE_LABELS["dorks"]})
    # Commentary is the final phase whenever any signal ran.
    if expected_phases:
        expected_phases.append({"id": "commentary", "label": _PHASE_LABELS["commentary"]})

    return render_template(
        "person_of_interest_detail.html",
        inv=inv,
        timeline_years=timeline_years_sorted,
        timeline_undated=undated,
        has_timeline=has_timeline,
        expected_phases=expected_phases,
        chat_context_md=_build_chat_context(inv),
    )


@person_of_interest_bp.route("/person-of-interest/<int:inv_id>/status.json")
def status_json(inv_id: int):
    """Lightweight polling endpoint — no log decorator (would spam the log)."""
    s = get_investigation_status(inv_id)
    if not s:
        abort(404)
    return jsonify(s)
