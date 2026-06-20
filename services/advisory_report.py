"""Branded, shareable PDF report for a single Cyber Security Advisory.

Renders an advisory record — facts, AI assessment + extracted IOCs/TTPs, the CAPD
scorecard verdict, Veracode SCA exposure, the QRadar 'were we touched?' result,
and reviewer notes — into a colorful one/two-pager via xhtml2pdf (pisa). Mirrors
``services.phish_report``: xhtml2pdf has no flexbox/grid, so layout is inline-
styled tables + solid background colors. Every section is guarded — only what the
record actually carries is rendered, so an un-enriched advisory still produces a
clean report.

The report is a snapshot of what's already on the ``/cs-advisories/<id>`` page;
the route gathers the data (including cached capability results) and hands a
context dict here.
"""

from __future__ import annotations

import html
import logging
from io import BytesIO
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_BRAND = "#0046ad"
_GREEN = "#00a651"
_INK = "#0f172a"
_MUTE = "#64748b"

# Severity → accent color.
_SEV_COLOR = {
    "critical": "#b91c1c", "high": "#c2410c", "moderate": "#b45309",
    "medium": "#b45309", "low": "#15803d", "info": "#64748b",
}
# CAPD band → (accent, soft background, label).
_BAND_STYLE = {
    "declare": ("#b91c1c", "#fef2f2", "DECLARE CAPD"),
    "monitor": ("#b45309", "#fffbeb", "MONITOR"),
    "none":    ("#15803d", "#f0fdf4", "NO ACTION"),
}
# AI recommendation → accent color.
_REC_COLOR = {"escalate": "#b91c1c", "investigate": "#b45309", "close": "#15803d"}


def _e(v: Any) -> str:
    return html.escape("" if v is None else str(v))


def _section(title: str, body_html: str, accent: str = _BRAND) -> str:
    return (
        f'<table width="100%" cellpadding="0" cellspacing="0" style="margin-top:12px;">'
        f'<tr><td style="border-left:3px solid {accent};padding-left:8px;">'
        f'<div style="color:{_MUTE};font-size:8.5pt;letter-spacing:1px;">{_e(title).upper()}</div>'
        f'<div style="font-size:10pt;color:{_INK};margin-top:3px;">{body_html}</div>'
        f'</td></tr></table>'
    )


def _kv_strip(pairs: List[tuple]) -> str:
    """A row of small labeled boxes (Source / Ecosystem / Published / …)."""
    cells = []
    for label, val in pairs:
        cells.append(
            f'<td style="background:#f8fafc;padding:7px 8px;border:1px solid #e2e8f0;">'
            f'<div style="color:{_MUTE};font-size:7.5pt;">{_e(label).upper()}</div>'
            f'<div style="font-size:10pt;color:{_INK};">{_e(val) or "&mdash;"}</div></td>'
            '<td width="6"></td>'
        )
    return f'<table width="100%" cellpadding="0" cellspacing="0" style="margin-top:10px;"><tr>{"".join(cells)}</tr></table>'


def _table(headers: List[str], rows: List[List[str]]) -> str:
    head = "".join(f'<td style="padding:5px 6px;">{_e(h)}</td>' for h in headers)
    out = [f'<tr style="background:{_BRAND};color:#fff;font-size:8.5pt;">{head}</tr>']
    for i, r in enumerate(rows):
        bg = "#f8fafc" if i % 2 == 0 else "#eef2f7"
        cells = "".join(f'<td style="padding:5px 6px;">{c}</td>' for c in r)  # cells pre-escaped by caller
        out.append(f'<tr style="background:{bg};font-size:8.5pt;color:{_INK};">{cells}</tr>')
    return ('<table width="100%" cellpadding="0" cellspacing="0" '
            'style="margin-top:6px;border:1px solid #e2e8f0;">' + "".join(out) + "</table>")


def build_report_html(ctx: Dict[str, Any]) -> str:
    adv = ctx.get("adv") or {}
    cvss = ctx.get("cvss") or {}
    sev = (adv.get("severity") or "").lower()
    sev_color = _SEV_COLOR.get(sev, _MUTE)
    cve = adv.get("cve_id") or "no CVE"
    cvss_txt = f" &middot; CVSS {_e(cvss.get('score'))}" if cvss.get("score") else ""

    # --- header band (brand) ---
    header = (
        f'<table width="100%" cellpadding="0" cellspacing="0" style="background:{_BRAND};">'
        f'<tr><td style="padding:15px 18px;">'
        f'<div style="color:#ffffff;font-size:17pt;font-weight:bold;">Cyber Security Advisory</div>'
        f'<div style="color:#cde0ff;font-size:9pt;margin-top:2px;">'
        f'the company Cyber Detection &amp; Response &middot; generated {_e(ctx.get("generated_at"))}'
        f'{(" by " + _e(ctx.get("generated_by"))) if ctx.get("generated_by") else ""}</div>'
        f'</td></tr></table>'
    )

    # --- title + severity banner ---
    banner = (
        f'<table width="100%" cellpadding="0" cellspacing="0" style="margin-top:10px;">'
        f'<tr><td style="padding:12px 14px;border:1px solid {sev_color};background:#ffffff;">'
        f'<span style="color:{sev_color};font-size:14pt;font-weight:bold;">{_e(adv.get("source_id"))}</span>'
        f'<span style="color:{_INK};font-size:11pt;"> &nbsp; {_e(cve)}{cvss_txt}</span><br>'
        f'<span style="background-color:{sev_color};color:#fff;font-size:8.5pt;padding:1px 8px;">'
        f'{_e(sev.upper() or "UNSCORED")}</span>'
        f'<span style="color:{_MUTE};font-size:9pt;"> &nbsp; {_e(ctx.get("source_label"))}</span>'
        f'</td></tr></table>'
    )

    # --- meta strip ---
    meta = _kv_strip([
        ("Status", (adv.get("status") or "").replace("_", " ")),
        ("Owner", adv.get("owner") or "unassigned"),
        ("Ecosystem", adv.get("ecosystem") or "n/a"),
        ("Published", (adv.get("published_at") or "")[:10]),
    ])

    parts = [header, banner, meta]

    if adv.get("summary"):
        parts.append(_section("Summary", _e(adv.get("summary"))))

    # --- affected packages ---
    affected = ctx.get("affected") or []
    if affected:
        rows = [[f'<code>{_e(a.get("package"))}</code>', _e(a.get("vulnerable_range")),
                 _e(a.get("first_patched"))] for a in affected[:40]]
        parts.append(_section("Affected packages",
                              _table(["Package", "Vulnerable range", "First patched"], rows)))

    # --- CAPD scorecard verdict ---
    capd = ctx.get("capd")
    if isinstance(capd, dict) and isinstance(capd.get("score"), int):
        accent, soft, label = _BAND_STYLE.get(capd.get("band") or "none", (_MUTE, "#f1f5f9", "—"))
        body = (
            f'<table width="100%"><tr>'
            f'<td><span style="color:{accent};font-size:13pt;font-weight:bold;">{_e(label)}</span></td>'
            f'<td align="right"><span style="font-size:11pt;color:{_INK};">Score '
            f'<b style="color:{accent};">{capd["score"]}/100</b></span></td></tr></table>'
        )
        if capd.get("verdict"):
            body += f'<div style="background:{soft};padding:8px;margin-top:6px;color:{_INK};">{_e(capd.get("verdict"))}</div>'
        cats = [c for c in (capd.get("categories") or []) if c.get("sufficient")]
        if cats:
            rows = [[_e(c.get("label")), f'{_e(c.get("pct"))}%', _e(c.get("evidence"))] for c in cats]
            body += _table(["Category", "Score", "Evidence"], rows)
        parts.append(_section("CAPD decision (Clear and Present Danger)", body, accent))

    # --- AI assessment + extracted intel ---
    ai = ctx.get("ai") if isinstance(ctx.get("ai"), dict) else None
    if ai:
        rec = (ai.get("recommendation") or "").lower()
        rec_color = _REC_COLOR.get(rec, _MUTE)
        body = (
            f'<div><b>Recommendation:</b> '
            f'<span style="background-color:{rec_color};color:#fff;font-size:9pt;padding:1px 8px;">{_e(rec.upper())}</span></div>'
        )
        if ai.get("exposure"):
            body += f'<div style="margin-top:5px;"><b>Likely exposure:</b> {_e(ai.get("exposure"))}</div>'
        if ai.get("rationale"):
            body += f'<div style="margin-top:5px;"><b>Rationale:</b> {_e(ai.get("rationale"))}</div>'
        parts.append(_section("AI assessment", body, _GREEN))

        if ai.get("iocs"):
            rows = [[f'<code>{_e(x.get("type") or "ioc")}</code>', f'<code>{_e(x.get("value"))}</code>',
                     _e(x.get("note"))] for x in ai["iocs"][:40]]
            parts.append(_section("Indicators of compromise (AI-extracted)",
                                  _table(["Type", "Indicator", "Note"], rows), _GREEN))
        if ai.get("ttps"):
            rows = [[f'<code>{_e(t.get("id"))}</code>', _e(t.get("name"))] for t in ai["ttps"][:40]]
            parts.append(_section("MITRE ATT&amp;CK TTPs (AI-extracted)",
                                  _table(["Technique", "Name"], rows), _GREEN))
        if ai.get("threat_actors"):
            rows = [[_e(a.get("name")), _e(a.get("note"))] for a in ai["threat_actors"][:20]]
            parts.append(_section("Threat actors / campaigns",
                                  _table(["Actor", "Note"], rows), _GREEN))
        if ai.get("next_steps"):
            items = "".join(f"<li>{_e(s)}</li>" for s in ai["next_steps"][:15])
            parts.append(_section("Suggested next steps", f'<ol style="margin:0;">{items}</ol>', _GREEN))

    # --- Native Threat Analysis (ATT&CK mapping + generated detection rules + brief) ---
    ta = ctx.get("threat_analysis") if isinstance(ctx.get("threat_analysis"), dict) else None
    if ta and not ta.get("error"):
        brief = ta.get("brief") or {}
        body = _kv_strip([
            ("Severity", ta.get("severity") or "—"),
            ("TLP", ta.get("tlp") or "AMBER"),
            ("Confidence", ta.get("confidence") or "—"),
            ("Brief audience", ta.get("audience_label") or "—"),
        ])
        if brief.get("threat_action"):
            body += f'<div style="margin-top:6px;"><b>Threat action:</b> {_e(brief.get("threat_action"))}</div>'
        if brief.get("detection_focus"):
            body += f'<div style="margin-top:5px;"><b>Detection focus:</b> {_e(brief.get("detection_focus"))}</div>'
        if brief.get("recommended_actions"):
            items = "".join(f"<li>{_e(s)}</li>" for s in brief["recommended_actions"][:10])
            body += f'<div style="margin-top:5px;"><b>Recommended actions:</b><ol style="margin:2px 0 0;">{items}</ol></div>'
        parts.append(_section("Threat analysis", body, _GREEN))

        if ta.get("techniques"):
            rows = [[f'<code>{_e(t.get("technique_id"))}</code>', _e(t.get("technique_name")),
                     _e(t.get("tactic")), _e(t.get("confidence"))] for t in ta["techniques"][:40]]
            parts.append(_section("MITRE ATT&CK techniques (analysis)",
                                  _table(["Technique", "Name", "Tactic", "Confidence"], rows), _GREEN))
        if ta.get("detection_rules"):
            rows = []
            for r in ta["detection_rules"][:40]:
                lint = r.get("lint") if isinstance(r.get("lint"), dict) else None
                lint_txt = (lint.get("summary") or lint.get("status") or "") if lint else ""
                rows.append([f'<code>{_e((r.get("rule_type") or "rule").upper())}</code>',
                             _e(r.get("rule_name")), _e(r.get("related_technique") or "—"), _e(lint_txt)])
            body = _table(["Type", "Rule", "Technique", "Lint"], rows)
            body += ('<div style="margin-top:6px;color:%s;font-size:9pt;">Full rule content is in the '
                     'STIX 2.1 / Markdown export. Validate before deployment.</div>' % _MUTE)
            parts.append(_section("Generated detection rules", body, _GREEN))

    # --- Veracode SCA exposure ---
    vc = ctx.get("veracode") if isinstance(ctx.get("veracode"), dict) else None
    if vc and (vc.get("summary_text") or vc.get("affected_app_count")):
        body = _e(vc.get("summary_text") or "")
        apps = ctx.get("veracode_apps") or []
        if apps:
            rows = [[_e(a.get("application")), _e(a.get("business_unit") or "—"),
                     f'<code>{_e(a.get("component"))}</code>', _e(a.get("version") or "—")]
                    for a in apps[:40]]
            body += _table(["Application", "Business unit", "Component", "Version"], rows)
        parts.append(_section("Veracode SCA exposure", body, _BRAND))

    # --- QRadar 'were we touched?' ---
    qr = ctx.get("qradar") if isinstance(ctx.get("qradar"), dict) else None
    if qr and qr.get("summary_text") and not qr.get("error"):
        parts.append(_section("SIEM check — were we touched? (QRadar, last 1h)", _e(qr.get("summary_text"))))

    # --- Fleet posture (Power BI) ---
    fp = ctx.get("fleet_posture") if isinstance(ctx.get("fleet_posture"), dict) else None
    if fp and fp.get("summary_text") and not fp.get("error"):
        label = "Fleet posture (Power BI" + (f" &middot; {_e(fp.get('dataset'))}" if fp.get("dataset") else "") + ")"
        parts.append(_section(label, _e(fp.get("summary_text"))))

    # --- reviewer notes ---
    notes = (adv.get("notes") or "").strip()
    if notes:
        parts.append(_section("Reviewer notes",
                              f'<div style="background:#f8fafc;padding:8px;border:1px solid #e2e8f0;white-space:pre-wrap;">{_e(notes)}</div>'))

    # --- advisory link + footer ---
    if adv.get("html_url"):
        parts.append(_section("Source advisory", f'<a href="{_e(adv.get("html_url"))}">{_e(adv.get("html_url"))}</a>'))

    footer = (
        '<table width="100%" style="margin-top:18px;border-top:1px solid #e2e8f0;">'
        '<tr><td style="padding-top:6px;color:#94a3b8;font-size:7.5pt;">'
        '<b style="color:#b45309;">TLP:AMBER &mdash; the company Internal.</b> '
        'Generated by the Cyber Security Advisories triage console. AI-extracted indicators and '
        'exposure findings are decision support &mdash; verify before acting. Veracode SCA is '
        'findings-only (not proof of absence).'
        '</td></tr></table>'
    )
    parts.append(footer)

    return (
        '<html><head><style>@page { size: A4; margin: 1.3cm; } '
        'body { font-family: Helvetica, Arial, sans-serif; color:#0f172a; } '
        'code { font-family: Courier, monospace; font-size: 8.5pt; }</style></head>'
        '<body>' + "".join(parts) + "</body></html>"
    )


def build_pdf(ctx: Dict[str, Any]) -> bytes:
    """Render the advisory report context to PDF bytes."""
    from xhtml2pdf import pisa

    html_str = build_report_html(ctx)
    out = BytesIO()
    status = pisa.CreatePDF(src=html_str, dest=out, encoding="utf-8")
    if status.err:
        raise RuntimeError(f"PDF generation failed with {status.err} error(s)")
    return out.getvalue()


def flatten_veracode_apps(vc: Optional[Dict[str, Any]], limit: int = 40) -> List[Dict[str, Any]]:
    """Distinct application rows out of a Veracode exposure result, for the report
    table — dedup on (application, component, version)."""
    if not isinstance(vc, dict):
        return []
    seen = set()
    out: List[Dict[str, Any]] = []
    for bucket in ("cves", "packages"):
        for rows in (vc.get(bucket) or {}).values():
            for r in rows or []:
                key = (r.get("application"), r.get("component"), r.get("version"))
                if r.get("application") and key not in seen:
                    seen.add(key)
                    out.append(r)
                    if len(out) >= limit:
                        return out
    return out
