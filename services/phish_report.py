"""Stylish PDF report for a phishing sentiment analysis result.

Renders the analyze_email() output to a colorful, branded PDF via xhtml2pdf
(pisa). xhtml2pdf has limited CSS (no flexbox/grid), so layout uses tables and
solid background colors — which still produces a clean, colorful one/two-pager
suitable for handing to leadership or attaching to a case.
"""

from __future__ import annotations

import html
import logging
from datetime import datetime
from io import BytesIO
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Verdict → (accent color, soft background, emoji-free label)
_VERDICT_STYLE = {
    "phishing":      ("#b91c1c", "#fef2f2", "PHISHING"),
    "suspicious":    ("#b45309", "#fffbeb", "SUSPICIOUS"),
    "likely_benign": ("#15803d", "#f0fdf4", "LIKELY BENIGN"),
}
_BRAND = "#0046ad"
_INK = "#0f172a"


def _e(v: Any) -> str:
    return html.escape("" if v is None else str(v))


def _chips_row(items: List[str], bg: str, fg: str) -> str:
    """Inline colored 'chips'. xhtml2pdf chokes on multi-cell auto-width tables,
    so chips are inline spans with background color, not a table."""
    if not items:
        return '<span style="color:#94a3b8">none</span>'
    return " ".join(
        f'<span style="background-color:{bg};color:{fg};padding:2px 7px;font-size:9pt;">{_e(i)}</span>&nbsp;'
        for i in items
    )


def _section(title: str, body_html: str) -> str:
    return (
        f'<table width="100%" cellpadding="0" cellspacing="0" style="margin-top:12px;">'
        f'<tr><td style="border-left:3px solid {_BRAND};padding-left:8px;">'
        f'<div style="color:#64748b;font-size:8.5pt;letter-spacing:1px;">{_e(title).upper()}</div>'
        f'<div style="font-size:10.5pt;color:{_INK};margin-top:3px;">{body_html}</div>'
        f'</td></tr></table>'
    )


def _attachments_table(attachments: List[Dict[str, Any]]) -> str:
    if not attachments:
        return ""
    rows = [
        '<tr style="background:#0046ad;color:#fff;font-size:8.5pt;">'
        '<td style="padding:5px;">File</td><td style="padding:5px;">Type</td>'
        '<td style="padding:5px;">WildFire</td><td style="padding:5px;">VirusTotal</td>'
        '<td style="padding:5px;">Static flags</td></tr>'
    ]
    for i, a in enumerate(attachments):
        wf = a.get("wildfire") or {}
        vt = a.get("vt") or {}
        wf_txt = wf.get("verdict", "—") if wf.get("ok") else "—"
        wf_color = "#b91c1c" if wf_txt in ("malware", "phishing", "c2") else ("#15803d" if wf_txt == "benign" else "#64748b")
        vt_txt = (f"{vt.get('malicious',0)} mal / {vt.get('suspicious',0)} susp" if vt.get("ok") else "—")
        vt_color = "#b91c1c" if (vt.get("ok") and vt.get("malicious")) else "#64748b"
        flags = "; ".join(a.get("static_flags") or []) or "—"
        bg = "#f8fafc" if i % 2 == 0 else "#eef2f7"
        rows.append(
            f'<tr style="background:{bg};font-size:8.5pt;">'
            f'<td style="padding:5px;">{_e(a.get("filename"))}<br>'
            f'<span style="color:#94a3b8;font-size:7pt;">{_e((a.get("sha256") or "")[:32])}…</span></td>'
            f'<td style="padding:5px;">{_e(a.get("true_type") or a.get("content_type"))}</td>'
            f'<td style="padding:5px;color:{wf_color};font-weight:bold;">{_e(wf_txt)}</td>'
            f'<td style="padding:5px;color:{vt_color};">{_e(vt_txt)}</td>'
            f'<td style="padding:5px;color:#b45309;">{_e(flags)}</td></tr>'
        )
    return (
        '<table width="100%" cellpadding="0" cellspacing="0" style="margin-top:6px;border:1px solid #e2e8f0;">'
        + "".join(rows) + "</table>"
    )


def build_report_html(result: Dict[str, Any], generated_at: Optional[str] = None) -> str:
    signals = result.get("signals") or {}
    v = result.get("verdict") or {}
    verdict_key = v.get("verdict", "suspicious")
    accent, soft, label = _VERDICT_STYLE.get(verdict_key, ("#64748b", "#f1f5f9", _e(verdict_key).upper()))
    conf = max(0, min(100, int(v.get("confidence") or 0)))
    generated_at = generated_at or datetime.now().strftime("%Y-%m-%d %H:%M")

    # Header band
    header = (
        f'<table width="100%" cellpadding="0" cellspacing="0" style="background:{_BRAND};">'
        f'<tr><td style="padding:16px 18px;">'
        f'<div style="color:#ffffff;font-size:18pt;font-weight:bold;">Phishing Sentiment Analysis</div>'
        f'<div style="color:#cde0ff;font-size:9pt;margin-top:2px;">'
        f'Cyber Security &middot; on-prem LLM analysis &middot; generated {_e(generated_at)}</div>'
        f'</td></tr></table>'
    )

    # Verdict banner
    banner = (
        f'<table width="100%" cellpadding="0" cellspacing="0" style="background:{soft};margin-top:10px;">'
        f'<tr><td style="padding:14px 16px;border:1px solid {accent};">'
        f'<table width="100%"><tr>'
        f'<td><span style="color:{accent};font-size:17pt;font-weight:bold;">{label}</span>'
        f'<span style="color:#475569;font-size:10pt;"> &nbsp; {_e((v.get("classification") or "").replace("_"," "))}</span></td>'
        f'<td align="right"><span style="color:{_INK};font-size:11pt;">Confidence '
        f'<b style="color:{accent};">{conf}%</b></span></td>'
        f'</tr></table></td></tr></table>'
    )

    # Meta strip (tone / urgency / classification) as a 3-col table
    meta = (
        '<table width="100%" cellpadding="0" cellspacing="0" style="margin-top:10px;">'
        '<tr>'
        f'<td width="33%" style="background:#f8fafc;padding:8px;border:1px solid #e2e8f0;">'
        f'<div style="color:#64748b;font-size:8pt;">TONE</div><div style="font-size:11pt;color:{_INK};">{_e(v.get("tone"))}</div></td>'
        '<td width="2%"></td>'
        f'<td width="32%" style="background:#f8fafc;padding:8px;border:1px solid #e2e8f0;">'
        f'<div style="color:#64748b;font-size:8pt;">URGENCY</div><div style="font-size:11pt;color:{_INK};">{_e(v.get("urgency_level"))}</div></td>'
        '<td width="2%"></td>'
        f'<td width="33%" style="background:#f8fafc;padding:8px;border:1px solid #e2e8f0;">'
        f'<div style="color:#64748b;font-size:8pt;">CLASSIFICATION</div><div style="font-size:11pt;color:{_INK};">{_e((v.get("classification") or "").replace("_"," "))}</div></td>'
        '</tr></table>'
    )

    body_parts = [header, banner, meta]

    if v.get("social_engineering_tactics"):
        body_parts.append(_section("Social-engineering tactics",
                                   _chips_row(v["social_engineering_tactics"], "#eef2ff", "#4338ca")))
    if v.get("emotional_triggers"):
        items = "".join(f"<li>{_e(t)}</li>" for t in v["emotional_triggers"])
        body_parts.append(_section("Emotional triggers", f'<ul style="margin:0;">{items}</ul>'))

    body_parts.append(_section("Pretext & intent",
                               f'<b>Pretext:</b> {_e(v.get("pretext"))}<br><b>Wants recipient to:</b> {_e(v.get("target_action"))}'))

    if v.get("red_flags"):
        body_parts.append(_section("Red flags", _chips_row(v["red_flags"], "#fff1f2", "#be123c")))

    body_parts.append(_section("Recommended action",
                               f'<div style="background:{soft};padding:8px;color:{accent};font-weight:bold;">{_e(v.get("recommended_action"))}</div>'))

    if v.get("summary"):
        body_parts.append(_section("Analyst summary", _e(v.get("summary"))))

    # Technical signals
    tech_rows = []
    if signals.get("has_headers"):
        for k, lbl in (("from", "From"), ("reply_to", "Reply-To"), ("return_path", "Return-Path"),
                       ("subject", "Subject"), ("auth_results", "Auth")):
            if signals.get(k):
                tech_rows.append(f'<b>{lbl}:</b> {_e(signals[k])}')
    if signals.get("anomalies"):
        tech_rows.append('<b>Anomalies:</b> <span style="color:#b45309;">' + _e("; ".join(signals["anomalies"])) + "</span>")
    if signals.get("url_domains"):
        tech_rows.append("<b>Link domains:</b> " + _e(", ".join(signals["url_domains"])))
    if tech_rows:
        body_parts.append(_section("Technical signals", "<br>".join(tech_rows)))

    if signals.get("attachments"):
        body_parts.append(_section("Attachments", _attachments_table(signals["attachments"])))

    footer = (
        '<table width="100%" style="margin-top:18px;border-top:1px solid #e2e8f0;">'
        '<tr><td style="padding-top:6px;color:#94a3b8;font-size:7.5pt;">'
        'Generated by the Cyber Security phishing analysis tool — runs entirely on on-prem LLM infrastructure '
        '(zero per-token cost). WildFire detonation via XSOAR Prod. For internal SOC use.'
        '</td></tr></table>'
    )
    body_parts.append(footer)

    return (
        '<html><head><style>@page { size: A4; margin: 1.4cm; } '
        'body { font-family: Helvetica, Arial, sans-serif; color:#0f172a; }</style></head>'
        '<body>' + "".join(body_parts) + "</body></html>"
    )


def build_pdf(result: Dict[str, Any], generated_at: Optional[str] = None) -> bytes:
    """Render the analysis result to PDF bytes."""
    from xhtml2pdf import pisa

    html_str = build_report_html(result, generated_at=generated_at)
    out = BytesIO()
    status = pisa.CreatePDF(src=html_str, dest=out, encoding="utf-8")
    if status.err:
        raise RuntimeError(f"PDF generation failed with {status.err} error(s)")
    return out.getvalue()
