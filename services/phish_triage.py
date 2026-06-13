"""Phishing sentiment & social-engineering analysis.

Takes a reported email (raw .eml, pasted source, or just the body text), pulls
the deterministic technical signals an analyst would eyeball (sender vs.
reply-to, display-name spoofing, embedded URLs, attachments, auth results) and
hands the content to the local LLM for a sentiment / social-engineering read:
tone, urgency, the manipulation levers being pulled, the pretext, and a verdict.

Two layers on purpose:
  * the parsed signals are facts (no model needed) and always render, so the
    page is useful even if the LLM is down;
  * the LLM verdict is the value-add — calibrated tone/tactic analysis that a
    keyword filter can't do.

Built to show the company already runs PwC's "phishing sentiment analysis" use case
on the local-LLM stack, at zero per-token cost.
"""

from __future__ import annotations

import logging
import re
from email import message_from_string
from email.message import Message
from email.utils import getaddresses, parseaddr
from typing import Any, Dict, List, Optional

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field

from my_bot.utils.llm_factory import create_llm, structured_output

logger = logging.getLogger(__name__)


# ── LLM output contract ─────────────────────────────────────────────────────
class PhishVerdict(BaseModel):
    """The LLM's sentiment / social-engineering read on a reported email."""

    verdict: str = Field(description="One of: 'phishing', 'suspicious', 'likely_benign'")
    confidence: int = Field(description="0-100 confidence in the verdict")
    classification: str = Field(
        description="Best-fit category: 'credential_harvest', 'exec_impersonation_bec', "
        "'invoice_payment_fraud', 'malware_delivery', 'extortion', 'reconnaissance', "
        "'spam_marketing', or 'benign'"
    )
    tone: str = Field(description="The email's emotional tone in 2-4 words, e.g. 'urgent and authoritative', 'friendly but pushy', 'threatening'")
    urgency_level: str = Field(description="How much pressure-to-act the message creates: 'low', 'medium', or 'high'")
    social_engineering_tactics: List[str] = Field(
        description="Manipulation levers pulled, e.g. 'authority', 'urgency', 'fear', "
        "'scarcity', 'reward/greed', 'curiosity', 'familiarity/trust'. Empty if none."
    )
    emotional_triggers: List[str] = Field(
        description="Short phrases from the email that create emotional pressure, quoted/paraphrased. Empty if none."
    )
    pretext: str = Field(description="One sentence: the cover story / lure the sender uses")
    target_action: str = Field(description="One sentence: what the sender wants the recipient to actually DO")
    red_flags: List[str] = Field(description="Concrete suspicious signals an analyst should note. Empty if genuinely none.")
    recommended_action: str = Field(description="Terse SOC next step, e.g. 'Block sender + purge from mailboxes', 'Low risk — close as benign'")
    summary: str = Field(description="2-3 sentence analyst summary in a terse SOC tone")


_SYSTEM = """You are a phishing triage analyst in a security operations center. You are given a reported email — its headers (if present), body text, and the technical signals already extracted by tooling (sender/reply-to mismatch, embedded URLs, attachments, authentication results).

Your job is a SENTIMENT and SOCIAL-ENGINEERING read, not just an IOC check:
- Judge the emotional TONE and how much URGENCY / pressure-to-act the message manufactures.
- Name the SOCIAL-ENGINEERING TACTICS in play (authority, urgency, fear, scarcity, reward/greed, curiosity, familiarity). These are the levers a human analyst feels; surface them explicitly.
- Identify the PRETEXT (the cover story) and the TARGET ACTION (click, reply, pay, open attachment, hand over credentials).
- Weigh the technical signals: a reply-to that differs from the from-address, a display name that doesn't match the sending domain, link text that hides a different destination, and failed SPF/DKIM/DMARC are strong phishing tells. Generic-greeting + urgent-financial-ask + lookalike-domain is the classic BEC pattern.
- Treat attachment reputation as decisive: a WildFire or VirusTotal "malware"/malicious verdict on any attachment means this is phishing/malware-delivery regardless of tone. Office macros (especially auto-exec hooks), double extensions, and type/extension mismatches are strong malicious tells.

Calibrate the verdict honestly:
- 'phishing' — clear malicious intent (credential theft, BEC, malware, extortion) with supporting signals.
- 'suspicious' — manipulative or anomalous but not conclusively malicious; warrants analyst eyes.
- 'likely_benign' — ordinary legitimate mail or low-risk marketing; say so plainly and don't manufacture red flags.

Be terse and concrete. Quote the email's own pressure language in emotional_triggers. Do not invent technical indicators that aren't in the provided signals."""


# ── deterministic email parsing ─────────────────────────────────────────────
_URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.IGNORECASE)
_HTML_HREF_RE = re.compile(r'href=["\']?(https?://[^\s"\'>]+)', re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")


def _looks_like_raw_email(text: str) -> bool:
    """Heuristic: does this text start with RFC-822-ish headers?"""
    head = text.lstrip()[:2000]
    return bool(re.search(r"^(From|Subject|To|Received|Date|Return-Path|Message-ID)\s*:", head, re.IGNORECASE | re.MULTILINE))


def _domain_of(addr: str) -> str:
    _, email_addr = parseaddr(addr or "")
    return email_addr.split("@")[-1].lower() if "@" in email_addr else ""


def _body_from_message(msg: Message) -> str:
    """Pull a text body out of a parsed email — prefer text/plain, fall back to
    stripped text/html, then the raw payload."""
    plain, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            if "attachment" in disp.lower():
                continue
            try:
                payload = part.get_payload(decode=True)
                chunk = payload.decode(part.get_content_charset() or "utf-8", "replace") if payload else ""
            except Exception:
                chunk = ""
            if ctype == "text/plain" and not plain:
                plain = chunk
            elif ctype == "text/html" and not html:
                html = chunk
    else:
        try:
            payload = msg.get_payload(decode=True)
            raw = payload.decode(msg.get_content_charset() or "utf-8", "replace") if payload else (msg.get_payload() or "")
        except Exception:
            raw = msg.get_payload() or ""
        if msg.get_content_type() == "text/html":
            html = raw
        else:
            plain = raw

    if plain.strip():
        return plain.strip()
    if html.strip():
        return re.sub(r"\s+\n", "\n", _TAG_RE.sub(" ", html)).strip()
    return ""


def _attachments(msg: Message) -> List[Dict[str, Any]]:
    """Extract attachments with decoded bytes (bytes used for static analysis,
    stripped from the response before it leaves the service)."""
    out: List[Dict[str, Any]] = []
    if not msg.is_multipart():
        return out
    for part in msg.walk():
        disp = str(part.get("Content-Disposition") or "")
        fname = part.get_filename()
        if fname or "attachment" in disp.lower():
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            out.append({
                "filename": fname or "(unnamed)",
                "content_type": part.get_content_type(),
                "_bytes": payload,
            })
    return out


# Risky attachment extensions worth flagging to the analyst up front.
_RISKY_EXTS = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".jar", ".bat", ".cmd",
    ".ps1", ".hta", ".lnk", ".iso", ".img", ".html", ".htm", ".docm", ".xlsm",
    ".pptm", ".zip", ".rar", ".7z", ".gz", ".ace",
}


def parse_email(text: str) -> Dict[str, Any]:
    """Parse pasted/uploaded email content into structured signals.

    Accepts a full raw email (headers + body), or just a body — falls back
    gracefully so an analyst can paste whatever they have.
    """
    text = (text or "").replace("\r\n", "\n").strip()
    signals: Dict[str, Any] = {
        "from": "", "from_name": "", "from_domain": "",
        "reply_to": "", "reply_to_domain": "",
        "return_path": "", "to": "", "subject": "", "date": "",
        "auth_results": "", "urls": [], "url_domains": [], "attachments": [],
        "risky_attachments": [], "anomalies": [], "body": "", "has_headers": False,
    }

    if _looks_like_raw_email(text):
        signals["has_headers"] = True
        msg = message_from_string(text)
        from_name, from_addr = parseaddr(msg.get("From", ""))
        reply_name, reply_addr = parseaddr(msg.get("Reply-To", ""))
        signals.update(
            {
                "from": from_addr,
                "from_name": from_name,
                "from_domain": _domain_of(from_addr),
                "reply_to": reply_addr,
                "reply_to_domain": _domain_of(reply_addr),
                "return_path": parseaddr(msg.get("Return-Path", ""))[1],
                "to": ", ".join(a for _, a in getaddresses(msg.get_all("To", []))),
                "subject": str(msg.get("Subject", "")),
                "date": str(msg.get("Date", "")),
                "auth_results": str(msg.get("Authentication-Results", "") or msg.get("ARC-Authentication-Results", "")),
            }
        )
        body = _body_from_message(msg)
        signals["attachments"] = _attachments(msg)
    else:
        body = text

    signals["body"] = body

    # URLs: from anchor hrefs (catches link-text spoofing) + bare URLs in text.
    urls: List[str] = []
    for u in _HTML_HREF_RE.findall(text) + _URL_RE.findall(body):
        u = u.rstrip(".,;)\"'>")
        if u not in urls:
            urls.append(u)
    signals["urls"] = urls[:50]
    url_domains: List[str] = []
    for u in signals["urls"]:
        m = re.match(r"https?://([^/:]+)", u, re.IGNORECASE)
        if m and m.group(1).lower() not in url_domains:
            url_domains.append(m.group(1).lower())
    signals["url_domains"] = url_domains

    signals["risky_attachments"] = [
        a["filename"] for a in signals["attachments"]
        if any(a["filename"].lower().endswith(ext) for ext in _RISKY_EXTS)
    ]

    # Deterministic anomalies — cheap, high-signal tells surfaced without the LLM.
    anomalies: List[str] = []
    fd, rd = signals["from_domain"], signals["reply_to_domain"]
    if rd and fd and rd != fd:
        anomalies.append(f"Reply-To domain ({rd}) differs from From domain ({fd})")
    rp = _domain_of(signals["return_path"])
    if rp and fd and rp != fd:
        anomalies.append(f"Return-Path domain ({rp}) differs from From domain ({fd})")
    if signals["from_name"] and fd:
        name_domains = re.findall(r"[A-Za-z0-9.-]+\.(?:com|net|org|io|gov|edu)", signals["from_name"], re.IGNORECASE)
        if any(nd.lower() != fd and nd.lower() not in fd for nd in name_domains):
            anomalies.append(f"Display name references a domain that isn't the sender ({fd})")
    auth = signals["auth_results"].lower()
    for mech in ("spf", "dkim", "dmarc"):
        if f"{mech}=fail" in auth or f"{mech}=softfail" in auth:
            anomalies.append(f"{mech.upper()} authentication failed")
    if signals["risky_attachments"]:
        anomalies.append("Risky attachment type: " + ", ".join(signals["risky_attachments"]))
    signals["anomalies"] = anomalies

    return signals


def _llm_prompt(signals: Dict[str, Any]) -> str:
    L: List[str] = ["Reported email under review.", ""]
    if signals["has_headers"]:
        L += [
            "== Headers ==",
            f"From: {signals['from_name']} <{signals['from']}>" if signals["from"] else "From: (not present)",
            f"Reply-To: {signals['reply_to']}" if signals["reply_to"] else "",
            f"Return-Path: {signals['return_path']}" if signals["return_path"] else "",
            f"To: {signals['to']}" if signals["to"] else "",
            f"Subject: {signals['subject']}",
            f"Date: {signals['date']}" if signals["date"] else "",
            f"Authentication-Results: {signals['auth_results']}" if signals["auth_results"] else "",
            "",
        ]
    else:
        L += ["(No email headers were provided — analyze the body content only.)", ""]

    if signals["anomalies"]:
        L += ["== Technical signals flagged by tooling =="]
        L += [f"- {a}" for a in signals["anomalies"]]
        L += [""]
    if signals["urls"]:
        L += ["== Embedded URLs =="]
        L += [f"- {u}" for u in signals["urls"][:20]]
        L += [""]
    if signals["attachments"]:
        L += ["== Attachments =="]
        for a in signals["attachments"]:
            parts = [f"- {a.get('filename')} ({a.get('true_type') or a.get('content_type')}, {a.get('size', 0)} bytes)"]
            if a.get("static_flags"):
                parts.append("    flags: " + "; ".join(a["static_flags"]))
            wf = a.get("wildfire") or {}
            if wf.get("ok") and wf.get("verdict") not in (None, "not_found", "unknown"):
                parts.append(f"    WildFire verdict: {wf.get('verdict')}")
            vt = a.get("vt") or {}
            if vt.get("ok") and (vt.get("malicious") or vt.get("suspicious")):
                parts.append(f"    VirusTotal: {vt.get('malicious')} malicious / {vt.get('suspicious')} suspicious ({vt.get('threat_level')})")
            L += parts
        L += [""]

    body = signals["body"] or "(empty body)"
    L += ["== Body ==", body[:6000]]
    return "\n".join(x for x in L if x is not None)


def _vt_reputation(file_hash: str) -> Dict[str, Any]:
    """Best-effort VirusTotal hash reputation (read-only)."""
    try:
        from services.virustotal import VirusTotalClient
        vt = VirusTotalClient()
        if not vt.is_configured():
            return {"ok": False, "error": "VT not configured"}
        resp = vt.lookup_hash(file_hash)
        if "error" in resp:
            return {"ok": False, "error": resp["error"]}
        stats = (((resp.get("data") or {}).get("attributes") or {}).get("last_analysis_stats")) or {}
        return {
            "ok": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "threat_level": VirusTotalClient.get_threat_level(stats, is_file=True),
        }
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {str(e)[:120]}"}


def _analyze_attachments(attachments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Static analysis + read-only reputation (VT + WildFire verdict) per file.

    No detonation here — only hash lookups. Detonation is an explicit, separate
    action (see services.wildfire.detonate / the /detonate route).
    """
    from services.attachment_static import analyze_attachment

    results: List[Dict[str, Any]] = []
    for att in attachments:
        data = att.get("_bytes") or b""
        info = analyze_attachment(data, att.get("filename", ""), att.get("content_type", ""))
        # Where the file came from — embedded in the email vs. uploaded standalone.
        info["source"] = att.get("source", "email")
        # Read-only reputation by hash — instant, submits nothing.
        info["vt"] = _vt_reputation(info["sha256"]) if data else {"ok": False, "error": "empty"}
        try:
            from services.wildfire import get_verdict
            info["wildfire"] = get_verdict(info["sha256"]) if data else {"ok": False, "verdict": "unknown"}
        except Exception as e:
            info["wildfire"] = {"ok": False, "verdict": "unknown", "error": str(e)[:120]}
        results.append(info)
    return results


def analyze_email(text: str, extra_attachments: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Full pipeline: parse signals, analyze attachments, then run the LLM read.

    ``extra_attachments`` are standalone files the analyst uploaded directly
    (not embedded in an email) — each a dict with ``filename``/``content_type``/
    ``_bytes``. They get the same static + reputation analysis and are merged
    into ``signals["attachments"]`` tagged ``source="uploaded"``.

    Returns ``{"signals": {...}, "verdict": {...}|None, "llm_error": str|None}``.
    Best-effort — if the LLM is unavailable the signals still come back so the
    page degrades gracefully. When only standalone attachments are submitted (no
    email), the LLM email read is skipped and ``signals["attachment_only"]`` is set.
    """
    signals = parse_email(text)

    # Merge email-embedded attachments with any standalone uploads, then run
    # static + reputation analysis. Raw bytes are stripped before return so they
    # never leave the service in the JSON response.
    raw_attachments = list(signals.get("attachments") or [])
    for att in (extra_attachments or []):
        att = dict(att)
        att["source"] = "uploaded"
        raw_attachments.append(att)
    signals["attachments"] = _analyze_attachments(raw_attachments)

    has_email = bool(signals["body"] or signals["subject"])
    if not has_email and not signals["attachments"]:
        return {"signals": signals, "verdict": None, "llm_error": "Nothing to analyze — paste an email or attach a file."}

    # Attachment-only submission: no email to read, so skip the LLM verdict
    # (not an error — just N/A) and let the attachment analysis stand on its own.
    if not has_email:
        signals["attachment_only"] = True
        return {"signals": signals, "verdict": None, "llm_error": None}

    try:
        chain = structured_output(create_llm(temperature=0), PhishVerdict)
        verdict_obj = chain.invoke([SystemMessage(content=_SYSTEM), HumanMessage(content=_llm_prompt(signals))])
        verdict = verdict_obj.model_dump()
        llm_error = None
    except Exception as e:
        logger.warning("Phishing LLM analysis failed: %s: %s", type(e).__name__, str(e)[:200])
        verdict, llm_error = None, f"{type(e).__name__}: {str(e)[:200]}"

    return {"signals": signals, "verdict": verdict, "llm_error": llm_error}
