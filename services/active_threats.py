"""Active-Threat Intake service — adversary-centric sibling to cs-advisories.

The heart of this module is :func:`ingest_report`: an analyst (slice 1) pastes a
threat report — an actor write-up, a campaign bulletin, a phishing/ransomware
advisory, a Recorded Future note — and a local LLM extracts the structured
fields the desk acts on: actor, campaign, threat type, severity, a tight
summary, the in-the-wild IOCs, the MITRE ATT&CK TTPs, and the recommended
actions. The result is upserted into the ``active_threats`` queue.

LLM-first, per house style: the model does the semantic extraction. A small
non-semantic IOC regex runs only as a backstop to recover indicators the model
may have missed (defanged URLs, hashes) — it never classifies. If the LLM is
unavailable the ingest still succeeds with the backstop IOCs and a stub record,
so a paste is never lost.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import Any

from my_config import get_config
from services import active_threats_db as db

logger = logging.getLogger(__name__)
CONFIG = get_config()

# ---- non-semantic IOC backstop (recovery only; the LLM is primary) ----------
_DEFANG = {"[.]": ".", "(.)": ".", "[dot]": ".", "hxxp": "http", "[:]": ":", "[at]": "@"}
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
_URL = re.compile(r"\bhttps?://[^\s)<>\"']+", re.I)
_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
_SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.I)
_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.I)
_EMAIL = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.I)
# Domains that are reporting infra / common noise, never the indicator itself.
_DOMAIN_NOISE = {
    "github.com", "twitter.com", "x.com", "linkedin.com", "microsoft.com",
    "mitre.org", "attack.mitre.org", "virustotal.com", "abuse.ch",
    "recordedfuture.com", "cisa.gov", "bleepingcomputer.com",
}


def _refang(text: str) -> str:
    for k, v in _DEFANG.items():
        text = text.replace(k, v)
    return text


def _backstop_iocs(text: str) -> list[dict[str, str]]:
    """Mechanically recover indicators from raw text. Non-semantic backstop."""
    t = _refang(text or "")
    found: dict[str, dict[str, str]] = {}

    def _add(ioc_type: str, value: str) -> None:
        v = value.strip().strip(".,);:'\"")
        if v and v.lower() not in found:
            found[v.lower()] = {"type": ioc_type, "value": v, "note": ""}

    for m in _URL.findall(t):
        _add("url", m)
    for m in _SHA256.findall(t):
        _add("sha256", m)
    for m in _SHA1.findall(t):
        _add("sha1", m)
    for m in _MD5.findall(t):
        _add("md5", m)
    for m in _IPV4.findall(t):
        parts = m.split(".")
        if all(0 <= int(p) <= 255 for p in parts) and m != "0.0.0.0":
            _add("ip", m)
    for m in _EMAIL.findall(t):
        _add("email", m)
    for m in _DOMAIN.findall(t):
        d = m.lower()
        if d in _DOMAIN_NOISE or d.endswith(".png") or d.endswith(".jpg"):
            continue
        # Skip domains that are actually part of a URL/email already captured.
        if any(d in v for v in found):
            continue
        _add("domain", m)
    return list(found.values())[:200]


def _extract_json(text: str) -> Any:
    """Pull the first JSON object/array out of an LLM reply (shared shape)."""
    if not text:
        return None
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1] if "```" in text[3:] else text.strip("`")
        text = text.lstrip("json").strip()
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass
    return None


_EXTRACT_SYS = (
    "You are a threat-intelligence analyst extracting structured fields from an "
    "active-threat report (an actor profile, campaign bulletin, phishing or "
    "ransomware advisory, or vendor intel note) for a SOC's active-threat queue. "
    "Read the report and reply with ONLY a JSON object, no prose:\n"
    "{\n"
    '  "title": "<short headline, <=120 chars>",\n'
    '  "actor": "<threat actor / group name, or \"\" if none named>",\n'
    '  "campaign": "<campaign / operation name, or \"\">",\n'
    '  "threat_type": "ransomware|phishing|malware|apt|infostealer|botnet|vulnerability_exploitation|fraud|other",\n'
    '  "severity": "critical|high|medium|low|info",\n'
    '  "summary": "<=400 chars, what the threat is and why it matters to defenders>",\n'
    '  "aliases": ["other names for the actor/malware"],\n'
    '  "ttps": [{"id": "T1566", "name": "Phishing"}],\n'
    '  "iocs": [{"type": "domain|ip|url|sha256|sha1|md5|email", "value": "<indicator>", "note": "<role, e.g. C2/payload/sender>"}],\n'
    '  "recommended_actions": ["concrete defender action", "..."]\n'
    "}\n"
    "Extract every IOC you can find, refanged to its real form (hxxp->http, "
    "[.]->.). Use MITRE ATT&CK technique IDs where you can. Choose the single "
    "best threat_type. If a field is unknown use \"\" or []."
)


def _extract_threat(text: str) -> dict[str, Any]:
    """LLM-extract structured threat fields from a pasted report.

    LLM is primary; merges in any backstop IOCs the model missed. Falls back to
    a stub (title from first line + backstop IOCs) if the LLM is unavailable so
    a paste is never dropped.
    """
    backstop = _backstop_iocs(text)
    data: dict[str, Any] = {}
    try:
        from my_bot.utils.llm_factory import create_llm
        from langchain_core.messages import HumanMessage, SystemMessage

        resp = create_llm().invoke(
            [SystemMessage(content=_EXTRACT_SYS),
             HumanMessage(content=f"REPORT:\n{text[:12000]}")]
        )
        raw = resp.content if hasattr(resp, "content") else str(resp)
        parsed = _extract_json(raw)
        if isinstance(parsed, dict):
            data = parsed
    except Exception as e:
        logger.warning("[ActiveThreats] LLM extraction failed (%s) — using backstop", e)

    # Normalize + merge.
    iocs = data.get("iocs") if isinstance(data.get("iocs"), list) else []
    norm_iocs: dict[str, dict[str, str]] = {}
    for it in iocs:
        if isinstance(it, dict) and it.get("value"):
            v = str(it["value"]).strip()
            norm_iocs[v.lower()] = {
                "type": (it.get("type") or "other").strip(),
                "value": v,
                "note": (it.get("note") or "").strip(),
            }
    for b in backstop:  # recover anything the model missed
        norm_iocs.setdefault(b["value"].lower(), b)

    ttps = []
    for tt in (data.get("ttps") if isinstance(data.get("ttps"), list) else []):
        if isinstance(tt, dict) and (tt.get("id") or tt.get("name")):
            ttps.append({"id": (tt.get("id") or "").strip(),
                         "name": (tt.get("name") or "").strip()})
        elif isinstance(tt, str) and tt.strip():
            ttps.append({"id": tt.strip(), "name": ""})

    threat_type = (data.get("threat_type") or "other").strip()
    if threat_type not in db.THREAT_TYPES:
        threat_type = "other"
    severity = (data.get("severity") or "medium").strip()
    if severity not in db.SEVERITIES:
        severity = "medium"

    first_line = next((ln.strip() for ln in (text or "").splitlines() if ln.strip()), "Untitled threat")
    title = (data.get("title") or first_line)[:120].strip()

    return {
        "title": title,
        "actor": (data.get("actor") or "").strip(),
        "campaign": (data.get("campaign") or "").strip(),
        "threat_type": threat_type,
        "severity": severity,
        "summary": (data.get("summary") or first_line)[:400].strip(),
        "aliases": [str(a).strip() for a in (data.get("aliases") or []) if str(a).strip()][:20],
        "ttps": ttps[:40],
        "iocs": list(norm_iocs.values())[:300],
        "recommended_actions": [str(a).strip() for a in (data.get("recommended_actions") or [])
                                if str(a).strip()][:30],
    }


def _source_id_for(extracted: dict[str, Any], text: str) -> str:
    """Stable, URL-friendly id. Prefer actor/campaign slug; else content hash so
    re-pasting the identical report dedups instead of stacking rows."""
    anchor = (extracted.get("actor") or extracted.get("campaign") or extracted.get("title") or "").strip()
    digest = hashlib.sha1((anchor + "|" + (text or "")[:2000]).encode("utf-8", "ignore")).hexdigest()[:12]
    slug = re.sub(r"[^a-z0-9]+", "-", anchor.lower()).strip("-")[:40] if anchor else "threat"
    return f"{slug}-{digest}" if slug else digest


def ingest_report(text: str, *, source: str = "manual", created_by: str = "",
                  source_id: str | None = None) -> dict[str, Any]:
    """Ingest an active-threat report → structured queue row.

    Returns ``{"ok", "uid", "key", "new", "threat"}``. ``new`` is False when the
    same report was already ingested. Manual pastes dedup by content hash; feed
    pollers (slice 5) pass an explicit stable ``source_id`` (the RF alert/note
    id) so re-polling the same item is an idempotent no-op.
    """
    text = (text or "").strip()
    if len(text) < 20:
        return {"ok": False, "error": "Report text is too short to extract a threat."}

    extracted = _extract_threat(text)
    source_id = (source_id or "").strip() or _source_id_for(extracted, text)
    uid = db.make_uid(source, source_id)
    rec = {
        **extracted,
        "source": source,
        "source_id": source_id,
        "raw_report": text[:20000],
        "created_by": created_by,
    }
    inserted = db.upsert_threat(rec)
    return {
        "ok": True,
        "uid": uid,
        "key": source_id,
        "new": inserted,
        "threat": db.get_threat(uid),
    }
