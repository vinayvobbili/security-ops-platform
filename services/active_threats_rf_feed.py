"""Active-Threat Intake — slice 5: Recorded Future auto-ingest.

Slices 1-4 gave the desk a manual paste box, enrichment, a hunt wire, and a
block wire. This slice fills the queue *on its own*: a poller pulls Recorded
Future's live advisory firehose — triggered Connect-API alerts (the firm's
own alert rules: new-critical/pre-NVD vulnerabilities, OSS zero-days,
tech-stack exposure, exploit chatter) and Insikt analyst notes (ransomware
roundups, threat-lead write-ups) — and runs each one through the *same* slice-1
LLM extractor that handles a human paste. The result is the slice that lets
Threat-Intel retire the manual CVE/actor tippers: the intel that used to be
copied into a Webex room by hand now lands in the structured queue by itself.

Design choices, consistent with the rest of the desk:

* **One extractor, not two.** An RF alert/note is just text; we render it to a
  report string and call ``active_threats.ingest_report``. The classification
  (threat_type / severity / actor / IOCs / TTPs) is the LLM's job — the alert's
  *rule name* is fed in as context, never hand-mapped with a regex (house rule:
  no regex classifier over an LLM that already classifies).
* **Idempotent.** Each item ingests under a stable ``source_id`` (``rf-alert-<id>``
  / ``rf-note-<id>``); a per-feed high-water cursor in ``active_threats_meta``
  bounds the query window so a re-poll only does work on genuinely new items,
  and an existence check skips the LLM entirely for anything already in the queue.
* **Read-only + safe to run anywhere.** This only *reads* RF and *writes* the
  local queue — no outward action — so unlike the block wire it needs no prod
  gate. It is registered on the detection-engineering scheduler (prod fleet);
  on dev it can be invoked directly against the isolated DB.
* **Never raises.** A scheduler job must not throw; every fetch/parse/ingest is
  guarded and the worst case is "0 ingested this cycle".
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from services import active_threats as at
from services import active_threats_db as db

logger = logging.getLogger(__name__)

SOURCE = "recorded_future"
_ALERT_CURSOR = "rf_alert_cursor"
_NOTE_CURSOR = "rf_note_cursor"

# Entity types RF attaches to an alert/note that are real indicators worth
# surfacing to the extractor as an "Indicators" block (the backstop regex then
# recovers them too). Everything else (IndustryTerm, Person, Source, …) is noise.
_IOC_ENTITY_TYPES = {
    "IpAddress": "ip", "InternetDomainName": "domain", "URL": "url",
    "Hash": "hash", "MD5": "md5", "SHA-1": "sha1", "SHA-256": "sha256",
}
# Context entity types worth naming in the report so the LLM can set actor /
# malware / CVE fields — context, not indicators.
_CONTEXT_ENTITY_TYPES = {
    "Malware": "malware", "CyberVulnerability": "vulnerability",
    "Organization": "org", "Company": "org", "Product": "product",
    "MitreAttackIdentifier": "attack",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _date_only(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d")


def _parse_dt(s: str) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _window_start(cursor_key: str, lookback_hours: int) -> tuple[datetime, datetime | None]:
    """Return (query_from, cursor_dt). The query starts at the cursor (minus a
    small overlap to survive boundary jitter) but never reaches back further
    than ``lookback_hours`` on a cold start."""
    cursor_dt = _parse_dt(db.get_meta(cursor_key, ""))
    floor = _now() - timedelta(hours=lookback_hours)
    if cursor_dt:
        start = cursor_dt - timedelta(minutes=10)  # overlap; upsert dedups
        return (max(start, floor), cursor_dt)
    return (floor, None)


# --------------------------------------------------------------------------- #
# Rendering RF objects → a report string the slice-1 extractor reads.          #
# --------------------------------------------------------------------------- #

def _walk_entities(node: Any, out: list[dict[str, str]], seen: set[str], depth: int = 0) -> None:
    """Depth-first collect ``{id,name,type}`` leaves from RF's nested alert
    ``entities`` tree (entities → documents → references → entities)."""
    if depth > 8 or not node:
        return
    if isinstance(node, list):
        for item in node:
            _walk_entities(item, out, seen, depth + 1)
        return
    if isinstance(node, dict):
        typ, name = node.get("type"), node.get("name")
        if isinstance(typ, str) and isinstance(name, str) and name.strip():
            key = f"{typ}:{name}".lower()
            if key not in seen:
                seen.add(key)
                out.append({"type": typ, "name": name.strip()})
        for v in node.values():
            if isinstance(v, (list, dict)):
                _walk_entities(v, out, seen, depth + 1)


def _split_entities(entities: list[dict[str, str]]) -> tuple[list[str], list[str]]:
    """Split flat ``{type,name}`` entities into (indicator lines, context lines)."""
    iocs: list[str] = []
    context: list[str] = []
    for e in entities:
        typ, name = e.get("type", ""), e.get("name", "")
        if typ in _IOC_ENTITY_TYPES:
            iocs.append(f"{_IOC_ENTITY_TYPES[typ]}: {name}")
        elif typ in _CONTEXT_ENTITY_TYPES:
            context.append(f"{_CONTEXT_ENTITY_TYPES[typ]}: {name}")
    return iocs[:120], context[:60]


def _alert_to_report(alert: dict[str, Any], detail: dict[str, Any] | None) -> str:
    """Render one triggered alert into a report string for the extractor."""
    rule = (alert.get("rule") or {}).get("name") or ""
    title = alert.get("title") or rule or "Recorded Future alert"
    triggered = alert.get("triggered") or ""
    ai = alert.get("ai_insights") or {}
    summary = (ai.get("text") or "").strip()
    if not summary:
        c = (ai.get("comment") or "").strip()
        summary = c if c and "has not yet been generated" not in c.lower() else ""

    entities: list[dict[str, str]] = []
    src = (detail or {}).get("data", detail) if detail else None
    if isinstance(src, dict):
        _walk_entities(src.get("entities"), entities, set())
    iocs, context = _split_entities(entities)

    parts = [f"Recorded Future Alert: {title}"]
    if rule and rule not in title:
        parts.append(f"Alert rule: {rule}")
    if triggered:
        parts.append(f"Triggered: {triggered}")
    if summary:
        parts.append(f"\n{summary}")
    if context:
        parts.append("\nContext:\n" + "\n".join(context))
    if iocs:
        parts.append("\nIndicators:\n" + "\n".join(iocs))
    if alert.get("url"):
        parts.append(f"\nSource: {alert['url']}")
    return "\n".join(parts)


def _note_to_report(note: dict[str, Any]) -> str:
    """Render one Insikt analyst note into a report string for the extractor."""
    attrs = note.get("attributes") or note
    title = (attrs.get("title") or "Recorded Future analyst note").strip()
    published = attrs.get("published") or ""
    topics = [t.get("name") for t in (attrs.get("topic") or []) if isinstance(t, dict) and t.get("name")]
    text = (attrs.get("text") or "").strip()

    indicators: list[str] = []
    for e in (attrs.get("note_entities") or []):
        if isinstance(e, dict) and e.get("type") in _IOC_ENTITY_TYPES and e.get("name"):
            indicators.append(f"{_IOC_ENTITY_TYPES[e['type']]}: {e['name'].strip()}")

    parts = [f"Recorded Future Insikt Note: {title}"]
    if topics:
        parts.append("Topics: " + ", ".join(topics[:8]))
    if published:
        parts.append(f"Published: {published}")
    if text:
        parts.append(f"\n{text[:10000]}")
    if indicators:
        parts.append("\nIndicators:\n" + "\n".join(indicators[:120]))
    return "\n".join(parts)


# --------------------------------------------------------------------------- #
# Poll                                                                        #
# --------------------------------------------------------------------------- #

def _ingest_item(source_id: str, report: str) -> tuple[bool, dict | None]:
    """Ingest one rendered item under a stable id; skip the LLM if already seen.

    Returns ``(is_new, threat_or_None)``.
    """
    uid = db.make_uid(SOURCE, source_id)
    if db.get_threat(uid):
        return (False, None)  # already in the queue — don't re-run extraction
    if len((report or "").strip()) < 20:
        return (False, None)
    res = at.ingest_report(report, source=SOURCE, source_id=source_id, created_by="rf-feed")
    if not res.get("ok"):
        return (False, None)
    return (bool(res.get("new")), res.get("threat"))


def poll_rf_feed(*, lookback_hours: int = 72, max_alerts: int = 50,
                 max_notes: int = 25, room_id: str | None = None) -> dict[str, Any]:
    """Pull recent RF alerts + Insikt notes and auto-ingest the new ones.

    Idempotent and never raises (scheduler-safe). Returns a small summary dict
    ``{ok, alerts_new, notes_new, ingested:[...], errors:[...]}``.
    """
    summary: dict[str, Any] = {"ok": True, "alerts_new": 0, "notes_new": 0,
                               "ingested": [], "errors": []}
    try:
        from services.recorded_future import get_client
        client = get_client()
        if not client.is_configured():
            summary.update(ok=False, errors=["Recorded Future API key not configured"])
            return summary
    except Exception as e:
        summary.update(ok=False, errors=[f"RF client init failed: {e}"])
        return summary

    now = _now()

    # ---- triggered alerts ----------------------------------------------------
    try:
        a_from, _ = _window_start(_ALERT_CURSOR, lookback_hours)
        resp = client.search_alerts(triggered_from=_date_only(a_from),
                                    triggered_to=_date_only(now), limit=max_alerts)
        results = ((resp or {}).get("data") or {}).get("results") or []
        max_dt = None
        for a in results:
            adt = _parse_dt(a.get("triggered") or "")
            if max_dt is None or (adt and adt > max_dt):
                max_dt = adt or max_dt
            aid = a.get("id")
            if not aid:
                continue
            try:
                detail = client.get_alert(aid)
            except Exception:
                detail = None
            report = _alert_to_report(a, detail if isinstance(detail, dict) and not detail.get("error") else None)
            is_new, threat = _ingest_item(f"rf-alert-{aid}", report)
            if is_new:
                summary["alerts_new"] += 1
                summary["ingested"].append({"kind": "alert", "id": aid,
                                            "title": (threat or {}).get("title", "")})
        if max_dt:
            db.set_meta(_ALERT_CURSOR, _iso(max_dt))
    except Exception as e:
        logger.exception("[ActiveThreats] RF alert poll failed")
        summary["errors"].append(f"alerts: {e}")

    # ---- Insikt analyst notes ------------------------------------------------
    try:
        n_from, _ = _window_start(_NOTE_CURSOR, lookback_hours)
        resp = client.search_analyst_notes(published_from=_date_only(n_from),
                                           published_to=_date_only(now), limit=max_notes)
        results = ((resp or {}).get("data") or {}).get("results") or []
        max_dt = None
        for n in results:
            attrs = n.get("attributes") or {}
            ndt = _parse_dt(attrs.get("published") or "")
            if max_dt is None or (ndt and ndt > max_dt):
                max_dt = ndt or max_dt
            nid = n.get("id")
            if not nid:
                continue
            report = _note_to_report(n)
            is_new, threat = _ingest_item(f"rf-note-{nid}", report)
            if is_new:
                summary["notes_new"] += 1
                summary["ingested"].append({"kind": "note", "id": nid,
                                            "title": (threat or {}).get("title", "")})
        if max_dt:
            db.set_meta(_NOTE_CURSOR, _iso(max_dt))
    except Exception as e:
        logger.exception("[ActiveThreats] RF note poll failed")
        summary["errors"].append(f"notes: {e}")

    total_new = summary["alerts_new"] + summary["notes_new"]
    logger.info("[ActiveThreats] RF feed poll: %d new (%d alerts, %d notes)%s",
                total_new, summary["alerts_new"], summary["notes_new"],
                f", {len(summary['errors'])} errors" if summary["errors"] else "")

    if room_id and total_new:
        try:
            _post_digest(room_id, summary)
        except Exception:
            logger.exception("[ActiveThreats] RF feed digest post failed")

    return summary


def _post_digest(room_id: str, summary: dict[str, Any]) -> None:
    """Optional Webex digest when new threats were auto-ingested (opt-in)."""
    from my_config import get_config
    from webexpythonsdk import WebexAPI
    from src.utils.webex_messaging import send_message  # lazy: avoid import cost

    token = get_config().webex_bot_access_token_toodles
    if not token or not room_id:
        return
    n = summary["alerts_new"] + summary["notes_new"]
    lines = [f"🛰️ **{n} new active threat{'s' if n != 1 else ''}** auto-ingested "
             f"from Recorded Future into the Active-Threat desk 🔎"]
    for it in summary["ingested"][:12]:
        tag = "🚨 Alert" if it["kind"] == "alert" else "📝 Insikt note"
        lines.append(f"• {tag}: {it.get('title') or it.get('id')}")
    send_message(WebexAPI(access_token=token), room_id, markdown="\n".join(lines))
