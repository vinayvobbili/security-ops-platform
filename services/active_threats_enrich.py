"""Active-Threat Intake — slice 2: IOC reputation enrichment.

Takes the IOCs a threat carries and runs each through the reputation providers
the SOC already integrates — VirusTotal, AbuseIPDB, urlscan, Recorded Future —
then folds the per-provider signal into one verdict (malicious / suspicious /
clean / unknown) per indicator, plus an actor-level Recorded Future card when a
named actor is present.

Why a thread, not an inline call: VirusTotal's free tier rate-limits at ~4
req/min, so enriching a report with a dozen indicators can take minutes. The web
route kicks this off in a daemon thread, writes a ``status='running'`` marker
immediately, and the detail page polls until ``status='done'``. All provider
calls are wrapped — one provider being down or unkeyed degrades that cell to
``unknown`` rather than failing the run.

The verdict math here is deterministic provider arithmetic (engine counts, abuse
confidence, RF risk score), not a semantic classifier — so it stays as plain
code, not an LLM call.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Any

from services import active_threats_db as db

logger = logging.getLogger(__name__)

# Bound the slow per-IOC providers (VT/AbuseIPDB) so a giant paste can't run for
# an hour against the VT rate limit. Recorded Future is batched and covers every
# IOC regardless of this cap.
_PER_IOC_PROVIDER_CAP = 30
# Order we spend the per-IOC budget on — the indicator types worth a definitive
# detonation verdict first.
_TYPE_PRIORITY = {"sha256": 0, "sha1": 1, "md5": 2, "url": 3, "ip": 4, "domain": 5}

_VERDICTS = ("malicious", "suspicious", "clean", "unknown")
# Worst-wins ordering when folding multiple providers into one verdict.
_VERDICT_RANK = {"malicious": 3, "suspicious": 2, "clean": 1, "unknown": 0}

# In-process guard so a double-click doesn't launch two enrichment threads for
# the same threat. The DB ``status='running'`` marker is the durable signal;
# this just avoids the immediate race.
_running: set[str] = set()
_running_lock = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _worst(verdicts: list[str]) -> str:
    best = "unknown"
    for v in verdicts:
        if _VERDICT_RANK.get(v, 0) > _VERDICT_RANK.get(best, 0):
            best = v
    return best


# --------------------------------------------------------------------------- #
# Per-provider adapters — each returns a small normalized cell or None.        #
# Every one is wrapped by the caller; they may also return an "error" cell.    #
# --------------------------------------------------------------------------- #

def _vt_cell(ioc_type: str, value: str) -> dict[str, Any] | None:
    """VirusTotal verdict from last-analysis engine stats."""
    from services.virustotal import VirusTotalClient

    client = VirusTotalClient()
    if not client.is_configured():
        return None
    if ioc_type == "ip":
        raw, gui = client.lookup_ip(value), f"ip-address/{value}"
    elif ioc_type == "domain":
        raw, gui = client.lookup_domain(value), f"domain/{value}"
    elif ioc_type == "url":
        raw, gui = client.lookup_url(value), None  # URL id is derived; link to search
    elif ioc_type in ("sha256", "sha1", "md5"):
        raw, gui = client.lookup_hash(value), f"file/{value}"
    else:
        return None

    if not isinstance(raw, dict) or raw.get("error"):
        return {"verdict": "unknown", "detail": (raw or {}).get("error", "no data")}

    stats = (raw.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})) or {}
    mal = int(stats.get("malicious", 0) or 0)
    susp = int(stats.get("suspicious", 0) or 0)
    total = sum(int(v or 0) for v in stats.values()) or 0
    if mal > 0:
        verdict = "malicious"
    elif susp > 0:
        verdict = "suspicious"
    elif total > 0:
        verdict = "clean"
    else:
        verdict = "unknown"
    link = f"https://www.virustotal.com/gui/{gui}" if gui else f"https://www.virustotal.com/gui/search/{value}"
    return {
        "verdict": verdict,
        "malicious": mal,
        "suspicious": susp,
        "total": total,
        "detail": f"{mal}/{total} engines flagged" if total else "not seen by VirusTotal",
        "link": link,
    }


def _abuseipdb_cell(value: str) -> dict[str, Any] | None:
    """AbuseIPDB abuse-confidence score for an IP."""
    from services.abuseipdb import check_ip

    raw = check_ip(value)
    if not isinstance(raw, dict) or not raw.get("success"):
        return None if (raw or {}).get("error") == "API key not configured" else {
            "verdict": "unknown", "detail": (raw or {}).get("error", "no data")}
    score = int(raw.get("abuse_confidence_score", 0) or 0)
    reports = int(raw.get("total_reports", 0) or 0)
    if score >= 75:
        verdict = "malicious"
    elif score >= 25:
        verdict = "suspicious"
    else:
        verdict = "clean"
    bits = [f"{score}% abuse confidence"]
    if reports:
        bits.append(f"{reports} reports")
    if raw.get("country_code"):
        bits.append(raw["country_code"])
    return {
        "verdict": verdict,
        "score": score,
        "reports": reports,
        "detail": " · ".join(bits),
        "link": raw.get("abuseipdb_link") or f"https://www.abuseipdb.com/check/{value}",
    }


def _urlscan_cell(ioc_type: str, value: str) -> dict[str, Any] | None:
    """urlscan.io — read-only search of prior scans (no live submission)."""
    from services.urlscan import URLScanClient

    host = value
    if ioc_type == "url":
        host = value.split("://", 1)[-1].split("/", 1)[0]
    client = URLScanClient()
    raw = client.search_domain(host, size=5)
    if not isinstance(raw, dict):
        return None
    results = raw.get("results") or raw.get("data") or []
    n = len(results) if isinstance(results, list) else int(raw.get("total", 0) or 0)
    if not n:
        return None
    return {
        "verdict": "unknown",  # urlscan presence is context, not a verdict
        "scans": n,
        "detail": f"{n} prior scan{'s' if n != 1 else ''} on urlscan",
        "link": f"https://urlscan.io/search/#{host}",
    }


def _rf_verdict(score: int) -> str:
    if score >= 65:
        return "malicious"
    if score >= 25:
        return "suspicious"
    if score > 0:
        return "clean"
    return "unknown"


def _rf_batch(by_type: dict[str, list[str]]) -> dict[str, dict[str, Any]]:
    """One batched Recorded Future enrich call covering every IOC.

    Returns ``{value_lower: cell}``. RF covers all indicators regardless of the
    per-IOC provider cap, so even capped reports get a risk score on every row.
    """
    out: dict[str, dict[str, Any]] = {}
    try:
        from services.recorded_future import get_client

        client = get_client()
        if not getattr(client, "is_configured", lambda: True)():
            return out
        ips = by_type.get("ip", [])
        domains = by_type.get("domain", [])
        hashes = by_type.get("sha256", []) + by_type.get("sha1", []) + by_type.get("md5", [])
        urls = by_type.get("url", [])
        if not any((ips, domains, hashes, urls)):
            return out
        resp = client.enrich(
            ips=ips or None, domains=domains or None,
            hashes=hashes or None, urls=urls or None,
        )
        for r in client.extract_enrichment_results(resp):
            val = (r.get("value") or "").strip()
            if not val:
                continue
            score = int(r.get("risk_score", 0) or 0)
            rules = [x for x in (r.get("rules") or []) if x][:6]
            eid = r.get("entity_id")
            out[val.lower()] = {
                "verdict": _rf_verdict(score),
                "score": score,
                "level": r.get("risk_level"),
                "rules": rules,
                "detail": (f"RF risk {score} ({r.get('risk_level')})"
                           + (f" — {rules[0]}" if rules else "")),
                "link": (f"https://app.recordedfuture.com/live/sc/entity/{eid}" if eid else None),
            }
    except Exception as e:
        logger.warning("[ActiveThreats] RF batch enrich failed: %s", e)
    return out


def _actor_card(actor: str) -> dict[str, Any] | None:
    """Recorded Future actor Intelligence Card for a named adversary."""
    if not actor:
        return None
    try:
        from services.recorded_future import RecordedFutureClient, get_client

        client = get_client()
        match = client.lookup_actor_by_name(actor)
        if not isinstance(match, dict) or match.get("error"):
            return None
        if match.get("match") == "single":
            summ = RecordedFutureClient.extract_actor_summary(match["actor"])
        elif match.get("match") == "multiple" and match.get("actors"):
            summ = RecordedFutureClient.extract_actor_summary(match["actors"][0])
        else:
            return None
        eid = summ.get("id")
        return {
            "name": summ.get("name") or actor,
            "risk_score": summ.get("risk_score"),
            "aliases": [a for a in (summ.get("aliases") or summ.get("common_names") or []) if a][:12],
            "categories": [c for c in (summ.get("categories") or []) if c][:10],
            "target_industries": [i for i in (summ.get("target_industries") or []) if i][:10],
            "link": (f"https://app.recordedfuture.com/live/sc/entity/{eid}" if eid else None),
        }
    except Exception as e:
        logger.warning("[ActiveThreats] RF actor lookup failed for %r: %s", actor, e)
        return None


# --------------------------------------------------------------------------- #
# Orchestration                                                               #
# --------------------------------------------------------------------------- #

def enrich_threat_sync(threat: dict[str, Any]) -> dict[str, Any]:
    """Run all providers for one threat and return the normalized enrichment blob.

    Synchronous (slow) — call via :func:`start_enrichment` for the web path.
    """
    iocs = [i for i in (threat.get("iocs") or []) if isinstance(i, dict) and i.get("value")]
    # De-dupe and bucket by type for the RF batch + per-IOC budgeting.
    seen: set[str] = set()
    ordered: list[dict[str, str]] = []
    by_type: dict[str, list[str]] = {}
    for i in iocs:
        val = str(i["value"]).strip()
        typ = (i.get("type") or "other").strip().lower()
        k = val.lower()
        if not val or k in seen:
            continue
        seen.add(k)
        ordered.append({"type": typ, "value": val, "note": i.get("note", "")})
        by_type.setdefault(typ, []).append(val)

    rf_by_value = _rf_batch(by_type)

    # Spend the per-IOC (VT/AbuseIPDB/urlscan) budget on the highest-value types.
    ranked = sorted(ordered, key=lambda i: _TYPE_PRIORITY.get(i["type"], 9))
    budgeted = {id(i) for i in ranked[:_PER_IOC_PROVIDER_CAP]}
    capped = max(0, len(ordered) - _PER_IOC_PROVIDER_CAP)

    results: list[dict[str, Any]] = []
    for i in ordered:
        typ, val = i["type"], i["value"]
        providers: dict[str, Any] = {}
        rf = rf_by_value.get(val.lower())
        if rf:
            providers["recordedfuture"] = rf

        if id(i) in budgeted:
            if typ in ("ip", "domain", "url", "sha256", "sha1", "md5"):
                try:
                    cell = _vt_cell(typ, val)
                    if cell:
                        providers["virustotal"] = cell
                except Exception as e:
                    logger.debug("VT cell failed for %s: %s", val, e)
            if typ == "ip":
                try:
                    cell = _abuseipdb_cell(val)
                    if cell:
                        providers["abuseipdb"] = cell
                except Exception as e:
                    logger.debug("AbuseIPDB cell failed for %s: %s", val, e)
            if typ in ("url", "domain"):
                try:
                    cell = _urlscan_cell(typ, val)
                    if cell:
                        providers["urlscan"] = cell
                except Exception as e:
                    logger.debug("urlscan cell failed for %s: %s", val, e)

        verdict = _worst([c.get("verdict", "unknown") for c in providers.values()]) if providers else "unknown"
        results.append({
            "type": typ, "value": val, "note": i.get("note", ""),
            "verdict": verdict, "providers": providers,
        })

    summary = {v: 0 for v in _VERDICTS}
    for r in results:
        summary[r["verdict"]] = summary.get(r["verdict"], 0) + 1
    summary["total"] = len(results)

    return {
        "status": "done",
        "started_at": threat.get("_enrich_started_at") or _now_iso(),
        "finished_at": _now_iso(),
        "iocs": results,
        "summary": summary,
        "capped": capped,
        "actor": _actor_card(threat.get("actor", "")),
    }


def _run(uid: str, threat: dict[str, Any]) -> None:
    try:
        threat["_enrich_started_at"] = _now_iso()
        blob = enrich_threat_sync(threat)
        db.save_enrichment(uid, blob)
    except Exception as e:
        logger.exception("[ActiveThreats] enrichment thread crashed for %s", uid)
        db.save_enrichment(uid, {"status": "error", "error": str(e), "finished_at": _now_iso()})
    finally:
        with _running_lock:
            _running.discard(uid)


def start_enrichment(key: str) -> dict[str, Any]:
    """Kick off enrichment in a daemon thread; return immediately.

    Idempotent-ish: if a run is already in flight for this threat, returns the
    running marker instead of launching a second thread.
    """
    threat = db.get_threat(key)
    if not threat:
        return {"ok": False, "error": "threat not found"}
    uid = threat.get("uid") or key
    if not (threat.get("iocs") or []):
        blob = {"status": "done", "iocs": [], "summary": {v: 0 for v in _VERDICTS} | {"total": 0},
                "finished_at": _now_iso(), "actor": _actor_card(threat.get("actor", ""))}
        db.save_enrichment(uid, blob)
        return {"ok": True, "status": "done", "enrichment": blob}

    with _running_lock:
        if uid in _running:
            return {"ok": True, "status": "running"}
        _running.add(uid)

    db.save_enrichment(uid, {"status": "running", "started_at": _now_iso()})
    t = threading.Thread(target=_run, args=(uid, threat), daemon=True,
                         name=f"at-enrich-{uid[:24]}")
    t.start()
    return {"ok": True, "status": "running"}
