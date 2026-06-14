"""'Were we touched?' exposure hunt for a malicious domain.

Given a confirmed/suspected malicious domain, ask the question that actually
matters: did any internal host or user resolve or connect to it? Reuses the
tipper IOC fan-out (``hunt_iocs``) across DNS/proxy (QRadar) and EDR
(CrowdStrike) — XSIAM is opt-in. SIEM queries are slow, so the public entry
point runs the hunt on a background thread and writes the result back to the
findings ledger; the dashboard polls the finding for status.
"""

import logging
import re
import threading
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlencode

logger = logging.getLogger(__name__)

# Lookback windows. EDR retains longer than the proxy/DNS logs, so cast a wider
# net there. These mirror the tipper hunt defaults.
_QRADAR_HOURS = 168    # 7 days
_CROWDSTRIKE_HOURS = 720  # 30 days
_DEFAULT_TOOLS = ["qradar", "crowdstrike"]


def _collect_hits(tool_result) -> Dict[str, Any]:
    """Flatten a ToolHuntResult into {hits, hosts, users, sources, errors}."""
    if not tool_result:
        return {"hits": 0, "hosts": [], "users": [], "sources": [], "errors": []}
    hosts, users, sources = set(), set(), set()
    for hit in (getattr(tool_result, "domain_hits", None) or []):
        for h in (hit.get("hosts") or hit.get("hostnames") or []):
            if h:
                hosts.add(str(h))
        for u in (hit.get("users") or []):
            if u:
                users.add(str(u))
        for s in (hit.get("sources") or []):
            if s:
                sources.add(str(s))
    return {
        "hits": getattr(tool_result, "total_hits", 0) or 0,
        "hosts": sorted(hosts)[:50],
        "users": sorted(users)[:50],
        "sources": sorted(sources)[:20],
        "errors": list(getattr(tool_result, "errors", None) or []),
    }


def _qradar_domain_aql(domain: str, hours: int) -> str:
    """The DNS/proxy/email AQL the hunt runs for a domain — analyst-readable, so
    it doubles as the QRadar console deep-link and a copy-paste query."""
    d = (domain or "").replace("'", "''")
    return (
        'SELECT sourceip, destinationip, starttime, '
        'logsourcetypename(devicetype) AS source, username, "Computer Hostname", '
        'qidname(qid) AS eventName, URL, "TSLD", sender, recipient, "Subject" '
        'FROM events '
        f"WHERE (URL ILIKE '%{d}%' OR sender ILIKE '%{d}%' "
        f"OR \"Subject\" ILIKE '%{d}%' OR \"TSLD\" ILIKE '%{d}%') "
        f'LAST {hours} HOURS'
    )


def _crowdstrike_domain_query(domain: str) -> str:
    """LogScale/Advanced Event Search query for DNS resolution of the domain."""
    esc = re.escape((domain or "").strip().lower())
    return (
        f"#event_simpleName=DnsRequest | DomainName=/(^|\\.){esc}$/i "
        "| table([timestamp, ComputerName, UserName, DomainName, aid]) "
        "| sort(timestamp, order=desc, limit=500)"
    )


def hunt_plan(domain: str) -> Dict[str, Any]:
    """Pre-flight plan for the 'IOC Hunt' modal — the IOC set and, per tool, the
    exact query plus a console deep-link. Builds NO network calls / runs no
    search; it just shows what *would* run so the analyst can review, run it
    here, or pivot into the native console via a true deep-link that lands
    straight on the pre-filled query results (QRadar AQL + Falcon LogScale).
    """
    domain = (domain or "").strip().lower()
    tools: List[Dict[str, Any]] = []

    # QRadar — true deep-link that lands on the AQL results.
    aql = _qradar_domain_aql(domain, _QRADAR_HOURS)
    qr_url = None
    try:
        from src.components.tipper_analyzer.formatters import _get_qradar_console_link
        link = _get_qradar_console_link(aql)
        if link:
            qr_url = link[0]
    except Exception as e:
        logger.warning(f"QRadar deep-link build failed for {domain}: {e}")
    tools.append({
        "key": "qradar", "label": "QRadar", "emoji": "📡",
        "portal": "QRadar Log Activity", "query": aql, "url": qr_url,
        "deeplink": bool(qr_url), "window_days": _QRADAR_HOURS // 24,
    })

    # CrowdStrike — true deep-link into Falcon Advanced Event Search (LogScale).
    # The CQL rides in ?query=, repo=all spans every retained source, and the
    # window is a relative range (start=Nd, end=<empty>=now) so the link never
    # goes stale. Mirrors exactly what the console produces when you run the query
    # by hand, so the analyst lands straight on results instead of pasting.
    cql = _crowdstrike_domain_query(domain)
    cs_url = None
    cs_deeplink = False
    try:
        from my_config import get_config
        base = (get_config().cs_falcon_console_url or "").rstrip("/")
        if base:
            params = urlencode(
                {
                    "query": cql,
                    "repo": "all",
                    "searchViewInteractions": "NoXSA",
                    "start": f"{_CROWDSTRIKE_HOURS // 24}d",
                    "end": "",
                },
                quote_via=quote,
            )
            cs_url = f"{base}/investigate/search?{params}"
            cs_deeplink = True
    except Exception as e:
        logger.warning(f"Falcon deep-link build failed for {domain}: {e}")
    tools.append({
        "key": "crowdstrike", "label": "CrowdStrike", "emoji": "🦅",
        "portal": "Falcon Advanced Event Search", "query": cql, "url": cs_url,
        "deeplink": cs_deeplink, "window_days": _CROWDSTRIKE_HOURS // 24,
    })

    return {
        "domain": domain,
        "iocs": [domain],
        "qradar_days": _QRADAR_HOURS // 24,
        "crowdstrike_days": _CROWDSTRIKE_HOURS // 24,
        "tools": tools,
    }


def check_domain_exposure(domain: str, tools: Optional[List[str]] = None,
                          qradar_hours: int = _QRADAR_HOURS,
                          crowdstrike_hours: int = _CROWDSTRIKE_HOURS,
                          on_tool_complete=None) -> Dict[str, Any]:
    """Synchronously hunt one domain across the selected log sources.

    Returns a compact, JSON-serializable result:
        {domain, touched, total_hits, unique_hosts, unique_users, hosts, users,
         per_tool, access_issues, error}
    """
    domain = (domain or "").strip().lower()
    tools = tools or _DEFAULT_TOOLS
    try:
        from src.utils.entity_extractor import ExtractedEntities
        from src.components.tipper_analyzer.hunting import hunt_iocs

        entities = ExtractedEntities(domains=[domain])
        result = hunt_iocs(
            entities,
            tipper_id=f"dommon-{domain}",
            tipper_title=f"Domain Monitoring exposure hunt: {domain}",
            qradar_hours=qradar_hours,
            crowdstrike_hours=crowdstrike_hours,
            tools=tools,
            on_tool_complete=on_tool_complete,
        )
        per_tool = {
            "qradar": _collect_hits(result.qradar),
            "crowdstrike": _collect_hits(result.crowdstrike),
            "xsiam": _collect_hits(result.xsiam),
        }
        all_hosts, all_users = set(), set()
        for t in per_tool.values():
            all_hosts.update(t["hosts"])
            all_users.update(t["users"])
        return {
            "domain": domain,
            "touched": (result.total_hits or 0) > 0,
            "total_hits": result.total_hits or 0,
            "unique_hosts": result.unique_hosts or len(all_hosts),
            "unique_users": getattr(result, "unique_users", 0) or len(all_users),
            "hosts": sorted(all_hosts)[:50],
            "users": sorted(all_users)[:50],
            "per_tool": per_tool,
            "access_issues": list(result.access_issues or []),
            "tools": tools,
            "error": None,
        }
    except Exception as e:
        logger.error(f"Exposure hunt failed for {domain}: {type(e).__name__}: {e}")
        return {"domain": domain, "touched": None, "total_hits": 0, "unique_hosts": 0,
                "unique_users": 0, "hosts": [], "users": [], "per_tool": {},
                "access_issues": [], "tools": tools, "error": f"{type(e).__name__}: {e}"}


def run_and_record(domain: str, tools: Optional[List[str]] = None) -> Dict[str, Any]:
    """Run an exposure hunt and persist the result to the findings ledger.

    Each tool's result is written to the ledger the moment it finishes (via the
    ``on_tool_complete`` callback), so the dashboard can render QRadar as soon as
    it's done while CrowdStrike keeps running.
    """
    from .findings_ledger import (set_exposure_status, set_exposure_result,
                                  record_tool_progress)
    domain = (domain or "").strip().lower()
    set_exposure_status(domain, "running")

    def _on_tool_complete(tool_result, *_args, **_kwargs):
        try:
            key = (getattr(tool_result, "tool_name", "") or "").strip().lower()
            flat = _collect_hits(tool_result)
            errs = flat.get("errors") or []
            record_tool_progress(domain, key, {
                "status": "error" if errs else "done",
                "hits": flat["hits"],
                "hosts": len(flat["hosts"]),
                "users": len(flat["users"]),
                "error": errs[0] if errs else None,
            })
        except Exception as e:  # progress is best-effort; never break the hunt
            logger.warning(f"tool-progress write failed for {domain}: {e}")

    result = check_domain_exposure(domain, tools=tools, on_tool_complete=_on_tool_complete)
    if result.get("error"):
        try:
            set_exposure_status(domain, "error")
        except Exception:
            pass
        return result
    set_exposure_result(domain, touched=bool(result["touched"]),
                        hosts=int(result["unique_hosts"]), result_blob=result)
    return result


def start_exposure_hunt(domain: str, tools: Optional[List[str]] = None) -> None:
    """Kick an exposure hunt on a background daemon thread (status → ledger).

    Returns immediately; the dashboard polls the finding's ``exposure_status``
    (running → done/error) and reads ``exposure_json`` when complete.
    """
    domain = (domain or "").strip().lower()
    if not domain:
        return
    from .findings_ledger import set_exposure_status, init_exposure_progress
    set_exposure_status(domain, "running")  # set before the thread so polling sees it instantly
    init_exposure_progress(domain, tools or _DEFAULT_TOOLS)  # seed both tools as 'running'

    def _worker():
        try:
            run_and_record(domain, tools=tools)
        except Exception as e:
            logger.error(f"Exposure-hunt worker crashed for {domain}: {e}")
            try:
                set_exposure_status(domain, "error")
            except Exception:
                pass

    threading.Thread(target=_worker, name=f"exposure-hunt-{domain}", daemon=True).start()
