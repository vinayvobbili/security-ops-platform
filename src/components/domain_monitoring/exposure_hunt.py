"""'Were we touched?' exposure hunt for a malicious domain.

Given a confirmed/suspected malicious domain, ask the question that actually
matters: did any internal host or user resolve or connect to it? Reuses the
tipper IOC fan-out (``hunt_iocs``) across DNS/proxy (QRadar) and EDR
(CrowdStrike) — XSIAM is opt-in. SIEM queries are slow, so the public entry
point runs the hunt on a background thread and writes the result back to the
findings ledger; the dashboard polls the finding for status.
"""

import logging
import threading
from typing import Any, Dict, List, Optional

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


def check_domain_exposure(domain: str, tools: Optional[List[str]] = None,
                          qradar_hours: int = _QRADAR_HOURS,
                          crowdstrike_hours: int = _CROWDSTRIKE_HOURS) -> Dict[str, Any]:
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
    """Run an exposure hunt and persist the result to the findings ledger."""
    from .findings_ledger import set_exposure_status, set_exposure_result
    domain = (domain or "").strip().lower()
    set_exposure_status(domain, "running")
    result = check_domain_exposure(domain, tools=tools)
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
    from .findings_ledger import set_exposure_status
    set_exposure_status(domain, "running")  # set before the thread so polling sees it instantly

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
