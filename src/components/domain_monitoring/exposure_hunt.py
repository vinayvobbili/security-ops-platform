"""'Were we touched?' exposure hunt for a malicious domain.

Given a confirmed/suspected malicious domain, ask the question that actually
matters: did any internal host or user resolve or connect to it? The hunt
*execution* runs through the unified ``services.hunt_engine`` — the same neutral
IOC→telemetry fan-out the tipper hunts and the active-threats desk use — rather
than this module's own private call into ``hunt_iocs`` (consolidation step 3,
see project_hunt_engine_kernel). Domain Monitoring keeps what is genuinely its
own: the single-domain framing, the pre-flight deep-link plan, and persistence
to the findings ledger. SIEM queries are slow, so the public entry point runs
the hunt on a background thread and writes back to the ledger; the dashboard
polls the finding for status.
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


def hunt_plan(domain: str) -> Dict[str, Any]:
    """Pre-flight plan for the 'IOC Hunt' modal — the IOC set and, per tool, the
    exact query plus a console deep-link. Builds NO network calls / runs no
    search; it just shows what *would* run so the analyst can review, run it
    here, or pivot into the native console via a true deep-link that lands
    straight on the pre-filled query results (QRadar AQL + Falcon LogScale).

    The query + deep-link building is shared with the rest of the SOC via
    ``services.hunt_links`` (deep-link convergence, see
    project_hunt_engine_kernel) — this is just the domain desk's framing around
    those neutral builders.
    """
    domain = (domain or "").strip().lower()
    from services import hunt_links

    tools = hunt_links.domain_plan_tools(
        domain, qradar_hours=_QRADAR_HOURS, crowdstrike_hours=_CROWDSTRIKE_HOURS)
    return {
        "domain": domain,
        "iocs": [domain],
        "qradar_days": _QRADAR_HOURS // 24,
        "crowdstrike_days": _CROWDSTRIKE_HOURS // 24,
        "tools": tools,
    }


def _compact_result(domain: str, res, tools: List[str]) -> Dict[str, Any]:
    """Map a neutral ``hunt_engine.HuntResult`` to the compact, ledger/dashboard
    shape this desk has always emitted (so neither persistence nor the report UI
    changes)."""
    per_tool: Dict[str, Any] = {}
    all_hosts: List[str] = []
    all_users: List[str] = []
    for name, sh in (res.sources or {}).items():
        hosts = list(sh.get("hosts") or [])
        users = list(sh.get("users") or [])
        all_hosts.extend(hosts)
        all_users.extend(users)
        per_tool[name] = {
            "hits": int(sh.get("total_hits") or 0),
            "hosts": hosts[:50],
            "users": users[:50],
            "errors": [sh["error"]] if sh.get("error") else [],
        }
    # de-dupe preserving order
    seen_h: set = set()
    hosts_u = [h for h in all_hosts if not (h in seen_h or seen_h.add(h))]
    seen_u: set = set()
    users_u = [u for u in all_users if not (u in seen_u or seen_u.add(u))]
    return {
        "domain": domain,
        "touched": bool(res.touched),
        "total_hits": int(res.total_hits or 0),
        "unique_hosts": int(res.unique_hosts or 0) or len(hosts_u),
        "unique_users": int(res.unique_users or 0) or len(users_u),
        "hosts": hosts_u[:50],
        "users": users_u[:50],
        "per_tool": per_tool,
        "access_issues": list(res.access_issues or []),
        "tools": tools,
        "error": None,
    }


def check_domain_exposure(domain: str, tools: Optional[List[str]] = None,
                          qradar_hours: int = _QRADAR_HOURS,
                          crowdstrike_hours: int = _CROWDSTRIKE_HOURS,
                          on_source_complete=None) -> Dict[str, Any]:
    """Synchronously hunt one domain across the selected log sources.

    Delegates the fan-out to :func:`services.hunt_engine.hunt` and adapts the
    result to this desk's compact, JSON-serializable shape:
        {domain, touched, total_hits, unique_hosts, unique_users, hosts, users,
         per_tool, access_issues, error}

    ``on_source_complete(source_name, source_hits_dict)`` is forwarded to the
    engine's ``on_progress`` so the ledger can render each tool the moment it
    finishes.
    """
    domain = (domain or "").strip().lower()
    tools = tools or _DEFAULT_TOOLS
    try:
        from services import hunt_engine

        res = hunt_engine.hunt(
            [{"type": "domain", "value": domain}],
            ref=f"dommon-{domain}",
            label=f"Domain Monitoring exposure hunt: {domain}",
            window={"qradar": qradar_hours, "crowdstrike": crowdstrike_hours},
            sources=tools,                       # XSIAM stays opt-in for this desk
            on_progress=on_source_complete,
        )
        if res.status == "error":
            return {"domain": domain, "touched": None, "total_hits": 0, "unique_hosts": 0,
                    "unique_users": 0, "hosts": [], "users": [], "per_tool": {},
                    "access_issues": [], "tools": tools,
                    "error": "; ".join(res.errors) or "hunt engine error"}
        return _compact_result(domain, res, tools)
    except Exception as e:
        logger.error(f"Exposure hunt failed for {domain}: {type(e).__name__}: {e}")
        return {"domain": domain, "touched": None, "total_hits": 0, "unique_hosts": 0,
                "unique_users": 0, "hosts": [], "users": [], "per_tool": {},
                "access_issues": [], "tools": tools, "error": f"{type(e).__name__}: {e}"}


def run_and_record(domain: str, tools: Optional[List[str]] = None) -> Dict[str, Any]:
    """Run an exposure hunt and persist the result to the findings ledger.

    Each tool's result is written to the ledger the moment it finishes (via the
    engine's ``on_progress`` callback), so the dashboard can render QRadar as soon
    as it's done while CrowdStrike keeps running.
    """
    from .findings_ledger import (set_exposure_status, set_exposure_result,
                                  record_tool_progress)
    domain = (domain or "").strip().lower()
    set_exposure_status(domain, "running")

    def _on_source_complete(source_name, hits):
        try:
            key = (source_name or "").strip().lower()
            err = (hits or {}).get("error")
            record_tool_progress(domain, key, {
                "status": "error" if err else "done",
                "hits": int((hits or {}).get("total_hits") or 0),
                "hosts": len((hits or {}).get("hosts") or []),
                "users": len((hits or {}).get("users") or []),
                "error": err or None,
            })
        except Exception as e:  # progress is best-effort; never break the hunt
            logger.warning(f"tool-progress write failed for {domain}: {e}")

    result = check_domain_exposure(domain, tools=tools, on_source_complete=_on_source_complete)
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
