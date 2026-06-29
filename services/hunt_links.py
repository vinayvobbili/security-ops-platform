"""Console deep-link builders for hunt queries — one neutral home.

"Wrap a SIEM query in a URL that lands the analyst straight on the pre-filled
results" was built three times: in the tipper formatters, in domain
monitoring's pre-flight modal, and (by hand) wherever else a desk wanted a
console link. This module is the single implementation every desk shares
(consolidation: see project_hunt_engine_kernel, deep-link convergence).

Two things live here:
  * console-link builders — ``qradar_console_url`` / ``falcon_logscale_url`` /
    ``console_url_for`` (pick the right one for a source's query), and
  * the domain pre-flight query builders + tool plan used by the domain
    monitoring "IOC Hunt" modal.

Pure string construction, no network. Builders return ``None`` when the
relevant console URL isn't configured, so callers fall back to the raw query.
"""
from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import quote, urlencode


# --------------------------------------------------------------------------- #
# Console deep-links                                                           #
# --------------------------------------------------------------------------- #

def qradar_console_url(aql: str) -> Optional[str]:
    """Deep-link to QRadar Log Activity that runs the given AQL on arrival."""
    if not aql:
        return None
    from my_config import get_config

    config = get_config()
    base = config.qradar_console_url
    if not base:
        # Derive the console URL from the API URL (strip a trailing /api).
        api_url = (config.qradar_api_url or "").rstrip("/")
        if api_url.endswith("/api"):
            base = api_url[:-4]
        elif api_url:
            base = api_url
        else:
            return None
    base = base.rstrip("/")
    normalized = re.sub(r"\s+", " ", aql).strip()
    encoded = quote(normalized, safe="")
    return (f"{base}/console/do/ariel/arielSearch?appName=EventViewer"
            f"&pageId=EventList&dispatch=performSearch"
            f"&value(searchMode)=AQL&value(aql)={encoded}")


def _xsiam_ui_base() -> Optional[str]:
    """Cortex XSIAM UI base URL, derived without touching the network.

    Mirrors ``services.xsiam.XsiamClient._derive_ui_base_url``: the explicit
    ``XSIAM_PROD_UI_BASE_URL`` override wins, else the API base with its ``api-``
    host prefix stripped. ``None`` if neither is configured.
    """
    from my_config import get_config

    config = get_config()
    override = getattr(config, "xsiam_prod_ui_base_url", None)
    if override:
        return override.rstrip("/")
    api = getattr(config, "xsiam_prod_api_base_url", None)
    if not api:
        return None
    return api.replace("//api-", "//", 1).rstrip("/")


def xsiam_xql_url(xql: str = "") -> Optional[str]:
    """One-click jump to the Cortex XSIAM XQL Query Builder.

    Unlike QRadar/LogScale, Cortex XSIAM has no documented, stable URL parameter
    that pre-fills an XQL query on arrival, so this is an honest *navigation*
    deep-link to the Query Builder page (Incident Response → Investigation →
    Query Builder) rather than a pre-filled-results link — the caller shows the
    XQL alongside it for a one-paste run. The ``xql`` arg is accepted for a
    uniform signature with the other builders but isn't embedded (no verified
    pre-fill param). ``None`` when the XSIAM UI base isn't configured.
    """
    base = _xsiam_ui_base()
    if not base:
        return None
    return f"{base}/query-builder"


def falcon_logscale_url(cql: str, window: str = "30d") -> Optional[str]:
    """True deep-link into Falcon Advanced Event Search (LogScale) results.

    The CQL rides in ``?query=``, ``repo=all`` spans every retained source, and
    the window is a relative range (``start=<Nd>``, ``end`` empty = now) so the
    link never goes stale. See reference_falcon_logscale_deeplink.
    """
    if not cql:
        return None
    from my_config import get_config

    base = (get_config().cs_falcon_console_url or "").rstrip("/")
    if not base:
        return None
    params = urlencode(
        {
            "query": cql,
            "repo": "all",
            "searchViewInteractions": "NoXSA",
            "start": window or "30d",
            "end": "",
        },
        quote_via=quote,
    )
    return f"{base}/investigate/search?{params}"


def _days(hours: Any) -> str:
    """Lookback hours -> a Falcon relative-window token like ``30d`` (min 1d)."""
    try:
        d = max(1, int(hours) // 24)
    except (TypeError, ValueError):
        d = 30
    return f"{d}d"


def console_url_for(source: str, query: str, *, query_type: str = "",
                    window_hours: Any = 720) -> Optional[str]:
    """Pick the right console-link builder for a source's hunt query.

    ``source`` is the telemetry source name (``qradar``, ``crowdstrike`` /
    ``falcon``, ``xsiam`` / ``cortex`` — display-cased names work too).
    ``query_type`` is the optional hint the source module attaches (``logscale``
    / ``fql`` / ``xql``); FQL filter queries are a different Falcon surface and
    aren't LogScale-deep-linked here. XSIAM resolves to a Query Builder
    navigation link (no verified pre-fill param — see :func:`xsiam_xql_url`).
    """
    s = (source or "").strip().lower()
    if "qradar" in s:
        return qradar_console_url(query)
    if "crowdstrike" in s or "falcon" in s:
        if (query_type or "").strip().lower() == "fql":
            return None
        return falcon_logscale_url(query, window=_days(window_hours))
    if "xsiam" in s or "cortex" in s or "xdr" in s:
        return xsiam_xql_url(query)
    return None


# --------------------------------------------------------------------------- #
# Domain pre-flight query builders + tool plan                                #
# (lifted from domain_monitoring/exposure_hunt.py so they're shared)          #
# --------------------------------------------------------------------------- #

def qradar_domain_aql(domain: str, hours: int = 168) -> str:
    """The DNS/proxy/email AQL a domain hunt runs — analyst-readable, so it
    doubles as the QRadar console deep-link and a copy-paste query."""
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


def falcon_domain_cql(domain: str) -> str:
    """LogScale/Advanced Event Search query for DNS resolution of the domain."""
    esc = re.escape((domain or "").strip().lower())
    return (
        f"#event_simpleName=DnsRequest | DomainName=/(^|\\.){esc}$/i "
        "| table([timestamp, ComputerName, UserName, DomainName, aid]) "
        "| sort(timestamp, order=desc, limit=500)"
    )


# --------------------------------------------------------------------------- #
# Multi-kind pre-flight query builders (representative previews)               #
#                                                                              #
# These mirror what each source hunts, for the engine's general pre-flight     #
# plan(). They are *representative* previews — the live adapters build their    #
# own exact query at run time (QRadar's AQL is assembled inside the network     #
# client; CrowdStrike's LogScale is reused verbatim by the engine). QRadar     #
# field choices follow hunting/qradar.py; XSIAM mirrors the validated          #
# xdr_data fields in hunting/xsiam.py.                                          #
# --------------------------------------------------------------------------- #

# Analyst-readable SELECT shared by the QRadar preview builders (matches the
# columns hunting/qradar.py surfaces).
_QRADAR_SELECT = (
    'SELECT sourceip, destinationip, starttime, '
    'logsourcetypename(devicetype) AS source, username, "Computer Hostname", '
    'qidname(qid) AS eventName, URL, sender, recipient, "Subject", "TSLD" '
    'FROM events '
)


def _aql_in(values) -> str:
    """A quoted, comma-joined AQL ``IN (...)`` list (single-quotes escaped)."""
    return ", ".join("'" + str(v).replace("'", "''") + "'" for v in values)


def _aql_like(field: str, values) -> str:
    """An OR-chain of ``field ILIKE '%v%'`` clauses for substring matches."""
    return " OR ".join(f"{field} ILIKE '%{str(v).replace(chr(39), chr(39) * 2)}%'" for v in values)


def qradar_ip_aql(ips, hours: int = 168) -> str:
    return f"{_QRADAR_SELECT}WHERE (sourceip IN ({_aql_in(ips)}) OR destinationip IN ({_aql_in(ips)})) LAST {hours} HOURS"


def qradar_url_aql(urls, hours: int = 168) -> str:
    paths = [u.replace("https://", "").replace("http://", "") for u in urls]
    return f"{_QRADAR_SELECT}WHERE ({_aql_like('URL', paths)}) LAST {hours} HOURS"


def qradar_hash_aql(hashes, hours: int = 168) -> str:
    vals = _aql_in(hashes)
    return (f'{_QRADAR_SELECT}WHERE ("SHA256 Hash" IN ({vals}) '
            f'OR "MD5 Hash" IN ({vals}) OR MD5 IN ({vals})) LAST {hours} HOURS')


def qradar_domains_aql(domains, hours: int = 168) -> str:
    """Multi-domain variant of :func:`qradar_domain_aql` for the plan — matches
    each domain across the URL / sender / Subject / TSLD fields."""
    clauses = []
    for d in domains:
        e = str(d).replace("'", "''")
        clauses.append(
            f"(URL ILIKE '%{e}%' OR sender ILIKE '%{e}%' "
            f"OR \"Subject\" ILIKE '%{e}%' OR \"TSLD\" ILIKE '%{e}%')"
        )
    return f"{_QRADAR_SELECT}WHERE ({' OR '.join(clauses)}) LAST {hours} HOURS"


def _xsiam_xql(fields: list, values) -> str:
    """A representative ``xdr_data`` count query over ``fields in (values)``,
    grouped by the first field — faithful to hunting/xsiam.py's per-field
    aggregations (it issues one per field; this previews them as one OR)."""
    vlist = ", ".join('"' + str(v).replace('"', "") + '"' for v in values)
    filt = " or ".join(f"{f} in ({vlist})" for f in fields)
    return (f"dataset = xdr_data | filter {filt} "
            f"| comp count() as cnt, values(agent_hostname) as hosts by {fields[0]}")


def _url_host(url: str) -> str:
    raw = url if "//" in url else "//" + url
    from urllib.parse import urlparse
    host = urlparse(raw).netloc or url
    return host.split("/")[0].split("@")[-1].split(":")[0]


def qradar_plan_queries(*, ips=None, domains=None, urls=None, hashes=None,
                        hours: int = 168) -> list[dict]:
    """Representative QRadar AQL the plan would run, one per IOC category
    present (domains/urls/ips/hashes — the kinds hunting/qradar.py searches)."""
    out: list[dict] = []
    if domains:
        out.append({"type": "Domain / email-indicator search", "query": qradar_domains_aql(domains, hours)})
    if urls:
        out.append({"type": "URL path search", "query": qradar_url_aql(urls, hours)})
    if ips:
        out.append({"type": "IP search", "query": qradar_ip_aql(ips, hours)})
    if hashes:
        out.append({"type": "File-hash search", "query": qradar_hash_aql(hashes, hours)})
    return out


def xsiam_plan_queries(*, ips=None, domains=None, urls=None, filenames=None,
                       hashes_by_type=None, hours: int = 720) -> list[dict]:
    """Representative XSIAM XQL the plan would run, mirroring hunting/xsiam.py's
    validated ``xdr_data`` field choices (sha1 intentionally skipped)."""
    out: list[dict] = []
    if ips:
        out.append({"type": "XQL: IP remote connections", "query": _xsiam_xql(["action_remote_ip"], ips), "query_type": "xql"})
    if domains:
        out.append({"type": "XQL: Domain", "query": _xsiam_xql(["dns_query_name", "action_external_hostname"], domains), "query_type": "xql"})
    if urls:
        hosts = sorted({_url_host(u) for u in urls if _url_host(u)})
        if hosts:
            out.append({"type": "XQL: URL host", "query": _xsiam_xql(["action_external_hostname"], hosts), "query_type": "xql"})
    if filenames:
        out.append({"type": "XQL: Filename", "query": _xsiam_xql(["action_file_name", "actor_process_image_name"], filenames), "query_type": "xql"})
    for htype, fields in (("sha256", ["action_file_sha256", "actor_process_image_sha256"]),
                          ("md5", ["action_file_md5", "actor_process_image_md5"])):
        vals = (hashes_by_type or {}).get(htype) or []
        if vals:
            out.append({"type": f"XQL: {htype}", "query": _xsiam_xql(fields, vals), "query_type": "xql"})
    return out


def domain_plan_tools(domain: str, *, qradar_hours: int = 168,
                      crowdstrike_hours: int = 720) -> list[dict]:
    """Per-tool pre-flight plan for a domain: the exact query plus a console
    deep-link that lands on its pre-filled results. No network calls."""
    domain = (domain or "").strip().lower()
    aql = qradar_domain_aql(domain, qradar_hours)
    qr_url = qradar_console_url(aql)
    cql = falcon_domain_cql(domain)
    cs_url = falcon_logscale_url(cql, window=_days(crowdstrike_hours))
    return [
        {
            "key": "qradar", "label": "QRadar", "emoji": "📡",
            "portal": "QRadar Log Activity", "query": aql, "url": qr_url,
            "deeplink": bool(qr_url), "window_days": qradar_hours // 24,
        },
        {
            "key": "crowdstrike", "label": "CrowdStrike", "emoji": "🦅",
            "portal": "Falcon Advanced Event Search", "query": cql, "url": cs_url,
            "deeplink": bool(cs_url), "window_days": crowdstrike_hours // 24,
        },
    ]
