"""Unified hunt engine — "given these IOCs, were we actually hit, and where?"

This is the neutral, feature-agnostic front door for the IOC→telemetry sweep
the SOC has re-implemented many times (tipper hunts, the KEV→hunt wire, domain
"were-we-touched", and now active-threats). The real fan-out engine already
exists — ``hunt_iocs`` inside ``src/components/tipper_analyzer/hunting`` — but
it is shaped for tippers: positional ``tipper_id``/``tipper_title`` args, a
result object full of ``tipper_*`` fields, and it lives inside the tipper
package. New desks couldn't import it cleanly, so they rebuilt the fan-out.

Step 1 of the consolidation (see project_hunt_engine_kernel): this module wraps
that engine behind a clean contract — ``hunt(iocs, ...) -> HuntResult`` — with
neutral names and a normalized, JSON-friendly result. It *delegates* to the
existing engine today (zero behaviour change, zero risk); later the source
adapters move under here and the tipper/KEV/domain callers point at this.

Callers own their own persistence — the engine returns data only. It is slow
(QRadar AQL alone can take minutes), so callers should run it off the request
thread and poll, exactly like the enrichment path does.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterable, Optional

logger = logging.getLogger(__name__)

# The sources the underlying engine can fan out to today. QRadar + CrowdStrike
# are the default; XSIAM and Abnormal are opt-in (slower / email-only).
SOURCES = ("qradar", "crowdstrike", "xsiam", "abnormal")
DEFAULT_SOURCES = ("qradar", "crowdstrike", "xsiam")

# How many sample hit rows / hostnames we keep per source in the normalized
# result (the raw engine result can be large; callers render a digest).
_SAMPLE_CAP = 25
_HOST_CAP = 50


@dataclass
class SourceHits:
    """Normalized per-source outcome — one telemetry source's view."""
    source: str
    total_hits: int = 0
    hosts: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    by_kind: dict[str, int] = field(default_factory=dict)   # {ip, domain, url, filename, hash, email}
    sample: list[dict[str, Any]] = field(default_factory=list)
    queries: list[dict[str, str]] = field(default_factory=list)
    error: str = ""
    access_denied: bool = False


@dataclass
class HuntResult:
    """Feature-agnostic hunt outcome. JSON-friendly via :meth:`to_dict`."""
    ref: str
    label: str
    hunt_time: str
    verdict: str = "clear"                 # touched | clear | inconclusive
    touched: bool = False
    total_iocs_searched: int = 0
    total_hits: int = 0
    unique_hosts: int = 0
    unique_users: int = 0
    unique_sources: list[str] = field(default_factory=list)
    sources: dict[str, dict] = field(default_factory=dict)   # name -> SourceHits dict
    searched: dict[str, list] = field(default_factory=dict)  # ips/domains/urls/filenames/hashes
    access_issues: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    window: dict[str, int] = field(default_factory=dict)
    status: str = "done"                   # done | error (running marker is written by callers)

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Input coercion                                                              #
# --------------------------------------------------------------------------- #

def _build_entities(iocs: Iterable[dict | str]):
    """Bucket a normalized IOC list into the engine's ``ExtractedEntities``.

    Accepts the active-threats IOC shape (``{"type","value"}``) — or bare
    strings, in which case the type is inferred loosely. Unknown types are
    dropped (the engine has no hunt path for them).
    """
    from src.utils.entity_extractor import ExtractedEntities

    e = ExtractedEntities()
    seen: set[str] = set()
    for raw in iocs or []:
        if isinstance(raw, str):
            typ, val = _infer_type(raw), raw.strip()
        elif isinstance(raw, dict):
            typ = (raw.get("type") or "").strip().lower()
            val = str(raw.get("value") or "").strip()
        else:
            continue
        if not val:
            continue
        k = f"{typ}:{val.lower()}"
        if k in seen:
            continue
        seen.add(k)
        if typ == "ip":
            e.ips.append(val)
        elif typ == "domain":
            e.domains.append(val)
        elif typ == "url":
            e.urls.append(val)
        elif typ == "filename":
            e.filenames.append(val)
        elif typ in ("sha256", "sha1", "md5"):
            e.hashes.setdefault(typ, []).append(val)
        elif typ == "email":
            e.emails.append(val)
            # the engine hunts the sender domain, not the localpart
            dom = val.split("@", 1)[-1].strip()
            if dom and dom.lower() not in (d.lower() for d in e.domains):
                e.domains.append(dom)
    return e


def _infer_type(v: str) -> str:
    import re
    v = v.strip()
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", v):
        return "ip"
    if re.fullmatch(r"[a-fA-F0-9]{64}", v):
        return "sha256"
    if re.fullmatch(r"[a-fA-F0-9]{40}", v):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{32}", v):
        return "md5"
    if "@" in v:
        return "email"
    if v.lower().startswith(("http://", "https://")):
        return "url"
    return "domain"


def _window(window) -> dict[str, int]:
    from src.components.tipper_analyzer.models import (
        DEFAULT_QRADAR_HUNT_HOURS, DEFAULT_CROWDSTRIKE_HUNT_HOURS, DEFAULT_XSIAM_HUNT_HOURS,
    )
    out = {"qradar": DEFAULT_QRADAR_HUNT_HOURS,
           "crowdstrike": DEFAULT_CROWDSTRIKE_HUNT_HOURS,
           "xsiam": DEFAULT_XSIAM_HUNT_HOURS}
    if isinstance(window, int) and window > 0:
        return {k: window for k in out}
    if isinstance(window, dict):
        for k in out:
            if isinstance(window.get(k), int) and window[k] > 0:
                out[k] = window[k]
    return out


# --------------------------------------------------------------------------- #
# Result normalization (tipper IOCHuntResult -> neutral HuntResult)           #
# --------------------------------------------------------------------------- #

_KIND_FIELDS = (
    ("ip", "ip_hits"), ("domain", "domain_hits"), ("url", "url_hits"),
    ("filename", "filename_hits"), ("hash", "hash_hits"), ("email", "email_hits"),
)


def _values_from(hits: list[dict], list_keys: tuple[str, ...],
                 scalar_keys: tuple[str, ...]) -> list[str]:
    """Pull identifiers out of hit rows, tolerating both shapes the source
    modules emit: list-valued fields (QRadar ``hosts``/``users``, XSIAM
    ``hostnames``) and scalar fields (EDR ``ComputerName``/``UserName``)."""
    out: list[str] = []
    for h in hits or []:
        if not isinstance(h, dict):
            continue
        for k in list_keys:
            v = h.get(k)
            if isinstance(v, (list, tuple, set)):
                out.extend(str(x) for x in v if x)
        for k in scalar_keys:
            v = h.get(k)
            if v and not isinstance(v, (list, tuple, set, dict)):
                out.append(str(v))
                break
    return out


def _hostnames_from(hits: list[dict]) -> list[str]:
    return _values_from(
        hits,
        list_keys=("hosts", "hostnames"),
        scalar_keys=("hostname", "host", "device", "computer_name", "ComputerName", "endpoint"),
    )


def _usernames_from(hits: list[dict]) -> list[str]:
    return _values_from(
        hits,
        list_keys=("users", "usernames"),
        scalar_keys=("username", "user", "user_name", "UserName", "account"),
    )


def _norm_source(tool) -> SourceHits | None:
    if tool is None:
        return None
    sh = SourceHits(source=getattr(tool, "tool_name", "") or "")
    sh.total_hits = int(getattr(tool, "total_hits", 0) or 0)
    sh.error = "; ".join(getattr(tool, "errors", []) or [])[:500]
    sh.access_denied = bool(getattr(tool, "foundry_access_denied", False))
    sh.queries = list(getattr(tool, "queries", []) or [])[:20]
    hosts: list[str] = []
    users: list[str] = []
    sample: list[dict] = []
    for kind, attr in _KIND_FIELDS:
        hits = getattr(tool, attr, []) or []
        if hits:
            sh.by_kind[kind] = len(hits)
            hosts.extend(_hostnames_from(hits))
            users.extend(_usernames_from(hits))
            for h in hits[:5]:
                if isinstance(h, dict):
                    sample.append({"kind": kind, **{k: h[k] for k in list(h)[:8]}})
    # de-dupe preserving order
    seen_h: set[str] = set()
    sh.hosts = [h for h in hosts if not (h in seen_h or seen_h.add(h))][:_HOST_CAP]
    seen_u: set[str] = set()
    sh.users = [u for u in users if not (u in seen_u or seen_u.add(u))][:_HOST_CAP]
    sh.sample = sample[:_SAMPLE_CAP]
    return sh


def _attach_console_links(sources: dict, window: dict) -> None:
    """Wrap each source's actual run queries in a console deep-link, so any desk
    rendering a HuntResult can offer "open this in the QRadar/Falcon console"
    pre-filled. Works for every IOC kind for free — it links the queries the
    hunt really ran. Best-effort: a build failure just leaves the raw query.
    """
    try:
        from services import hunt_links
    except Exception:
        return
    for name, sd in (sources or {}).items():
        if not isinstance(sd, dict):
            continue
        hours = window.get(name, 720)
        primary = None
        for q in sd.get("queries", []) or []:
            if not isinstance(q, dict) or not q.get("query"):
                continue
            url = hunt_links.console_url_for(
                name, q["query"], query_type=q.get("query_type", ""), window_hours=hours)
            if url:
                q["console_url"] = url
                if primary is None:
                    primary = url
        if primary:
            sd["console_url"] = primary


def _normalize(res, ref: str, label: str, window: dict) -> HuntResult:
    out = HuntResult(
        ref=ref, label=label,
        hunt_time=getattr(res, "hunt_time", "") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_iocs_searched=int(getattr(res, "total_iocs_searched", 0) or 0),
        total_hits=int(getattr(res, "total_hits", 0) or 0),
        unique_hosts=int(getattr(res, "unique_hosts", 0) or 0),
        unique_users=int(getattr(res, "unique_users", 0) or 0),
        unique_sources=list(getattr(res, "unique_sources", []) or []),
        access_issues=list(getattr(res, "access_issues", []) or []),
        errors=list(getattr(res, "errors", []) or []),
        window=window,
        searched={
            "ips": list(getattr(res, "searched_ips", []) or []),
            "domains": list(getattr(res, "searched_domains", []) or []),
            "urls": list(getattr(res, "searched_urls", []) or []),
            "filenames": list(getattr(res, "searched_filenames", []) or []),
            "hashes": list(getattr(res, "searched_hashes", []) or []),
        },
    )
    for name in ("qradar", "crowdstrike", "xsiam", "abnormal"):
        sh = _norm_source(getattr(res, name, None))
        if sh is not None:
            out.sources[name] = asdict(sh)
    _attach_console_links(out.sources, window)

    out.touched = out.total_hits > 0
    if out.touched:
        out.verdict = "touched"
    elif out.access_issues or any(s.get("error") or s.get("access_denied") for s in out.sources.values()):
        # No hits, but at least one source couldn't answer — don't claim "clear".
        out.verdict = "inconclusive"
    else:
        out.verdict = "clear"
    return out


# --------------------------------------------------------------------------- #
# Public API                                                                  #
# --------------------------------------------------------------------------- #

def _prep(window: Any, sources, on_progress):
    """Shared setup for the two front doors: resolved window, validated source
    list, and the neutral->tipper progress-callback bridge."""
    win = _window(window)
    src = [s for s in (sources or DEFAULT_SOURCES) if s in SOURCES]
    cb = None
    if on_progress:
        def cb(tool_result, _tid, _ttl, _hours, _total, _searched):  # noqa: ANN001
            try:
                sh = _norm_source(tool_result)
                if sh is not None:
                    on_progress(sh.source, asdict(sh))
            except Exception:
                logger.debug("hunt on_progress callback failed", exc_info=True)
    return win, src, cb


def run_fanout(
    entities,
    *,
    ref: str,
    label: str = "",
    window: Any = None,
    sources: Optional[Iterable[str]] = None,
    on_progress: Optional[Callable[[str, dict], None]] = None,
):
    """Neutral front door to the *raw* IOC fan-out.

    Runs the same parallel QRadar/CrowdStrike/XSIAM/Abnormal sweep as
    :func:`hunt`, but returns the rich underlying result (a duck-typed
    ``IOCHuntResult``) with the full per-kind hit rows intact — for callers that
    render those rows directly (the Hunt Workbench page). New desks should
    prefer :func:`hunt`, which normalizes this into a JSON-friendly,
    feature-agnostic :class:`HuntResult`.

    This is the single import point that lets callers reach the fan-out without
    importing the tipper package: the tipper ``hunting`` module is an
    implementation detail behind the engine, not a thing desks reach around it
    for. ``entities`` is a pre-built ``ExtractedEntities`` (callers that already
    have one); pass IOCs through :func:`hunt` instead if you only have
    ``[{"type","value"}]`` / bare strings.
    """
    win, src, cb = _prep(window, sources, on_progress)
    from src.components.tipper_analyzer.hunting import hunt_iocs

    return hunt_iocs(
        entities,
        tipper_id=ref,
        tipper_title=label or ref,
        qradar_hours=win["qradar"],
        crowdstrike_hours=win["crowdstrike"],
        xsiam_hours=win["xsiam"],
        tools=src,
        on_tool_complete=cb,
    )


# Source display metadata for the pre-flight plan.
_PLAN_META = {
    "qradar": ("QRadar", "📡"),
    "crowdstrike": ("CrowdStrike", "🦅"),
    "xsiam": ("XSIAM", "🧠"),
}


def plan(
    iocs: Iterable[dict | str],
    *,
    window: Any = None,
    sources: Optional[Iterable[str]] = None,
    ref: Optional[str] = None,
) -> dict:
    """Pre-flight plan — the queries each source *would* run for these IOCs, plus
    a console deep-link per query, **without touching the network**.

    This generalizes the per-domain pre-flight the Domain Monitoring desk already
    shows (``hunt_links.domain_plan_tools``) to every IOC kind, so any desk can
    preview a hunt and let the analyst review the queries or pivot straight into
    the native console before running anything.

    Fidelity by source: CrowdStrike reuses the engine's real LogScale generator
    verbatim (zero drift); XSIAM mirrors the validated ``xdr_data`` field choices;
    QRadar is a *representative* AQL preview — the live adapter assembles its exact
    query inside the network client, so the plan shows analyst-readable AQL of the
    same shape (same convention as the existing domain pre-flight).

    Args:
        iocs: normalized indicators — ``[{"type","value"}, ...]`` or bare strings.
        window: lookback hours (int or per-source dict), as in :func:`hunt`.
        sources: subset of ``SOURCES`` to plan for. Defaults to QRadar +
                 CrowdStrike + XSIAM. (Abnormal has no query-based deep-link.)
        ref: opaque caller reference echoed back; auto-generated if omitted.

    Returns:
        JSON-friendly dict: ``{ref, window, iocs, counts, sources}`` where each
        ``sources[name]`` is ``{label, emoji, window_days, queries:[{type, query,
        query_type?, console_url, deeplink}]}``.
    """
    from services import hunt_links

    win = _window(window)
    src = [s for s in (sources or DEFAULT_SOURCES) if s in SOURCES]
    e = _build_entities(iocs)

    ips = list(e.ips)
    domains = list(e.domains)
    urls = list(e.urls)
    filenames = list(e.filenames)
    hashes_by_type = {t: list(v) for t, v in (e.hashes or {}).items()}
    hash_pairs = [(h, t) for t, vs in hashes_by_type.items() for h in vs]
    emails = list(getattr(e, "emails", []) or [])

    def _wrap(source: str, queries: list, hours: int) -> list:
        out = []
        for q in queries or []:
            q = dict(q)
            url = hunt_links.console_url_for(
                source, q.get("query", ""), query_type=q.get("query_type", ""),
                window_hours=hours)
            q["console_url"] = url
            q["deeplink"] = bool(url)
            out.append(q)
        return out

    plan_sources: dict[str, dict] = {}
    for source in src:
        if source == "qradar":
            hours = win["qradar"]
            ql = hunt_links.qradar_plan_queries(
                ips=ips, domains=domains, urls=urls,
                hashes=[h for h, _ in hash_pairs], hours=hours)
        elif source == "crowdstrike":
            hours = win["crowdstrike"]
            try:
                from src.components.tipper_analyzer.hunting.crowdstrike import _generate_logscale_queries
                ql = _generate_logscale_queries(ips, domains, urls, filenames, hash_pairs, hours)
            except Exception:
                logger.exception("[hunt_engine] plan: crowdstrike query generation failed")
                ql = []
        elif source == "xsiam":
            hours = win["xsiam"]
            ql = hunt_links.xsiam_plan_queries(
                ips=ips, domains=domains, urls=urls, filenames=filenames,
                hashes_by_type=hashes_by_type, hours=hours)
        else:
            continue  # e.g. abnormal — no query-based console deep-link
        label, emoji = _PLAN_META.get(source, (source.title(), "🔍"))
        plan_sources[source] = {
            "label": label, "emoji": emoji,
            "window_days": max(1, hours // 24),
            "queries": _wrap(source, ql, hours),
        }

    return {
        "ref": ref or f"plan-{uuid.uuid4().hex[:12]}",
        "window": win,
        "iocs": {
            "ips": ips, "domains": domains, "urls": urls,
            "filenames": filenames, "hashes": [h for h, _ in hash_pairs],
            "emails": emails,
        },
        "counts": {
            "ips": len(ips), "domains": len(domains), "urls": len(urls),
            "filenames": len(filenames), "hashes": len(hash_pairs),
            "emails": len(emails),
        },
        "sources": plan_sources,
    }


def hunt(
    iocs: Iterable[dict | str],
    *,
    ref: Optional[str] = None,
    label: str = "",
    window: Any = None,
    sources: Optional[Iterable[str]] = None,
    on_progress: Optional[Callable[[str, dict], None]] = None,
) -> HuntResult:
    """Fan a set of IOCs out across our telemetry and return where we were hit.

    Args:
        iocs: normalized indicators — ``[{"type","value"}, ...]`` or bare strings.
        ref: opaque caller reference echoed back on the result (e.g. a threat
             uid). Auto-generated if omitted.
        label: human label for the hunt (shown in logs / the engine's tracking).
        window: lookback hours — an int (applied to every source) or a dict
                ``{"qradar":h,"crowdstrike":h,"xsiam":h}``. Defaults per source.
        sources: subset of ``SOURCES`` to query. Defaults to QRadar + CrowdStrike
                 + XSIAM.
        on_progress: optional ``(source_name, source_hits_dict)`` callback fired
                     as each source finishes, for streaming UIs.

    Returns:
        :class:`HuntResult` — JSON-friendly via ``.to_dict()``.
    """
    ref = ref or f"hunt-{uuid.uuid4().hex[:12]}"
    win = _window(window)
    entities = _build_entities(iocs)

    try:
        res = run_fanout(entities, ref=ref, label=label, window=window,
                         sources=sources, on_progress=on_progress)
        return _normalize(res, ref, label, win)
    except Exception as e:
        logger.exception("[hunt_engine] hunt failed for ref=%s", ref)
        return HuntResult(
            ref=ref, label=label,
            hunt_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            status="error", verdict="inconclusive", window=win,
            errors=[f"hunt engine error: {e}"],
        )
