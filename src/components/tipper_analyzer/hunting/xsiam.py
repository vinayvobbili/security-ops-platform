"""Cortex XSIAM IOC hunting via XQL (xdr_data dataset).

Mirrors the other hunting adapters (qradar / crowdstrike / abnormal): a single
``hunt_xsiam(entities, hours)`` entry point returning a ``ToolHuntResult``.

Uses the existing ``services.xsiam.XsiamClient`` for auth/signing and the
start/poll XQL flow. Field names below were verified against the live amer
tenant's ``xdr_data`` schema (non-null over a 24h window):

    IP        action_remote_ip
    domain    dns_query_name, action_external_hostname
    sha256    action_file_sha256, actor_process_image_sha256
    md5       action_file_md5, actor_process_image_md5
    filename  action_file_name, actor_process_image_name
    hostname  agent_hostname   (for environment-exposure rollup)

Query strategy / deliberate choices:
  - One aggregation query *per field* (batched ``in (...)`` IOC list), grouped by
    that field. Because the filter is ``<field> in (LIST)``, every group value
    returned IS one of our IOCs, so attribution is exact. Results across the
    fields of a category are then merged by IOC value in Python.
  - We do NOT use coalesce()/a unified group-by column: for categories whose two
    fields co-populate on the same event (e.g. a process event has both
    actor_process_image_name AND the action_file_name it touched), coalesce
    attributes the count to the wrong value and explodes the result set.
  - sha1 is intentionally skipped: xdr_data only carries *authenticode* sha1
    (signing cert), not file-content sha1, so matching IOC sha1s would be wrong.
  - URLs are matched host-only (no full-URL/path field in xdr_data), same
    compromise the other adapters make.
  - XSIAM caps concurrent XQL queries, so this adapter issues its queries
    sequentially (it already runs concurrently with the other tools one level up
    in hunt_iocs). Worst case ~9 queries for a fully-populated tipper.
"""

import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..models import ToolHuntResult

logger = logging.getLogger(__name__)

# Per-IOC-type caps (match crowdstrike.py budgets)
_MAX_IPS = 15
_MAX_DOMAINS = 10
_MAX_URLS = 10
_MAX_FILENAMES = 10
_MAX_HASHES = 10
_MAX_HOSTS = 10  # cap hostnames stored per hit (a common IOC can match thousands)

# Per-query polling ceiling (seconds). XQL aggregations over the lookback can
# take a while; the de_scheduler job timeout is 1800s and we run sequentially.
_QUERY_MAX_WAIT = 300.0


def _quote_list(values) -> str:
    """Build a quoted, comma-joined XQL ``in (...)`` list, stripping embedded quotes."""
    return ", ".join('"' + str(v).replace('"', "") + '"' for v in values)


def _url_host(url: str) -> str:
    """Extract the host portion of a URL (xdr_data has no full-URL field)."""
    raw = url if "//" in url else "//" + url
    host = urlparse(raw).netloc or url
    return host.split("/")[0].split("@")[-1].split(":")[0]


def hunt_xsiam(entities, hours: int) -> ToolHuntResult:
    """Hunt IOCs in Cortex XSIAM via XQL.

    Args:
        entities: ExtractedEntities object from entity_extractor
        hours: Number of hours to search back

    Returns:
        ToolHuntResult with XSIAM findings
    """
    try:
        from services.xsiam import XsiamClient
    except ImportError:
        return ToolHuntResult(
            tool_name="XSIAM",
            total_hits=0,
            errors=["XSIAM client not available"],
        )

    client = XsiamClient()
    if not client.is_configured():
        return ToolHuntResult(
            tool_name="XSIAM",
            total_hits=0,
            errors=["XSIAM API not configured"],
        )

    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    time_from_ms = now_ms - hours * 3600 * 1000

    errors, queries = [], []

    def _run(label: str, xql: str):
        """Submit an XQL query, poll, and return its result rows (or [] on error)."""
        queries.append({"type": label, "query": xql, "query_type": "xql"})
        sub = client.start_xql_query(xql, time_from_ms=time_from_ms, time_to_ms=now_ms)
        if not isinstance(sub, dict) or "error" in sub:
            errors.append(f"{label}: {sub.get('error', 'submit failed') if isinstance(sub, dict) else 'submit failed'}")
            return []
        query_id = sub.get("reply")
        if not query_id:
            errors.append(f"{label}: no query_id returned")
            return []
        res = client.get_query_results(query_id, poll=True, max_wait=_QUERY_MAX_WAIT)
        if not isinstance(res, dict) or "error" in res:
            errors.append(f"{label}: {res.get('error', 'results failed') if isinstance(res, dict) else 'results failed'}")
            return []
        reply = res.get("reply") or {}
        results = reply.get("results") or {}
        stream_id = results.get("stream_id")
        if stream_id:
            stream = client.get_query_results_stream(stream_id)
            if isinstance(stream, dict) and "error" in stream:
                errors.append(f"{label}: {stream['error']}")
                return []
            # get_query_results_stream returns parsed NDJSON rows under 'data'
            return (stream or {}).get("data") or []
        return results.get("data") or []

    def _hunt_fields(label: str, fields: list, values: list) -> dict:
        """Run one grouped-count query per field and merge hits by IOC value.

        Every returned group value is guaranteed to be one of ``values`` (the
        query filters ``field in (values)``), so attribution is exact.
        Returns {ioc_value: {"count": int, "hosts": set}}.
        """
        merged: dict = {}
        vlist = _quote_list(values)
        for field in fields:
            rows = _run(
                f"{label} [{field}]",
                f"dataset = xdr_data | filter {field} in ({vlist}) "
                f"| comp count() as cnt, values(agent_hostname) as hosts by {field}",
            )
            for r in rows:
                val, cnt = r.get(field), r.get("cnt") or 0
                if not val or not cnt:
                    continue
                slot = merged.setdefault(val, {"count": 0, "hosts": set()})
                slot["count"] += cnt
                slot["hosts"].update(r.get("hosts") or [])
        return merged

    ip_hits, domain_hits, url_hits, filename_hits, hash_hits = [], [], [], [], []

    # ── IPs ──────────────────────────────────────────────────────────────────
    ips = entities.ips[:_MAX_IPS]
    if ips:
        for val, agg in _hunt_fields("XQL: IP remote connections", ["action_remote_ip"], ips).items():
            ip_hits.append({
                "ip": val, "event_count": agg["count"],
                "hostnames": sorted(agg["hosts"])[:_MAX_HOSTS], "sources": ["XSIAM"],
            })
            logger.info(f"  [XSIAM] HIT: IP {val} - {agg['count']} event(s)")

    # ── Domains ──────────────────────────────────────────────────────────────
    domains = entities.domains[:_MAX_DOMAINS]
    if domains:
        for val, agg in _hunt_fields(
            "XQL: Domain", ["dns_query_name", "action_external_hostname"], domains
        ).items():
            domain_hits.append({
                "domain": val, "event_count": agg["count"],
                "hostnames": sorted(agg["hosts"])[:_MAX_HOSTS], "sources": ["XSIAM"],
            })
            logger.info(f"  [XSIAM] HIT: Domain {val} - {agg['count']} event(s)")

    # ── URLs (host-only) ───────────────────────────────────────────────────────
    urls = entities.urls[:_MAX_URLS]
    if urls:
        url_hosts = {_url_host(u): u for u in urls if _url_host(u)}
        if url_hosts:
            for host, agg in _hunt_fields(
                "XQL: URL host", ["action_external_hostname"], list(url_hosts)
            ).items():
                url_hits.append({
                    "url": url_hosts.get(host, host), "event_count": agg["count"],
                    "hostnames": sorted(agg["hosts"])[:_MAX_HOSTS], "sources": ["XSIAM"],
                })
                logger.info(f"  [XSIAM] HIT: URL host {host} - {agg['count']} event(s)")

    # ── Filenames ──────────────────────────────────────────────────────────────
    filenames = entities.filenames[:_MAX_FILENAMES]
    if filenames:
        for val, agg in _hunt_fields(
            "XQL: Filename", ["action_file_name", "actor_process_image_name"], filenames
        ).items():
            filename_hits.append({
                "filename": val, "event_count": agg["count"],
                "detection_count": agg["count"],  # formatter reads detection_count for files
                "hostnames": sorted(agg["hosts"])[:_MAX_HOSTS],
            })
            logger.info(f"  [XSIAM] HIT: Filename {val} - {agg['count']} event(s)")

    # ── Hashes (sha256 + md5; sha1 skipped — see module docstring) ──────────────
    hash_specs = [
        ("sha256", ["action_file_sha256", "actor_process_image_sha256"]),
        ("md5", ["action_file_md5", "actor_process_image_md5"]),
    ]
    for hash_type, fields in hash_specs:
        values = entities.hashes.get(hash_type, [])[:_MAX_HASHES]
        if not values:
            continue
        for val, agg in _hunt_fields(f"XQL: {hash_type}", fields, values).items():
            hash_hits.append({
                "hash": val, "hash_type": hash_type, "event_count": agg["count"],
                "hostnames": sorted(agg["hosts"])[:_MAX_HOSTS],
            })
            logger.info(f"  [XSIAM] HIT: {hash_type} {val[:16]}… - {agg['count']} event(s)")

    total_hits = (
        len(ip_hits) + len(domain_hits) + len(url_hits)
        + len(filename_hits) + len(hash_hits)
    )
    logger.info(f"[XSIAM] hunt complete: {total_hits} hit(s)")
    return ToolHuntResult(
        tool_name="XSIAM",
        total_hits=total_hits,
        ip_hits=ip_hits,
        domain_hits=domain_hits,
        url_hits=url_hits,
        filename_hits=filename_hits,
        hash_hits=hash_hits,
        errors=errors[:5],
        queries=queries,
    )
