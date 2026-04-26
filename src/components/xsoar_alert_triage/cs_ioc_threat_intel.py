"""IOC threat-intel checks against the local tipper TI store.

Hashes, IPs, and domains pulled from a CrowdStrike alert (and any linked
chain siblings) are looked up in `services/threat_intel_db.py` -- the local
SQLite store of tipper / Detection Engineering work items that the IR team
has already triaged. A hit means at least one prior tipper specifically
mentioned this IOC, which is a strong escalation signal -- it tells the
analyst "this exact IOC has been seen before, here's the prior context."

A *negative* result is also useful: when 11 IOCs from a chain are checked
and zero have hits, that's a meaningful FP-leaning datapoint to surface
to the analyst (and to the LLM in the prompt).

The local TI store is SQLite, so calls are essentially free -- there's no
network round-trip and no API quota. The cost ceiling is just keeping the
analyst-visible output and the LLM prompt readable, so we cap each IOC
class at MAX_PER_TYPE.

Domains: known-benign infrastructure (microsoft.com, akamai.com, etc.) is
filtered out via threat_intel_db._is_benign_domain so we don't waste a
TI lookup on go.microsoft.com -- but we still surface the count of skipped
benign domains so the analyst sees the chain's network behaviour.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# Cap each IOC class so the rendered section + LLM prompt stays scannable.
# A real chain almost never has more than 5-10 of any one type; the cap is
# a safety belt for noisy detections (mass file ops, beacon-style C2).
MAX_PER_TYPE = 25

# Cap on tipper hits returned per matching IOC -- one IOC matching 50
# tipper work items would dominate the section. Show top N most-recent.
MAX_TIPPERS_PER_IOC = 5

# Hash sentinel values that mean "no real hash" -- CS sometimes returns
# all-zero strings as a placeholder.
_HASH_SENTINELS = {
    "0" * 64,  # null sha256
    "0" * 40,  # null sha1
    "0" * 32,  # null md5
    "",
}


def _is_public_ip(ip: str) -> bool:
    """Return True if `ip` is routable / public (not RFC1918 / loopback /
    link-local). The lateral-movement gap takes private IPs; this gap takes
    public ones."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def _collect_hashes(
    det: Dict[str, Any],
    cs_process_tree: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """Collect every non-sentinel hash from anchor + chain siblings.

    Pulls from: anchor sha256/md5/sha1, parent_details, grandparent_details,
    behaviors[].sha256, plus the same fields on each linked-chain sibling
    (cs_process_tree captures them as part of its single host+window query).
    """
    hashes: List[str] = []

    def _maybe(h: Any) -> None:
        if not h:
            return
        s = str(h).strip().lower()
        if s and s not in _HASH_SENTINELS:
            hashes.append(s)

    _maybe(det.get("sha256"))
    _maybe(det.get("md5"))
    _maybe(det.get("sha1"))

    parent = det.get("parent_details") or {}
    _maybe(parent.get("sha256"))
    _maybe(parent.get("md5"))
    grandparent = det.get("grandparent_details") or {}
    _maybe(grandparent.get("sha256"))
    _maybe(grandparent.get("md5"))

    for b in det.get("behaviors") or []:
        _maybe(b.get("sha256"))
        _maybe(b.get("md5"))

    if cs_process_tree and isinstance(cs_process_tree, dict):
        for sib in cs_process_tree.get("linked_chain") or []:
            _maybe(sib.get("sha256"))
            _maybe(sib.get("md5"))
            _maybe(sib.get("parent_sha256"))
            _maybe(sib.get("grandparent_sha256"))

    # Dedupe while preserving order so the anchor's own hashes lead the list.
    seen: Set[str] = set()
    out: List[str] = []
    for h in hashes:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def _collect_public_ips(
    det: Dict[str, Any],
    cs_process_tree: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """Collect unique outbound public-IP destinations from anchor + chain."""
    ips: List[str] = []
    seen: Set[str] = set()

    def _walk_network(net_list: Any) -> None:
        for n in net_list or []:
            direction = (n.get("connection_direction") or "").lower()
            if direction and direction != "outbound":
                continue
            ip = (n.get("remote_address") or "").strip()
            if not _is_public_ip(ip):
                continue
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)

    _walk_network(det.get("network_accesses") or [])
    if cs_process_tree and isinstance(cs_process_tree, dict):
        for sib in cs_process_tree.get("linked_chain") or []:
            _walk_network(sib.get("network_accesses") or [])
    return ips


def _collect_domains(
    det: Dict[str, Any],
    cs_process_tree: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """Collect unique DNS request domains from anchor + chain."""
    domains: List[str] = []
    seen: Set[str] = set()

    def _walk_dns(dns_list: Any) -> None:
        for d in dns_list or []:
            name = (d.get("domain_name") or "").strip().lower()
            if name and name not in seen:
                seen.add(name)
                domains.append(name)

    _walk_dns(det.get("dns_requests") or [])
    if cs_process_tree and isinstance(cs_process_tree, dict):
        for sib in cs_process_tree.get("linked_chain") or []:
            _walk_dns(sib.get("dns_requests") or [])
    return domains


def _format_tipper_hits(tippers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Trim a list of tipper dicts to the top MAX_TIPPERS_PER_IOC most
    recent and pick a stable subset of fields for rendering."""
    out: List[Dict[str, Any]] = []
    for t in tippers[:MAX_TIPPERS_PER_IOC]:
        out.append({
            "azdo_id": t.get("azdo_id", ""),
            "title": t.get("title", "")[:120],
            "created_date": t.get("created_date", ""),
            "url": t.get("url", ""),
        })
    return out


def build_ioc_threat_intel(
    det: Dict[str, Any],
    cs_process_tree: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Check anchor + chain IOCs against the local tipper TI store.

    Args:
        det: The raw CS v2 alert payload (the anchor).
        cs_process_tree: Output of build_process_tree_correlation(det), if
            available. Linked-chain siblings are walked for additional
            hashes, network IPs, and DNS request domains.

    Returns:
        Dict with three sub-sections (hashes, ips, domains) plus aggregate
        counters. Each sub-section reports {checked, hits, ...}. A hit is a
        dict with the IOC value and the list of matching tippers.
    """
    result: Dict[str, Any] = {
        "hashes": {"checked": 0, "hits": []},
        "ips": {"checked": 0, "hits": []},
        "domains": {"checked": 0, "skipped_benign": 0, "hits": []},
        "total_checked": 0,
        "total_hits": 0,
    }

    # Lazy import so we don't pay the SQLite warmup if the source isn't CS.
    try:
        from services.threat_intel_db import (
            get_tippers_for_entity,
            _is_benign_domain,
        )
    except Exception as e:
        logger.warning(f"[CSIocTI] threat_intel_db import failed: {e}")
        result["error"] = str(e)
        return result

    # ---- 1. Hashes ----
    hashes = _collect_hashes(det, cs_process_tree)[:MAX_PER_TYPE]
    result["hashes"]["checked"] = len(hashes)
    for h in hashes:
        try:
            tippers = get_tippers_for_entity("Hash", h)
        except Exception as e:
            logger.debug(f"[CSIocTI] hash lookup {h[:16]} failed: {e}")
            continue
        if tippers:
            result["hashes"]["hits"].append({
                "value": h,
                "tipper_count": len(tippers),
                "tippers": _format_tipper_hits(tippers),
            })

    # ---- 2. Public IPs ----
    ips = _collect_public_ips(det, cs_process_tree)[:MAX_PER_TYPE]
    result["ips"]["checked"] = len(ips)
    for ip in ips:
        try:
            tippers = get_tippers_for_entity("IP", ip)
        except Exception as e:
            logger.debug(f"[CSIocTI] ip lookup {ip} failed: {e}")
            continue
        if tippers:
            result["ips"]["hits"].append({
                "value": ip,
                "tipper_count": len(tippers),
                "tippers": _format_tipper_hits(tippers),
            })

    # ---- 3. Domains (filter benign infra first) ----
    raw_domains = _collect_domains(det, cs_process_tree)
    to_check: List[str] = []
    skipped = 0
    for d in raw_domains:
        try:
            if _is_benign_domain(d):
                skipped += 1
                continue
        except Exception:
            pass
        to_check.append(d)
        if len(to_check) >= MAX_PER_TYPE:
            break
    result["domains"]["checked"] = len(to_check)
    result["domains"]["skipped_benign"] = skipped
    for d in to_check:
        try:
            tippers = get_tippers_for_entity("Domain", d)
        except Exception as e:
            logger.debug(f"[CSIocTI] domain lookup {d} failed: {e}")
            continue
        if tippers:
            result["domains"]["hits"].append({
                "value": d,
                "tipper_count": len(tippers),
                "tippers": _format_tipper_hits(tippers),
            })

    result["total_checked"] = (
        result["hashes"]["checked"]
        + result["ips"]["checked"]
        + result["domains"]["checked"]
    )
    result["total_hits"] = (
        len(result["hashes"]["hits"])
        + len(result["ips"]["hits"])
        + len(result["domains"]["hits"])
    )
    return result
