"""CS host context for lateral-movement targets.

When a CrowdStrike alert contains outbound network connections to internal
addresses, those addresses are almost always more interesting than the alert
itself: they tell the analyst WHERE the actor was trying to go. The Falcon
console shows the IP but not the role, OU, or criticality of the target host
-- so the analyst either pivots into Falcon's host search or, more often,
just files the IP and moves on.

This module resolves each unique internal target IP via the CS hosts API:

  hosts_client.query_devices_by_filter(filter="local_ip:'X.X.X.X'")
  -> hosts_client.get_device_details(ids=[device_id])

For each resolved target, the analyst sees: hostname, OS, machine domain,
OU path, product type (workstation vs server), tags, groups, containment
status, last seen. The pivot from "outbound to <internal-host>" to
"SZWBT134AHA, Windows Server 2016, JP-Tokyo Production server in alico.corp"
is the entire point of this gap.

The anchor alert is the primary source of network_accesses, but the module
also walks `cs_process_tree.linked_chain[]` siblings (which already carry
network_accesses since process-tree correlation captures them as part of
its single host+window query). That way an alert chain like .NET load ->
.NET load -> lateral move surfaces the lateral target even when the anchor
is the upstream .NET load and the lateral move is downstream.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# Cap on unique target IPs we'll resolve. A single alert chain rarely talks
# to more than a handful of internal hosts; this is a safety belt against
# a noisy detection (broadcast/scan) hosing the host API.
MAX_TARGETS = 10


def _is_private_ip(ip: str) -> bool:
    """Return True if `ip` is in an RFC1918 / loopback / link-local range.

    Public IPs are intentionally ignored -- CS won't have a host record for
    them, and "lateral movement target" is by definition an internal pivot.
    """
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def _collect_outbound_targets(
    network_accesses: List[Dict[str, Any]],
    source_local_ip: str,
    source_label: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Pull outbound private-IP destinations from a network_accesses list.

    Each returned dict carries the destination IP/port/protocol plus the
    `source_label` (which alert in the chain this connection came from).
    Skips public IPs, inbound connections, and self-referential traffic.
    """
    out: List[Dict[str, Any]] = []
    for n in network_accesses or []:
        direction = (n.get("connection_direction") or "").lower()
        if direction and direction != "outbound":
            continue
        remote_addr = (n.get("remote_address") or "").strip()
        if not remote_addr or remote_addr == source_local_ip:
            continue
        if not _is_private_ip(remote_addr):
            continue
        out.append({
            "target_ip": remote_addr,
            "target_port": str(n.get("remote_port", "") or ""),
            "protocol": n.get("protocol", ""),
            "direction": n.get("connection_direction", "Outbound"),
            "source_alert": source_label,
        })
    return out


_GUID_RE = __import__("re").compile(r"^[a-f0-9]{32}$", __import__("re").IGNORECASE)


def _normalize_groups(groups_raw: Any) -> List[str]:
    """CS returns groups as either list[dict{name}] or list[str] depending
    on which API endpoint -- normalize to list[str] for rendering. Strips
    opaque 32-char GUIDs (the hosts API often returns group IDs not names);
    they're noise to a human analyst and just push the useful tags down."""
    if not groups_raw:
        return []
    if isinstance(groups_raw, list) and groups_raw:
        if isinstance(groups_raw[0], dict):
            return [g.get("name", "") for g in groups_raw if g.get("name")]
        return [str(g) for g in groups_raw if g and not _GUID_RE.match(str(g))]
    return []


def _resolve_target_host(
    client, target_ip: str,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Look up a single internal IP in CS via hosts API.

    Returns (device_dict, error). On success device_dict is the structured
    metadata block; on failure error is a short string and device_dict is
    None.
    """
    try:
        query_resp = client.hosts_client.query_devices_by_filter(
            filter=f"local_ip:'{target_ip}'", limit=5,
        )
    except Exception as e:
        return None, f"query failed: {e}"

    if query_resp.get("status_code") != 200:
        return None, f"query status {query_resp.get('status_code')}"

    device_ids = query_resp.get("body", {}).get("resources") or []
    if not device_ids:
        return None, "no host found"

    try:
        details_resp = client.hosts_client.get_device_details(ids=device_ids)
    except Exception as e:
        return None, f"details failed: {e}"

    if details_resp.get("status_code") != 200:
        return None, f"details status {details_resp.get('status_code')}"

    devices = details_resp.get("body", {}).get("resources") or []
    if not devices:
        return None, "details returned no resources"

    # If the IP belongs to multiple hosts (DHCP churn, NAT, etc.), pick the
    # most-recently-seen one. CS returns last_seen as a sortable ISO string.
    devices.sort(key=lambda d: d.get("last_seen", ""), reverse=True)
    d = devices[0]

    return ({
        "hostname": d.get("hostname", ""),
        "device_id": d.get("device_id", ""),
        "platform_name": d.get("platform_name", ""),
        "os_version": d.get("os_version", ""),
        "product_type_desc": d.get("product_type_desc", ""),
        "machine_domain": d.get("machine_domain", ""),
        "ou": d.get("ou") or [],
        "tags": d.get("tags") or [],
        "groups": _normalize_groups(d.get("groups")),
        "site_name": d.get("site_name", ""),
        "status": d.get("status", ""),
        "last_seen": d.get("last_seen", ""),
        "first_seen": d.get("first_seen", ""),
        "local_ip": d.get("local_ip", ""),
        "external_ip": d.get("external_ip", ""),
        "extra_devices_at_ip": len(devices) - 1,
    }, None)


def build_lateral_targets(
    det: Dict[str, Any],
    cs_process_tree: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Resolve internal-IP destinations from this alert + linked chain to
    CS host metadata.

    Args:
        det: The raw CS v2 alert payload (the anchor).
        cs_process_tree: Output of build_process_tree_correlation(det), if
            available. Linked-chain siblings are walked for additional
            network_accesses entries -- so a chain like .NET-load ->
            lateral-move surfaces the lateral target even when the anchor
            is the upstream .NET-load.

    Returns:
        Dict with `targets` (one entry per unique resolved internal IP),
        plus a few aggregate counters. Each target carries device metadata
        plus the source alert label that originated the connection.
    """
    device = det.get("device") or {}
    source_local_ip = (device.get("local_ip") or "").strip()
    source_hostname = (
        device.get("hostname")
        or (det.get("host_names") or [None])[0]
        or ""
    )
    if source_hostname:
        source_hostname = source_hostname.strip()

    result: Dict[str, Any] = {
        "source_hostname": source_hostname,
        "source_local_ip": source_local_ip,
        "targets": [],
        "unresolved": [],
        "candidate_count": 0,
        "resolved_count": 0,
        "truncated": False,
    }

    # ---- 1. Collect outbound private-IP candidates from anchor + chain ----
    candidates: List[Dict[str, Any]] = []

    # Anchor first
    anchor_label = {
        "role": "anchor",
        "composite_id": det.get("composite_id", ""),
        "pattern_id": str(det.get("pattern_id", "") or ""),
        "name": det.get("name", "") or det.get("display_name", ""),
        "minutes_offset": 0,
    }
    candidates.extend(
        _collect_outbound_targets(
            det.get("network_accesses") or [],
            source_local_ip,
            anchor_label,
        )
    )

    # Then linked-chain siblings (they have network_accesses since
    # cs_process_tree captures it from its host+window query).
    if cs_process_tree and isinstance(cs_process_tree, dict):
        for sib in cs_process_tree.get("linked_chain") or []:
            sib_label = {
                "role": "linked_chain",
                "composite_id": sib.get("composite_id", ""),
                "pattern_id": str(sib.get("pattern_id", "") or ""),
                "name": sib.get("name", ""),
                "minutes_offset": sib.get("minutes_offset", 0),
                "linkage": sib.get("linkage", ""),
            }
            candidates.extend(
                _collect_outbound_targets(
                    sib.get("network_accesses") or [],
                    source_local_ip,
                    sib_label,
                )
            )

    if not candidates:
        return result

    # ---- 2. Dedupe by target IP, keeping the strongest source label ----
    # If the same internal IP shows up in multiple alerts in the chain,
    # we want one entry per IP -- but the analyst should know which alerts
    # touched it. Collapse to one entry, accumulate the source labels.
    by_ip: Dict[str, Dict[str, Any]] = {}
    seen_ips_order: List[str] = []
    for c in candidates:
        ip = c["target_ip"]
        if ip not in by_ip:
            by_ip[ip] = {
                "target_ip": ip,
                "target_port": c["target_port"],
                "protocol": c["protocol"],
                "direction": c["direction"],
                "source_alerts": [c["source_alert"]],
            }
            seen_ips_order.append(ip)
        else:
            # Add the source alert if it's not a duplicate. Also keep the
            # earliest port/protocol observation -- if the same target was
            # contacted on multiple ports the analyst can find that in the
            # raw network_accesses; here we keep one row per IP.
            existing = by_ip[ip]
            if c["source_alert"] not in existing["source_alerts"]:
                existing["source_alerts"].append(c["source_alert"])

    result["candidate_count"] = len(seen_ips_order)
    if len(seen_ips_order) > MAX_TARGETS:
        result["truncated"] = True
        seen_ips_order = seen_ips_order[:MAX_TARGETS]

    # ---- 3. Resolve each unique target IP via CS hosts API ----
    try:
        from services.crowdstrike import CrowdStrikeClient
        client = CrowdStrikeClient()
    except Exception as e:
        logger.warning(f"[CSLateralTargets] CrowdStrikeClient init failed: {e}")
        result["error"] = str(e)
        return result

    for ip in seen_ips_order:
        target = by_ip[ip]
        device_data, err = _resolve_target_host(client, ip)
        if device_data is not None:
            target["target_device"] = device_data
            target["target_hostname"] = device_data.get("hostname", "")
            result["targets"].append(target)
            result["resolved_count"] += 1
        else:
            target["lookup_error"] = err or "unknown"
            result["unresolved"].append(target)

    return result
