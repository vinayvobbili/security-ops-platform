"""Source-platform enrichment for XSOAR tickets.

For tickets originating from QRadar or CrowdStrike, fetches the full alert
details from the source platform's API and returns a structured dict that
gets injected into the LLM triage prompt.

Extraction logic:
- QRadar: parses offense ID from the 'Qradar Event URL' XSOAR custom field
- CrowdStrike: parses detection composite ID from the 'CrowdStrike Alert Link' field
"""

import logging
import re
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ID extraction helpers
# ---------------------------------------------------------------------------

def _extract_qradar_offense_id(url: str) -> Optional[int]:
    """Extract offense ID from a QRadar console URL.

    Handles formats like:
    - https://qradar/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId=12345
    - https://qradar/console/qradar/jsp/QRadar.jsp?appName=Sem&pageId=OffenseSummary&summaryId=12345
    - Plain integer string (just the ID)
    """
    if not url:
        return None

    url = url.strip()

    # Plain integer
    if url.isdigit():
        return int(url)

    # URL with summaryId param
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        summary_id = qs.get("summaryId", [None])[0]
        if summary_id and summary_id.isdigit():
            return int(summary_id)
    except Exception:
        pass

    # Fallback: regex for any digits in summaryId=
    match = re.search(r"summaryId=(\d+)", url)
    if match:
        return int(match.group(1))

    # Last resort: trailing integer after last /
    match = re.search(r"/(\d+)\s*$", url)
    if match:
        return int(match.group(1))

    return None


def _extract_cs_detection_id(url: str) -> Optional[str]:
    """Extract CrowdStrike detection composite ID from a Falcon console URL.

    Handles formats like:
    - https://falcon.us-2.crowdstrike.com/activity/detections/detail/abc:def123...
    - https://falcon.crowdstrike.com/alerts/detail/abc:def123...
    - Plain composite ID string (contains ':')
    """
    if not url:
        return None

    url = url.strip()

    # Plain composite ID (contains colon, no spaces)
    if ":" in url and " " not in url and "/" not in url:
        return url

    # URL path — composite ID is typically the last path segment
    try:
        parsed = urlparse(url)
        path = parsed.path.rstrip("/")
        # The composite ID is the last segment, often after /detail/
        segments = path.split("/")
        for seg in reversed(segments):
            if ":" in seg and len(seg) > 10:
                return seg
    except Exception:
        pass

    # Fallback: regex for composite ID pattern in URL
    match = re.search(r"(?:detail/|detections/)([a-zA-Z0-9]+:[a-zA-Z0-9]+)", url)
    if match:
        return match.group(1)

    return None


# ---------------------------------------------------------------------------
# QRadar enrichment
# ---------------------------------------------------------------------------

def _enrich_qradar(offense_id: int) -> Dict[str, Any]:
    """Fetch QRadar offense details, rule descriptions, sample events, and notes."""
    try:
        from services.qradar import QRadarClient
        client = QRadarClient()
        if not client.is_configured():
            return {"error": "QRadar not configured"}
    except Exception as e:
        return {"error": str(e)}

    result: Dict[str, Any] = {"source": "qradar", "offense_id": offense_id}

    try:
        offense = client.get_offense(offense_id)
        if "error" in offense:
            return {**result, "error": offense["error"]}

        # Extract rule IDs for description lookup
        raw_rules = offense.get("rules", [])

        result.update({
            "description": offense.get("description", ""),
            "offense_type_str": offense.get("offense_type_str", ""),
            "categories": offense.get("categories", []),
            "magnitude": offense.get("magnitude", 0),
            "relevance": offense.get("relevance", 0),
            "credibility": offense.get("credibility", 0),
            "severity": offense.get("severity", 0),
            "event_count": offense.get("event_count", 0),
            "flow_count": offense.get("flow_count", 0),
            "source_network": offense.get("source_network", ""),
            "destination_networks": offense.get("destination_networks", []),
            "log_sources": [ls.get("name", "") for ls in offense.get("log_sources", []) if ls.get("name")],
            "offense_source": offense.get("offense_source", ""),
            "status": offense.get("status", ""),
            "last_updated_time": offense.get("last_updated_time", 0),
            "start_time": offense.get("start_time", 0),
        })
    except Exception as e:
        logger.warning(f"QRadar offense fetch failed for {offense_id}: {e}")
        result["error"] = str(e)
        return result

    # Rule details with descriptions (best-effort, up to 5 rules)
    rules_with_desc = []
    for r in raw_rules[:5]:
        rule_id = r.get("id")
        rule_name = r.get("name", "")
        entry = {"name": rule_name, "id": rule_id}
        if rule_id:
            try:
                rule_detail = client.get_rule(rule_id)
                if "error" not in rule_detail:
                    entry["notes"] = rule_detail.get("notes", "")
                    entry["type"] = rule_detail.get("type", "")
            except Exception as e:
                logger.debug(f"QRadar rule detail fetch failed for {rule_id}: {e}")
        rules_with_desc.append(entry)
    result["rules"] = rules_with_desc

    # Sample events (best-effort, up to 3 events, 30s timeout)
    try:
        events = client.get_offense_events(offense_id, limit=3, timeout=30)
        if events:
            result["sample_events"] = [
                {
                    "event_time": e.get("event_time", ""),
                    "event_name": e.get("event_name", ""),
                    "log_source": e.get("log_source", ""),
                    "sourceip": e.get("sourceip", ""),
                    "destinationip": e.get("destinationip", ""),
                    "destinationport": e.get("destinationport", ""),
                    "category": e.get("category", ""),
                    "username": e.get("username", ""),
                    "magnitude": e.get("magnitude", ""),
                    "payload": str(e.get("payload", ""))[:500],
                }
                for e in events[:3]
            ]
    except Exception as e:
        logger.debug(f"QRadar offense events fetch failed for {offense_id}: {e}")

    # Offense notes (best-effort)
    try:
        notes_resp = client.get_offense_notes(offense_id)
        notes = notes_resp.get("notes", [])
        if notes:
            result["notes"] = [
                {"note_text": n.get("note_text", ""), "create_time": n.get("create_time", 0)}
                for n in notes[:10]
            ]
    except Exception as e:
        logger.debug(f"QRadar offense notes fetch failed for {offense_id}: {e}")

    return result


# ---------------------------------------------------------------------------
# CrowdStrike enrichment
# ---------------------------------------------------------------------------

# Standard system paths — anything NOT under one of these is flagged as a
# non-standard (user-writable / suspicious) location for an executable or
# loaded module. The check is case-insensitive and matches by substring.
_CS_STANDARD_PATH_PREFIXES = (
    r"\windows\system32\\",
    r"\windows\syswow64\\",
    r"\windows\winsxs\\",
    r"\windows\servicing\\",
    r"\windows\assembly\\",
    r"\windows\microsoft.net\\",
    r"\program files\\",
    r"\program files (x86)\\",
)

# Path substrings that explicitly indicate user-writable / attacker-favored
# locations. Used to *positively* tag a path as non-standard even if it
# doesn't pattern-match the system prefix list above (belt and suspenders).
_CS_NONSTANDARD_PATH_MARKERS = (
    r"\users\\",
    r"\appdata\\",
    r"\temp\\",
    r"\onedrive",       # OneDrive sync folders
    r"\downloads\\",
    r"\public\\",
    r"\programdata\\",  # writable by users by default
    r"\$recycle.bin\\",
)


def _is_non_standard_path(filepath: str) -> bool:
    """Return True if a Windows file path is in a user-writable / suspicious location.

    Used to flag loaded modules and executables that originate from places
    attackers favor (Temp, AppData, OneDrive, user profile, etc.) versus
    standard system paths (\\Windows\\System32, \\Program Files, etc.).
    """
    if not filepath:
        return False
    path_lc = filepath.lower()
    # Strip the \Device\HarddiskVolumeN prefix that CS often emits, so the
    # \Windows\System32 / \Users\... root is at the start of what we match.
    if r"\device\harddiskvolume" in path_lc:
        path_lc = re.sub(r"\\device\\harddiskvolume\d+", "", path_lc)

    # Positive markers win — if any user-writable marker is in the path,
    # it's non-standard regardless of where else it sits.
    if any(marker in path_lc for marker in _CS_NONSTANDARD_PATH_MARKERS):
        return True

    # Otherwise: standard if it starts with any known system prefix.
    return not any(path_lc.startswith(prefix) for prefix in _CS_STANDARD_PATH_PREFIXES)


def _dedupe_files_of_interest(files: list, cap: int = 10) -> list:
    """Filter a CS files_accessed/files_written list to non-standard paths only,
    dedupe by (filename, filepath), and cap at `cap` entries.

    CS often emits the same file multiple times (separate events for read,
    open, modify, etc.) — collapse those to one row before showing the
    analyst.
    """
    seen = set()
    out = []
    for f in files:
        fp = f.get("filepath", "") or ""
        fn = f.get("filename", "") or ""
        if not _is_non_standard_path(fp):
            continue
        key = (fn, fp)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "filename": fn,
            "filepath": fp,
            "non_standard_path": True,
        })
        if len(out) >= cap:
            break
    return out


def _build_cs_smoking_gun_facts(det: Dict[str, Any]) -> Dict[str, Any]:
    """Pull the high-signal facts out of a CS v2 alert payload.

    The default `_build_source_details_section` rendering hands the LLM a
    flat dump of fields. The LLM tends to grab the obvious ones (filename,
    sha256, cmdline) and miss the smoking gun (e.g. a .NET assembly loaded
    from `\\OneDrive\\…\\NtObjectManager\\2.0.1\\`). This function pulls
    those high-signal fields out explicitly so they can be rendered as a
    labeled section in both the LLM prompt and the XSOAR ticket note.

    Returns a structured dict — empty fields are kept so downstream
    rendering can decide whether to omit a section or show "(none)".
    """
    facts: Dict[str, Any] = {}

    # ---- Process tree (grandparent → parent → trigger) ----
    process_tree = []
    grandparent = det.get("grandparent_details") or {}
    parent = det.get("parent_details") or {}
    if grandparent:
        process_tree.append({
            "level": "grandparent",
            "filename": grandparent.get("filename", ""),
            "cmdline": (grandparent.get("cmdline", "") or "")[:300],
            "user_name": grandparent.get("user_name", ""),
            "sha256": grandparent.get("sha256", ""),
            "process_id": grandparent.get("process_id", ""),
        })
    if parent:
        process_tree.append({
            "level": "parent",
            "filename": parent.get("filename", ""),
            "cmdline": (parent.get("cmdline", "") or "")[:300],
            "user_name": parent.get("user_name", ""),
            "sha256": parent.get("sha256", ""),
            "process_id": parent.get("process_id", ""),
        })
    # The trigger process — the alert's own process info is at the top level
    trigger_filename = det.get("filename", "")
    trigger_cmdline = (det.get("cmdline", "") or "")[:300]
    if trigger_filename or trigger_cmdline:
        process_tree.append({
            "level": "trigger",
            "filename": trigger_filename,
            "cmdline": trigger_cmdline,
            "user_name": det.get("user_name", ""),
            "sha256": det.get("sha256", ""),
            "process_id": det.get("process_id", ""),
        })
    facts["process_tree"] = process_tree

    # ---- Files accessed of interest (filtered by non-standard path) ----
    # The CS v2 alerts API uses `files_accessed` and `files_written`, NOT
    # `loaded_files`. These are the most useful smoking-gun fields — they
    # show which files the process touched on disk during the suspicious
    # behavior. Filter to non-standard paths (user-writable / attacker-
    # favored locations) and dedupe by (filename, filepath) since CS often
    # emits multiple events for the same file.
    files_accessed = det.get("files_accessed") or []
    facts["files_accessed_of_interest"] = _dedupe_files_of_interest(files_accessed)
    facts["files_accessed_total"] = len(files_accessed)

    # ---- Files written of interest (process creating files on disk) ----
    files_written = det.get("files_written") or []
    facts["files_written_of_interest"] = _dedupe_files_of_interest(files_written)
    facts["files_written_total"] = len(files_written)

    # ---- DNS requests (extremely high signal — domain context) ----
    # Cap at 15 unique domains. Strip duplicates (CS reports A and AAAA
    # lookups separately for the same name).
    dns = det.get("dns_requests") or []
    seen_domains = set()
    dns_domains = []
    for d in dns:
        domain = (d.get("domain_name") or "").strip().lower()
        if domain and domain not in seen_domains:
            seen_domains.add(domain)
            dns_domains.append(domain)
        if len(dns_domains) >= 15:
            break
    facts["dns_requests"] = dns_domains
    facts["dns_requests_total"] = len(dns)

    # ---- Network accesses (cap at 10) ----
    net = det.get("network_accesses") or []
    facts["network_accesses"] = [
        {
            "local_address": n.get("local_address", ""),
            "local_port": str(n.get("local_port", "") or ""),
            "remote_address": n.get("remote_address", ""),
            "remote_port": str(n.get("remote_port", "") or ""),
            "protocol": n.get("protocol", ""),
            "direction": n.get("connection_direction", ""),
        }
        for n in net[:10]
    ]
    facts["network_accesses_total"] = len(net)

    # ---- Quarantined files ----
    qf = det.get("quarantined_files") or []
    facts["quarantined_files"] = [
        {
            "filename": q.get("filename", ""),
            "filepath": q.get("path", "") or q.get("filepath", ""),
            "sha256": q.get("sha256", ""),
            "state": q.get("state", ""),
        }
        for q in qf[:5]
    ]

    # ---- Pattern disposition (was anything actually blocked?) ----
    facts["pattern_disposition"] = det.get("pattern_disposition_description", "")
    pdd = det.get("pattern_disposition_details") or {}
    # Convenience boolean — did CS take ANY blocking/preventive action?
    facts["pattern_disposition_blocked"] = any(
        bool(pdd.get(k)) for k in (
            "process_blocked", "operation_blocked", "fs_operation_blocked",
            "registry_operation_blocked", "quarantine_file", "quarantine_machine",
            "kill_process", "kill_parent", "kill_subprocess",
            "containment_file_system",
        )
    )

    # ---- Prevalence (local vs global) ----
    facts["prevalence"] = {
        "local": det.get("local_prevalence", ""),
        "global": det.get("global_prevalence", ""),
    }

    # ---- Structured MITRE ATT&CK list (multiple techniques per detection) ----
    mitre = det.get("mitre_attack") or []
    facts["mitre_attack"] = [
        {
            "tactic": m.get("tactic", ""),
            "tactic_id": m.get("tactic_id", ""),
            "technique": m.get("technique", ""),
            "technique_id": m.get("technique_id", ""),
            "pattern_id": m.get("pattern_id", ""),
        }
        for m in mitre
    ]

    # ---- Dual-use tool detection ----
    # Scan the (already-filtered, deduped) files-of-interest plus the trigger
    # cmdline + parent/grandparent cmdlines against the known dual-use tool
    # dictionary. This puts a NAME on tools the analyst would otherwise have
    # to recognize from a folder path (NtObjectManager, SharpHound, etc.).
    from src.components.xsoar_alert_triage.dual_use_tools import scan_for_dual_use_tools
    extra_cmdlines = []
    if parent.get("cmdline"):
        extra_cmdlines.append(parent.get("cmdline"))
    if grandparent.get("cmdline"):
        extra_cmdlines.append(grandparent.get("cmdline"))
    facts["dual_use_tools_detected"] = scan_for_dual_use_tools(
        files=facts["files_accessed_of_interest"] + facts["files_written_of_interest"],
        cmdline=det.get("cmdline", "") or "",
        extra_cmdlines=extra_cmdlines,
    )

    return facts


def _enrich_crowdstrike(detection_id: str) -> Dict[str, Any]:
    """Fetch CrowdStrike detection details, device context, and parent incident."""
    try:
        from services.crowdstrike import CrowdStrikeClient
        client = CrowdStrikeClient()
    except Exception as e:
        return {"error": str(e)}

    result: Dict[str, Any] = {"source": "crowdstrike", "detection_id": detection_id}

    try:
        det = client.get_detection_by_id(detection_id)
        if "error" in det:
            return {**result, "error": det["error"]}

        # v2 alerts API: host/IP/OS fields live under a `device` sub-dict;
        # user fields and host_names are at the TOP LEVEL.
        device = det.get("device") or {}
        device_id = device.get("device_id", "") or det.get("device_id", "")
        host_names = det.get("host_names") or det.get("source_hosts") or []
        # Fall back to device.hostname if top-level host_names is empty
        if not host_names and device.get("hostname"):
            host_names = [device.get("hostname")]
        user_name = det.get("user_name", "")
        user_principal = det.get("user_principal", "")

        result.update({
            "display_name": det.get("display_name") or det.get("name", ""),
            "description": det.get("description", ""),
            "severity": det.get("severity", 0),
            "severity_name": det.get("severity_name", ""),
            "status": det.get("status", ""),
            "type": det.get("type", ""),
            "product": det.get("product", ""),
            "tactic": det.get("tactic", ""),
            "tactic_id": det.get("tactic_id", ""),
            "technique": det.get("technique", ""),
            "technique_id": det.get("technique_id", ""),
            "hostnames": host_names,
            "source_ips": [device.get("external_ip", "")] if device.get("external_ip") else [],
            "local_ip": device.get("local_ip", ""),
            "users": [user_name] if user_name else [],
            "user_principal": user_principal,
            "os_version": device.get("os_version", ""),
            "platform_name": device.get("platform_name", "") or det.get("platform", ""),
            "start_time": det.get("start_time", ""),
            "end_time": det.get("end_time", ""),
            "created_timestamp": det.get("created_timestamp", "") or det.get("timestamp", ""),
            "falcon_host_link": det.get("falcon_host_link", ""),
            "pattern_id": det.get("pattern_id", ""),
            "scenario": det.get("scenario", ""),
        })

        # Smoking-gun facts — high-signal fields explicitly extracted so the
        # LLM (and the analyst reading the ticket note) doesn't have to dig
        # them out of the raw payload.
        result["smoking_gun_facts"] = _build_cs_smoking_gun_facts(det)

        # CS baseline — per-user/per-pattern history + recent detections by
        # user and host. Turns a binary "this fired" into a behavior delta
        # ("this user has triggered this pattern N times in 90 days, last
        # seen X days ago"). Three additional CS API calls; failures land
        # in result['cs_baseline']['*']['error'] without blocking the rest.
        try:
            from src.components.xsoar_alert_triage.cs_baseline import build_cs_baseline
            result["cs_baseline"] = build_cs_baseline(det)
        except Exception as e:
            logger.warning(f"CS baseline build failed for {detection_id[:40]}...: {e}")
            result["cs_baseline"] = {"error": str(e)}

        # CS process-tree correlation — find other CS detections on the
        # same host within +/- 2h that share a tree_id, process_graph_id,
        # aggregate_id, or lead_id with this anchor. Surfaces the rest of
        # the chain (e.g. .NET load -> .NET load -> lateral move) without
        # the analyst having to pivot into Falcon. One CS API call.
        try:
            from src.components.xsoar_alert_triage.cs_process_tree import (
                build_process_tree_correlation,
            )
            result["cs_process_tree"] = build_process_tree_correlation(det)
        except Exception as e:
            logger.warning(
                f"CS process-tree correlation failed for {detection_id[:40]}...: {e}"
            )
            result["cs_process_tree"] = {"error": str(e)}

        # CS lateral-target host context — for outbound private-IP
        # destinations in the anchor's network_accesses (and any sibling
        # in the linked chain), look up the target host's metadata via
        # the CS hosts API. Pivots the analyst from "outbound to
        # 10.x.x.x:5985" to "Production server SZWBT134AHA in JP-Tokyo
        # OU." Depends on cs_process_tree for sibling network_accesses,
        # so this MUST run after the process-tree call above.
        try:
            from src.components.xsoar_alert_triage.cs_lateral_targets import (
                build_lateral_targets,
            )
            result["cs_lateral_targets"] = build_lateral_targets(
                det, result.get("cs_process_tree"),
            )
        except Exception as e:
            logger.warning(
                f"CS lateral-target enrichment failed for {detection_id[:40]}...: {e}"
            )
            result["cs_lateral_targets"] = {"error": str(e)}

        # IOC threat-intel checks — hashes, public IPs, and DNS request
        # domains from anchor + linked chain are looked up against the
        # local tipper TI store. Hits are a strong escalation signal
        # (this exact IOC has been seen in a prior triaged tipper);
        # zero hits across many checked IOCs is a meaningful FP-leaning
        # datapoint. Local SQLite, no network cost.
        try:
            from src.components.xsoar_alert_triage.cs_ioc_threat_intel import (
                build_ioc_threat_intel,
            )
            result["cs_ioc_ti"] = build_ioc_threat_intel(
                det, result.get("cs_process_tree"),
            )
        except Exception as e:
            logger.warning(
                f"CS IOC TI checks failed for {detection_id[:40]}...: {e}"
            )
            result["cs_ioc_ti"] = {"error": str(e)}

        # Cross-source correlation — open QRadar offenses on the same
        # host/user as the CS anchor (plus any lateral-movement target
        # hostnames resolved in Gap 4). Tells the analyst whether the
        # same activity is tripping a SIEM rule independently. Depends
        # on cs_lateral_targets, so this MUST run after Gap 4 above.
        # Tanium is intentionally skipped -- unreachable from this VM.
        try:
            from src.components.xsoar_alert_triage.cs_cross_source import (
                build_cross_source_correlation,
            )
            result["cs_cross_source"] = build_cross_source_correlation(
                det, result.get("cs_lateral_targets"),
            )
        except Exception as e:
            logger.warning(
                f"CS cross-source correlation failed for "
                f"{detection_id[:40]}...: {e}"
            )
            result["cs_cross_source"] = {"error": str(e)}

        # Behaviors (sub-detections within the alert)
        behaviors = det.get("behaviors", [])
        if behaviors:
            result["behaviors"] = [
                {
                    "display_name": b.get("display_name", ""),
                    "tactic": b.get("tactic", ""),
                    "technique": b.get("technique", ""),
                    "severity": b.get("severity", 0),
                    "filename": b.get("filename", ""),
                    "filepath": b.get("filepath", ""),
                    "cmdline": b.get("cmdline", ""),
                    "sha256": b.get("sha256", ""),
                    "parent_cmdline": b.get("parent_details", {}).get("parent_cmdline", ""),
                }
                for b in behaviors[:10]
            ]

    except Exception as e:
        logger.warning(f"CrowdStrike detection fetch failed for {detection_id}: {e}")
        result["error"] = str(e)
        return result

    # Device details — the inline `device` sub-dict on the v2 alert payload
    # already contains everything we need (status, last_seen, OU, tags,
    # groups, machine domain). No secondary API call required.
    if device:
        groups_raw = device.get("groups") or []
        # Normalize groups: API can return list[dict{name}] OR list[str].
        # When strings come back they're often opaque 32-char GUIDs (the CS
        # hosts API returns group IDs, not names) — strip them so the
        # ticket note + LLM prompt show useful labels, not hex noise.
        if groups_raw and isinstance(groups_raw[0], dict):
            groups = [g.get("name", "") for g in groups_raw if g.get("name")]
        else:
            groups = [
                str(g) for g in groups_raw
                if g and not re.match(r"^[a-f0-9]{32}$", str(g), re.IGNORECASE)
            ]
        result["device_details"] = {
            "status": device.get("status", ""),
            "last_seen": device.get("last_seen", ""),
            "first_seen": device.get("first_seen", ""),
            "product_type": device.get("product_type_desc", ""),
            "machine_domain": device.get("machine_domain", ""),
            "ou": device.get("ou") or [],
            "tags": device.get("tags") or [],
            "groups": groups,
            "site_name": device.get("site_name", ""),
        }

    # Parent incident context (best-effort) — related detections, tactics, severity
    incident_ids = det.get("incident_ids", []) if det else []
    if incident_ids:
        try:
            inc = client.get_incident_by_id(incident_ids[0])
            if inc and "error" not in inc:
                inc_hosts = inc.get("hosts", [])
                result["incident"] = {
                    "incident_id": inc.get("incident_id", ""),
                    "fine_score": inc.get("fine_score", 0),
                    "status": inc.get("status", ""),
                    "start": inc.get("start", ""),
                    "end": inc.get("end", ""),
                    "tactics": inc.get("tactics", []),
                    "techniques": inc.get("techniques", []),
                    "objectives": inc.get("objectives", []),
                    "host_count": len(inc_hosts),
                    "hostnames": [h.get("hostname", "") for h in inc_hosts[:5]],
                }
        except Exception as e:
            logger.debug(f"CrowdStrike incident fetch failed for {incident_ids[0]}: {e}")

    return result


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def enrich_from_source(ticket: dict) -> Optional[Dict[str, Any]]:
    """Fetch source-platform alert details for an XSOAR ticket.

    Checks ticket custom fields for QRadar offense URL or CrowdStrike alert link
    and fetches the full alert from the source platform.

    Returns:
        Dict with source alert details, or None if no source link found.
    """
    custom = ticket.get("CustomFields") or {}

    # QRadar: 'Qradar Event URL' → CustomFields.qradareventurl
    qradar_url = custom.get("qradareventurl", "")
    if qradar_url:
        offense_id = _extract_qradar_offense_id(qradar_url)
        if offense_id is not None:
            logger.info(f"[SourceEnrich] Fetching QRadar offense {offense_id}")
            result = _enrich_qradar(offense_id)
            result["source_url"] = qradar_url
            return result
        else:
            logger.warning(f"[SourceEnrich] Could not parse offense ID from: {qradar_url}")

    # CrowdStrike: 'CrowdStrike Alert Link' → CustomFields.crowdstrikealertlink
    cs_url = custom.get("crowdstrikealertlink", "")
    if cs_url:
        detection_id = _extract_cs_detection_id(cs_url)
        if detection_id:
            logger.info(f"[SourceEnrich] Fetching CrowdStrike detection {detection_id[:40]}...")
            result = _enrich_crowdstrike(detection_id)
            result["source_url"] = cs_url
            return result
        else:
            logger.warning(f"[SourceEnrich] Could not parse CS detection ID from: {cs_url}")

    return None
