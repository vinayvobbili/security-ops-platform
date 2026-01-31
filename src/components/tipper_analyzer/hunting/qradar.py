"""QRadar IOC hunting functions using batched queries for efficiency."""

import logging
from datetime import datetime
from typing import List, Dict, Any

from ..models import ToolHuntResult

logger = logging.getLogger(__name__)


def hunt_qradar(entities, hours: int) -> ToolHuntResult:
    """Hunt IOCs in QRadar using batched queries.

    Instead of running one query per IOC sequentially (which could take hours),
    this batches IOCs into efficient combined queries:
    - 1 query for domains (combined search across webproxy, email, O365, PA firewall)
    - 1 query for IPs (combined search across ZPA, Entra, endpoint, PA firewall)
    - 1 query for hashes (endpoint)

    Both domain and IP searches return context information (threat names, actions,
    sender info, process info) which is displayed in the hunt results table.

    Args:
        entities: ExtractedEntities object from entity_extractor
        hours: Number of hours to search back

    Returns:
        ToolHuntResult with QRadar findings including context for domain and IP hits
    """
    from services.qradar import QRadarClient

    qradar = QRadarClient()
    if not qradar.is_configured():
        return ToolHuntResult(
            tool_name="QRadar",
            total_hits=0,
            errors=["QRadar API not configured"]
        )

    ip_hits = []
    domain_hits = []
    hash_hits = []
    errors = []

    # Collect all IOCs
    domains = entities.domains[:30]  # Limit to 30 domains
    ips = entities.ips[:20]  # Limit to 20 IPs
    all_hashes = []
    for hash_type in ['md5', 'sha1', 'sha256']:
        for h in entities.hashes.get(hash_type, [])[:10]:
            all_hashes.append((h, hash_type))

    logger.info(f"[QRadar] Parallel batched hunt: {len(domains)} domains, {len(ips)} IPs, {len(all_hashes)} hashes")

    # ==================== Domain Search (single combined query) ====================
    if domains:
        domain_events = {}  # Track events per domain

        try:
            logger.info(f"[QRadar] Running combined domain search across all log sources...")
            result = qradar.batch_search_domains_combined(domains, hours=hours, max_results=500)

            if result and "error" not in result:
                _aggregate_domain_hits_with_context(result.get('events', []), domains, domain_events)
            elif "error" in result:
                errors.append(f"Domain combined search: {result['error']}")

        except Exception as e:
            errors.append(f"Domain combined search: {str(e)}")
            logger.error(f"[QRadar] Domain combined search error: {e}")

        # Convert aggregated results to hits
        for domain, data in domain_events.items():
            if data['count'] > 0:
                domain_hits.append({
                    'domain': domain,
                    'event_count': data['count'],
                    'sources': list(data['sources']),
                    'first_seen': data['first_seen'].strftime("%Y-%m-%d %H:%M") if data['first_seen'] else 'N/A',
                    'last_seen': data['last_seen'].strftime("%Y-%m-%d %H:%M") if data['last_seen'] else 'N/A',
                    'context': list(data['context'])[:5],
                    'users': list(data['users'])[:10],
                    'hosts': list(data['hosts'])[:10],
                    'recipients': list(data['recipients'])[:10],
                })
                logger.info(f"  [QRadar] HIT: Domain {domain} - {data['count']} events, {len(data['users'])} users, {len(data['hosts'])} hosts")

    # ==================== IP Search (single combined query) ====================
    if ips:
        ip_events = {}  # Track events per IP

        try:
            logger.info(f"[QRadar] Running combined IP search across all log sources...")
            result = qradar.batch_search_ips_combined(ips, hours=hours, max_results=500)

            if result and "error" not in result:
                _aggregate_ip_hits_with_context(result.get('events', []), ips, ip_events)
            elif "error" in result:
                errors.append(f"IP combined search: {result['error']}")

        except Exception as e:
            errors.append(f"IP combined search: {str(e)}")
            logger.error(f"[QRadar] IP combined search error: {e}")

        # Convert aggregated results to hits
        for ip, data in ip_events.items():
            if data['count'] > 0:
                # Determine primary direction
                inbound = data['inbound']
                outbound = data['outbound']
                if outbound > inbound:
                    direction = f"→ Outbound ({outbound})"
                elif inbound > outbound:
                    direction = f"← Inbound ({inbound})"
                else:
                    direction = f"↔ Both ({inbound}/{outbound})"

                ip_hits.append({
                    'ip': ip,
                    'event_count': data['count'],
                    'sources': list(data['sources']),
                    'first_seen': data['first_seen'].strftime("%Y-%m-%d %H:%M") if data['first_seen'] else 'N/A',
                    'last_seen': data['last_seen'].strftime("%Y-%m-%d %H:%M") if data['last_seen'] else 'N/A',
                    'context': list(data['context'])[:5],
                    'users': list(data['users'])[:10],
                    'hosts': list(data['hosts'])[:10],
                    'direction': direction,
                })
                logger.info(f"  [QRadar] HIT: IP {ip} - {data['count']} events, {len(data['users'])} users, {len(data['hosts'])} hosts, {direction}")

    # ==================== Hash Search (1 query) ====================
    if all_hashes:
        hash_list = [h for h, _ in all_hashes]
        hash_type_map = {h: t for h, t in all_hashes}

        try:
            logger.info(f"[QRadar] Running hash search...")
            result = qradar.batch_search_hashes_endpoint(hash_list, hours=hours, max_results=500)
            if "error" not in result:
                hash_events = {}
                for event in result.get('events', []):
                    # Check which hash matched
                    for field in ['MD5', 'MD5 Hash', 'SHA256 Hash']:
                        event_hash = event.get(field, '')
                        if event_hash and event_hash.lower() in [h.lower() for h in hash_list]:
                            matched_hash = next((h for h in hash_list if h.lower() == event_hash.lower()), None)
                            if matched_hash:
                                if matched_hash not in hash_events:
                                    hash_events[matched_hash] = 0
                                hash_events[matched_hash] += 1

                for file_hash, count in hash_events.items():
                    hash_type = hash_type_map.get(file_hash, 'unknown')
                    hash_hits.append({
                        'hash': file_hash,
                        'hash_type': hash_type.upper(),
                        'event_count': count
                    })
                    logger.info(f"  [QRadar] HIT: Hash {file_hash[:16]}... - {count} events")

        except Exception as e:
            errors.append(f"Hash endpoint batch: {str(e)}")
            logger.error(f"[QRadar] Hash endpoint batch error: {e}")

    total_hits = len(ip_hits) + len(domain_hits) + len(hash_hits)
    return ToolHuntResult(
        tool_name="QRadar",
        total_hits=total_hits,
        ip_hits=ip_hits,
        domain_hits=domain_hits,
        hash_hits=hash_hits,
        errors=errors[:5]
    )


def _aggregate_domain_hits_with_context(
    events: List[Dict[str, Any]],
    domains: List[str],
    domain_events: Dict[str, Dict]
) -> None:
    """Aggregate events by matching domain, extracting source, context, users, hosts, and recipients.

    Args:
        events: List of events from QRadar (from combined query)
        domains: List of domains we searched for
        domain_events: Dict to accumulate results
    """
    # Map QRadar log source names to short labels
    source_map = {
        'Zscaler Nss': 'Zscaler',
        'Blue Coat Web Security Service': 'BlueCoat',
        'Area1 Security': 'Area1',
        'Abnormal Security': 'Abnormal',
        'Palo Alto PA Series': 'PaloAlto',
    }

    for event in events:
        # Check URL, Subject, sender, TSLD fields for domain matches
        url = event.get('URL', '') or ''
        subject = event.get('Subject', '') or ''
        sender = event.get('sender', '') or ''
        tsld = event.get('TSLD', '') or ''

        text_to_check = f"{url} {subject} {sender} {tsld}".lower()

        for domain in domains:
            if domain.lower() in text_to_check:
                if domain not in domain_events:
                    domain_events[domain] = {
                        'count': 0,
                        'sources': set(),
                        'first_seen': None,
                        'last_seen': None,
                        'context': set(),
                        'users': set(),
                        'hosts': set(),
                        'recipients': set(),  # Email recipients for phishing containment
                    }

                domain_events[domain]['count'] += 1

                # Get source from event
                raw_source = event.get('source', '')
                # Handle O365 (deviceType 397) which may not have logsourcetypename
                if not raw_source and event.get('eventName'):
                    event_name = event.get('eventName', '')
                    if 'TI' in event_name or 'Air' in event_name:
                        raw_source = 'O365'
                source = source_map.get(raw_source, raw_source or 'Unknown')
                domain_events[domain]['sources'].add(source)

                # Track affected users and hosts
                username = event.get('username', '')
                hostname = event.get('Computer Hostname', '')
                if username and username not in ('-', 'N/A', 'unknown'):
                    domain_events[domain]['users'].add(username)
                if hostname and hostname not in ('-', 'N/A', 'unknown'):
                    domain_events[domain]['hosts'].add(hostname)

                # Track email recipients (critical for phishing containment)
                recipient = event.get('recipient', '')
                if recipient and recipient not in ('-', 'N/A', 'unknown'):
                    # Could be comma-separated list
                    for r in recipient.split(','):
                        r = r.strip()
                        if r and '@' in r:
                            domain_events[domain]['recipients'].add(r)

                # Extract context based on source type
                context = _extract_domain_event_context(event, source)
                if context:
                    domain_events[domain]['context'].add(context)

                # Track timestamps
                ts = _parse_timestamp(event.get('starttime'))
                if ts:
                    if domain_events[domain]['first_seen'] is None or ts < domain_events[domain]['first_seen']:
                        domain_events[domain]['first_seen'] = ts
                    if domain_events[domain]['last_seen'] is None or ts > domain_events[domain]['last_seen']:
                        domain_events[domain]['last_seen'] = ts


def _extract_domain_event_context(event: Dict[str, Any], source: str) -> str:
    """Extract meaningful context string from a domain event based on its source.

    Args:
        event: Event dict from QRadar
        source: Short source label (Zscaler, PaloAlto, Area1, etc.)

    Returns:
        Context string or empty string if no meaningful context
    """
    parts = []

    if source == 'PaloAlto':
        threat = event.get('Threat Name', '')
        action = event.get('Action', '')
        subtype = event.get('PAN Log SubType', '')
        if threat:
            parts.append(f"Threat: {threat}")
        if action:
            parts.append(action)
        elif subtype:
            parts.append(subtype)

    elif source in ('Area1', 'Abnormal'):
        sender = event.get('sender', '')
        subject = event.get('Subject', '')
        if sender:
            # Extract just the domain part of sender
            if '@' in sender:
                parts.append(f"From: {sender.split('@')[1]}")
            else:
                parts.append(f"From: {sender[:30]}")
        if subject:
            parts.append(f"Subj: {subject[:40]}")

    elif source in ('Zscaler', 'BlueCoat'):
        user_agent = event.get('User Agent', '')
        action = event.get('Action', '')
        filename = event.get('filename', '')
        if action:
            parts.append(action)
        if filename:
            parts.append(f"File: {filename[:30]}")
        elif user_agent and len(user_agent) < 40:
            parts.append(user_agent)

    elif source == 'O365':
        event_name = event.get('eventName', '')
        filename = event.get('Filename', '')
        if event_name:
            parts.append(event_name)
        if filename:
            parts.append(f"File: {filename[:30]}")

    else:
        # Generic fallback
        event_name = event.get('eventName', '')
        if event_name:
            parts.append(event_name[:40])

    if parts:
        return f"{source}: {', '.join(parts)}"
    return ""


def _aggregate_ip_hits_with_context(
    events: List[Dict[str, Any]],
    ips: List[str],
    ip_events: Dict[str, Dict]
) -> None:
    """Aggregate events by matching IP, extracting source, context, users, hosts, and direction.

    Args:
        events: List of events from QRadar (from combined query)
        ips: List of IPs we searched for
        ip_events: Dict to accumulate results
    """
    # Map QRadar log source names to short labels
    source_map = {
        'Zscaler Private Access': 'ZPA',
        'Microsoft Entra ID': 'Entra',
        'CrowdStrikeEndpoint': 'CrowdStrike',
        'Tanium HTTP': 'Tanium',
        'Palo Alto PA Series': 'PaloAlto',
    }

    for event in events:
        src_ip = event.get('sourceip', '')
        dst_ip = event.get('destinationip', '')

        for ip in ips:
            if ip == src_ip or ip == dst_ip:
                if ip not in ip_events:
                    ip_events[ip] = {
                        'count': 0,
                        'sources': set(),
                        'first_seen': None,
                        'last_seen': None,
                        'context': set(),
                        'users': set(),
                        'hosts': set(),
                        'inbound': 0,   # IOC is sourceip (external -> internal)
                        'outbound': 0,  # IOC is destinationip (internal -> external)
                    }

                ip_events[ip]['count'] += 1

                # Track direction
                if ip == src_ip:
                    ip_events[ip]['inbound'] += 1
                else:
                    ip_events[ip]['outbound'] += 1

                # Track affected users and hosts
                username = event.get('username', '')
                hostname = event.get('Computer Hostname', '')
                if username and username not in ('-', 'N/A', 'unknown'):
                    ip_events[ip]['users'].add(username)
                if hostname and hostname not in ('-', 'N/A', 'unknown'):
                    ip_events[ip]['hosts'].add(hostname)

                # Get source from event
                raw_source = event.get('source', 'Unknown')
                source = source_map.get(raw_source, raw_source)
                ip_events[ip]['sources'].add(source)

                # Extract context based on source type
                context = _extract_event_context(event, source)
                if context:
                    ip_events[ip]['context'].add(context)

                # Track timestamps
                ts = _parse_timestamp(event.get('starttime'))
                if ts:
                    if ip_events[ip]['first_seen'] is None or ts < ip_events[ip]['first_seen']:
                        ip_events[ip]['first_seen'] = ts
                    if ip_events[ip]['last_seen'] is None or ts > ip_events[ip]['last_seen']:
                        ip_events[ip]['last_seen'] = ts


def _extract_event_context(event: Dict[str, Any], source: str) -> str:
    """Extract meaningful context string from an event based on its source.

    Args:
        event: Event dict from QRadar
        source: Short source label (ZPA, Entra, CrowdStrike, PaloAlto, etc.)

    Returns:
        Context string or empty string if no meaningful context
    """
    parts = []

    if source == 'PaloAlto':
        threat = event.get('Threat Name', '')
        action = event.get('Action', '')
        subtype = event.get('PAN Log SubType', '')
        if threat:
            parts.append(f"Threat: {threat}")
        if action:
            parts.append(action)
        elif subtype:
            parts.append(subtype)

    elif source in ('CrowdStrike', 'Tanium'):
        process = event.get('Process Name', '')
        action = event.get('Action', '')
        command = event.get('Command', '')
        if process:
            parts.append(f"Process: {process}")
        if action:
            parts.append(action)
        if command and len(command) < 50:
            parts.append(f"Cmd: {command}")

    elif source == 'Entra':
        status = event.get('Conditional Access Status', '')
        event_name = event.get('eventName', '')
        if status:
            parts.append(f"CA: {status}")
        if event_name and 'sign' in event_name.lower():
            parts.append(event_name)

    elif source == 'ZPA':
        status = event.get('ZPN-Sess-Status', '')
        if status:
            parts.append(f"Session: {status}")

    else:
        # Generic fallback
        event_name = event.get('eventName', '')
        if event_name:
            parts.append(event_name[:40])

    if parts:
        return f"{source}: {', '.join(parts)}"
    return ""


def _parse_timestamp(ts_value) -> datetime:
    """Parse QRadar timestamp (milliseconds or seconds since epoch)."""
    if not ts_value:
        return None
    try:
        # QRadar returns milliseconds since epoch
        if ts_value > 1e12:
            return datetime.fromtimestamp(ts_value / 1000)
        return datetime.fromtimestamp(ts_value)
    except (ValueError, TypeError, OSError):
        return None
