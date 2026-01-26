"""QRadar IOC hunting functions using batched + parallel queries for efficiency."""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Any, Tuple, Callable

from ..models import ToolHuntResult

logger = logging.getLogger(__name__)

# Max concurrent QRadar searches (tune based on QRadar capacity)
MAX_PARALLEL_SEARCHES = 4


def hunt_qradar(entities, hours: int) -> ToolHuntResult:
    """Hunt IOCs in QRadar using batched + parallel queries.

    Instead of running one query per IOC sequentially (which could take hours),
    this batches all IOCs into ~10 queries and runs them in parallel:
    - 4 queries for domains (webproxy, email, O365, PA firewall) - run in parallel
    - 5 queries for IPs (general, ZPA, Entra, endpoint, PA firewall) - run in parallel
    - 1 query for hashes (endpoint)

    Args:
        entities: ExtractedEntities object from entity_extractor
        hours: Number of hours to search back

    Returns:
        ToolHuntResult with QRadar findings
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

    # ==================== Domain Searches (4 parallel queries) ====================
    if domains:
        domain_events = {}  # Track events per domain

        # Define search tasks: (search_func, source_name)
        domain_tasks = [
            (lambda: qradar.batch_search_domains_webproxy(domains, hours=hours, max_results=500), 'webproxy'),
            (lambda: qradar.batch_search_domains_email(domains, hours=hours, max_results=500), 'email'),
            (lambda: qradar.batch_search_domains_o365(domains, hours=hours, max_results=500), 'o365'),
            (lambda: qradar.batch_search_domains_paloalto(domains, hours=hours, max_results=500), 'paloalto'),
        ]

        # Run domain searches in parallel
        logger.info(f"[QRadar] Running {len(domain_tasks)} domain searches in parallel...")
        results = _run_searches_parallel(domain_tasks, errors)

        # Aggregate results
        for result, source in results:
            if result and "error" not in result:
                _aggregate_domain_hits(result.get('events', []), domains, domain_events, source)

        # Convert aggregated results to hits
        for domain, data in domain_events.items():
            if data['count'] > 0:
                domain_hits.append({
                    'domain': domain,
                    'event_count': data['count'],
                    'sources': list(data['sources']),
                    'first_seen': data['first_seen'].strftime("%Y-%m-%d %H:%M") if data['first_seen'] else 'N/A',
                    'last_seen': data['last_seen'].strftime("%Y-%m-%d %H:%M") if data['last_seen'] else 'N/A'
                })
                logger.info(f"  [QRadar] HIT: Domain {domain} - {data['count']} events from {data['sources']}")

    # ==================== IP Searches (5 parallel queries) ====================
    if ips:
        ip_events = {}  # Track events per IP

        # Define search tasks
        ip_tasks = [
            (lambda: qradar.batch_search_ips_general(ips, hours=hours, max_results=500), 'general'),
            (lambda: qradar.batch_search_ips_zpa(ips, hours=hours, max_results=500), 'zpa'),
            (lambda: qradar.batch_search_ips_entra(ips, hours=hours, max_results=500), 'entra'),
            (lambda: qradar.batch_search_ips_endpoint(ips, hours=hours, max_results=500), 'endpoint'),
            (lambda: qradar.batch_search_ips_paloalto(ips, hours=hours, max_results=500), 'paloalto'),
        ]

        # Run IP searches in parallel
        logger.info(f"[QRadar] Running {len(ip_tasks)} IP searches in parallel...")
        results = _run_searches_parallel(ip_tasks, errors)

        # Aggregate results
        for result, source in results:
            if result and "error" not in result:
                _aggregate_ip_hits(result.get('events', []), ips, ip_events, source)

        # Convert aggregated results to hits
        for ip, data in ip_events.items():
            if data['count'] > 0:
                ip_hits.append({
                    'ip': ip,
                    'event_count': data['count'],
                    'sources': list(data['sources']),
                    'first_seen': data['first_seen'].strftime("%Y-%m-%d %H:%M") if data['first_seen'] else 'N/A',
                    'last_seen': data['last_seen'].strftime("%Y-%m-%d %H:%M") if data['last_seen'] else 'N/A'
                })
                logger.info(f"  [QRadar] HIT: IP {ip} - {data['count']} events from {data['sources']}")

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


def _run_searches_parallel(
    tasks: List[Tuple[Callable, str]],
    errors: List[str]
) -> List[Tuple[Dict[str, Any], str]]:
    """Run multiple QRadar searches in parallel.

    Args:
        tasks: List of (search_function, source_name) tuples
        errors: List to append errors to

    Returns:
        List of (result, source_name) tuples
    """
    results = []

    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_SEARCHES) as executor:
        # Submit all tasks
        future_to_source = {
            executor.submit(search_func): source
            for search_func, source in tasks
        }

        # Collect results as they complete
        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                result = future.result()
                results.append((result, source))
                logger.info(f"[QRadar] {source} search completed")
            except Exception as e:
                errors.append(f"{source} batch: {str(e)}")
                logger.error(f"[QRadar] {source} batch error: {e}")
                results.append((None, source))

    return results


def _aggregate_domain_hits(
    events: List[Dict[str, Any]],
    domains: List[str],
    domain_events: Dict[str, Dict],
    source: str
) -> None:
    """Aggregate events by matching domain.

    Args:
        events: List of events from QRadar
        domains: List of domains we searched for
        domain_events: Dict to accumulate results {domain: {count, sources, first_seen, last_seen}}
        source: Source identifier (webproxy, email, o365, paloalto)
    """
    for event in events:
        # Check URL, Subject, sender fields for domain matches
        url = event.get('URL', '') or event.get('url', '') or ''
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
                        'last_seen': None
                    }

                domain_events[domain]['count'] += 1
                domain_events[domain]['sources'].add(source)

                # Track timestamps
                ts = _parse_timestamp(event.get('starttime'))
                if ts:
                    if domain_events[domain]['first_seen'] is None or ts < domain_events[domain]['first_seen']:
                        domain_events[domain]['first_seen'] = ts
                    if domain_events[domain]['last_seen'] is None or ts > domain_events[domain]['last_seen']:
                        domain_events[domain]['last_seen'] = ts


def _aggregate_ip_hits(
    events: List[Dict[str, Any]],
    ips: List[str],
    ip_events: Dict[str, Dict],
    source: str
) -> None:
    """Aggregate events by matching IP.

    Args:
        events: List of events from QRadar
        ips: List of IPs we searched for
        ip_events: Dict to accumulate results {ip: {count, sources, first_seen, last_seen}}
        source: Source identifier (general, zpa, entra, endpoint, paloalto)
    """
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
                        'last_seen': None
                    }

                ip_events[ip]['count'] += 1
                ip_events[ip]['sources'].add(source)

                # Track timestamps
                ts = _parse_timestamp(event.get('starttime'))
                if ts:
                    if ip_events[ip]['first_seen'] is None or ts < ip_events[ip]['first_seen']:
                        ip_events[ip]['first_seen'] = ts
                    if ip_events[ip]['last_seen'] is None or ts > ip_events[ip]['last_seen']:
                        ip_events[ip]['last_seen'] = ts


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
