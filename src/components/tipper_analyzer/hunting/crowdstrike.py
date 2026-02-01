"""CrowdStrike IOC hunting functions."""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..models import ToolHuntResult

logger = logging.getLogger(__name__)


def hunt_crowdstrike(entities, hours: int) -> ToolHuntResult:
    """Hunt IOCs in CrowdStrike IN PARALLEL.

    Runs all search types concurrently:
    - IP search (detections + alerts)
    - Hash search (detections)
    - Domain search (Falcon X intel)
    - URL search (ThreatGraph)
    - Filename search (detections)

    Args:
        entities: ExtractedEntities object from entity_extractor
        hours: Number of hours to search back

    Returns:
        ToolHuntResult with CrowdStrike findings
    """
    try:
        from services.crowdstrike import CrowdStrikeClient
    except ImportError:
        return ToolHuntResult(
            tool_name="CrowdStrike",
            total_hits=0,
            errors=["CrowdStrike service not available"]
        )

    cs_client = CrowdStrikeClient()

    # Validate authentication first
    if not cs_client.validate_auth():
        return ToolHuntResult(
            tool_name="CrowdStrike",
            total_hits=0,
            errors=[f"CrowdStrike auth failed: {cs_client.last_error}"]
        )

    # Collect IOCs
    ips = entities.ips[:15]
    domains = entities.domains[:10]
    urls = entities.urls[:10]
    filenames = entities.filenames[:10]
    all_hashes = []
    for hash_type in ['sha256', 'md5']:
        for h in entities.hashes.get(hash_type, [])[:10]:
            all_hashes.append((h, hash_type))

    logger.info(f"[CrowdStrike] PARALLEL hunt: {len(ips)} IPs, {len(domains)} domains, {len(urls)} URLs, {len(filenames)} filenames, {len(all_hashes)} hashes")

    # Results collectors
    all_ip_hits = []
    all_hash_hits = []
    all_domain_hits = []
    all_url_hits = []
    all_filename_hits = []
    all_errors = []
    all_queries = []

    def _search_ips():
        if not ips:
            return [], [], []
        ip_hits = []
        queries = []
        fql_queries_seen = set()
        logger.info(f"[CrowdStrike] Starting IP search ({len(ips)} IPs)...")
        for ip in ips:
            try:
                det_result = cs_client.search_detections_by_ip(ip, hours=hours)
                detection_count = det_result.get('count', 0) if 'error' not in det_result else 0
                # Capture the actual FQL query
                if det_result.get('fql_query') and det_result['fql_query'] not in fql_queries_seen:
                    queries.append({
                        'type': 'IP Detection Search (Detects API)',
                        'query': det_result['fql_query']
                    })
                    fql_queries_seen.add(det_result['fql_query'])
                alert_result = cs_client.search_alerts_by_ip(ip, hours=hours)
                alert_count = alert_result.get('count', 0) if 'error' not in alert_result else 0
                # Capture the actual FQL query for alerts
                if alert_result.get('fql_query') and alert_result['fql_query'] not in fql_queries_seen:
                    queries.append({
                        'type': 'IP Alert Search (Alerts API)',
                        'query': alert_result['fql_query']
                    })
                    fql_queries_seen.add(alert_result['fql_query'])
                if detection_count + alert_count > 0:
                    hostnames = []
                    for d in det_result.get('detections', []):
                        hostname = d.get('device', {}).get('hostname')
                        if hostname and hostname not in hostnames:
                            hostnames.append(hostname)
                    ip_hits.append({
                        'ip': ip,
                        'detection_count': detection_count,
                        'alert_count': alert_count,
                        'hostnames': hostnames[:5]
                    })
                    logger.info(f"  [CrowdStrike] HIT: IP {ip} - {detection_count} detections, {alert_count} alerts")
            except Exception as e:
                logger.debug(f"CrowdStrike IP search error for {ip}: {e}")
        logger.info(f"[CrowdStrike] IP search complete: {len(ip_hits)} hits")
        return ip_hits, [], queries

    def _search_hashes():
        if not all_hashes:
            return [], [], []
        hash_hits = []
        queries = []
        fql_queries_seen = set()
        logger.info(f"[CrowdStrike] Starting hash search ({len(all_hashes)} hashes)...")
        for file_hash, hash_type in all_hashes[:15]:
            try:
                result = cs_client.search_detections_by_hash(file_hash, hours=hours)
                # Capture the actual FQL query
                if result.get('fql_query') and result['fql_query'] not in fql_queries_seen:
                    queries.append({
                        'type': 'Hash Detection Search',
                        'query': result['fql_query']
                    })
                    fql_queries_seen.add(result['fql_query'])
                if 'error' not in result and result.get('count', 0) > 0:
                    hostnames = []
                    for d in result.get('detections', []):
                        hostname = d.get('device', {}).get('hostname')
                        if hostname and hostname not in hostnames:
                            hostnames.append(hostname)
                    hash_hits.append({
                        'hash': file_hash,
                        'hash_type': hash_type.upper(),
                        'detection_count': result['count'],
                        'hostnames': hostnames[:5]
                    })
                    logger.info(f"  [CrowdStrike] HIT: Hash {file_hash[:16]}... - {result['count']} detections")
            except Exception as e:
                logger.debug(f"CrowdStrike hash search error for {file_hash[:16]}...: {e}")
        logger.info(f"[CrowdStrike] Hash search complete: {len(hash_hits)} hits")
        return hash_hits, [], queries

    def _search_domains():
        if not domains:
            return [], [], []
        domain_hits = []
        queries = []
        fql_queries_seen = set()
        logger.info(f"[CrowdStrike] Starting domain search ({len(domains)} domains)...")
        for domain in domains:
            try:
                result = cs_client.lookup_intel_indicator(domain)
                # Capture the actual FQL query
                if result.get('fql_query') and result['fql_query'] not in fql_queries_seen:
                    queries.append({
                        'type': 'Domain Intel Lookup (Falcon X)',
                        'query': result['fql_query']
                    })
                    fql_queries_seen.add(result['fql_query'])
                if 'error' not in result and result.get('count', 0) > 0:
                    indicators = result.get('indicators', [])
                    malicious_count = sum(1 for i in indicators if i.get('malicious_confidence', '').lower() in ['high', 'medium'])
                    domain_hits.append({
                        'domain': domain,
                        'intel_count': result['count'],
                        'malicious_count': malicious_count
                    })
                    logger.info(f"  [CrowdStrike] HIT: Domain {domain} - {result['count']} intel records")
            except Exception as e:
                logger.debug(f"CrowdStrike domain intel lookup error for {domain}: {e}")
        logger.info(f"[CrowdStrike] Domain search complete: {len(domain_hits)} hits")
        return domain_hits, [], queries

    def _search_urls():
        if not urls:
            return [], [], []
        url_hits = []
        queries = []
        api_calls_seen = set()
        logger.info(f"[CrowdStrike] Starting URL search ({len(urls)} URLs)...")
        for url in urls:
            try:
                url_clean = url.replace('https://', '').replace('http://', '')
                domain_part = url_clean.split('/')[0]
                result = cs_client.search_threatgraph_domain(domain_part)
                # Capture the actual API call
                if result.get('api_call') and result['api_call'] not in api_calls_seen:
                    queries.append({
                        'type': 'URL/DNS ThreatGraph Search',
                        'query': result['api_call']
                    })
                    api_calls_seen.add(result['api_call'])
                if 'error' not in result and result.get('count', 0) > 0:
                    url_hits.append({
                        'url': url,
                        'host_count': result['count'],
                        'hostnames': result.get('hosts', [])[:5]
                    })
                    logger.info(f"  [CrowdStrike] HIT: URL {url[:40]}... - {result['count']} hosts connected")
            except Exception as e:
                logger.debug(f"CrowdStrike URL search error for {url[:30]}...: {e}")
        logger.info(f"[CrowdStrike] URL search complete: {len(url_hits)} hits")
        return url_hits, [], queries

    def _search_filenames():
        if not filenames:
            return [], [], []
        filename_hits = []
        queries = []
        fql_queries_seen = set()
        logger.info(f"[CrowdStrike] Starting filename search ({len(filenames)} filenames)...")
        for filename in filenames:
            try:
                result = cs_client.search_detections_by_filename(filename, hours=hours)
                # Capture the actual FQL query
                if result.get('fql_query') and result['fql_query'] not in fql_queries_seen:
                    queries.append({
                        'type': 'Filename Detection Search',
                        'query': result['fql_query']
                    })
                    fql_queries_seen.add(result['fql_query'])
                if 'error' not in result and result.get('count', 0) > 0:
                    hostnames = []
                    for d in result.get('detections', []):
                        hostname = d.get('device', {}).get('hostname')
                        if hostname and hostname not in hostnames:
                            hostnames.append(hostname)
                    filename_hits.append({
                        'filename': filename,
                        'detection_count': result['count'],
                        'hostnames': hostnames[:5]
                    })
                    logger.info(f"  [CrowdStrike] HIT: Filename {filename} - {result['count']} detections")
            except Exception as e:
                logger.debug(f"CrowdStrike filename search error for {filename}: {e}")
        logger.info(f"[CrowdStrike] Filename search complete: {len(filename_hits)} hits")
        return filename_hits, [], queries

    # Run all searches in PARALLEL
    try:
        with ThreadPoolExecutor(max_workers=5, thread_name_prefix="cs-hunt") as executor:
            futures = {
                executor.submit(_search_ips): "ips",
                executor.submit(_search_hashes): "hashes",
                executor.submit(_search_domains): "domains",
                executor.submit(_search_urls): "urls",
                executor.submit(_search_filenames): "filenames",
            }

            for future in as_completed(futures):
                search_type = futures[future]
                try:
                    hits, errors, queries = future.result()
                    if search_type == "ips":
                        all_ip_hits.extend(hits)
                    elif search_type == "hashes":
                        all_hash_hits.extend(hits)
                    elif search_type == "domains":
                        all_domain_hits.extend(hits)
                    elif search_type == "urls":
                        all_url_hits.extend(hits)
                    elif search_type == "filenames":
                        all_filename_hits.extend(hits)
                    all_errors.extend(errors)
                    all_queries.extend(queries)
                except Exception as e:
                    logger.error(f"[CrowdStrike] {search_type} search failed: {e}")
                    all_errors.append(f"{search_type}: {str(e)}")

    except Exception as e:
        all_errors.append(f"CrowdStrike connection error: {str(e)}")
        logger.error(f"CrowdStrike hunt error: {e}")

    total_hits = len(all_ip_hits) + len(all_hash_hits) + len(all_domain_hits) + len(all_url_hits) + len(all_filename_hits)
    logger.info(f"[CrowdStrike] All searches complete: {total_hits} total hits")

    return ToolHuntResult(
        tool_name="CrowdStrike",
        total_hits=total_hits,
        ip_hits=all_ip_hits,
        hash_hits=all_hash_hits,
        domain_hits=all_domain_hits,
        url_hits=all_url_hits,
        filename_hits=all_filename_hits,
        errors=all_errors[:3],
        queries=all_queries
    )
