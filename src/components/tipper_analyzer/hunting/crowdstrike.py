"""CrowdStrike IOC hunting functions."""

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

from ..models import ToolHuntResult

logger = logging.getLogger(__name__)


def _generate_logscale_queries(
    ips: List[str],
    domains: List[str],
    urls: List[str],
    filenames: List[str],
    hashes: List[Tuple[str, str]],
    hours: int
) -> List[dict]:
    """Generate LogScale/Event Search queries for IOC hunting.

    These queries can be run in Falcon's Event Search UI for deeper
    investigation beyond detections/alerts.

    Args:
        ips: List of IP addresses
        domains: List of domains
        urls: List of URLs
        filenames: List of filenames
        hashes: List of (hash, hash_type) tuples
        hours: Hours to search back (for documentation)

    Returns:
        List of query dicts with 'type' and 'query' keys
    """
    queries = []
    days = hours // 24

    # IP Address query - Network connections
    if ips:
        ip_pattern = "|".join([re.escape(ip) for ip in ips])
        query = f"""#event_simpleName=NetworkConnectIP4
| RemoteAddressIP4=/{ip_pattern}/
| table([timestamp, aid, ComputerName, UserName, LocalAddressIP4, RemoteAddressIP4, RemotePort, ContextBaseFileName])
| sort(timestamp, order=desc, limit=500)"""
        queries.append({
            'type': f'Event Search: IP Network Connections (last {days} days)',
            'query': query,
            'query_type': 'logscale'
        })

        # Also add DNS query for IPs (reverse lookups)
        query_dns = f"""#event_simpleName=DnsRequest
| (ContextBaseFileName=* OR ImageFileName=*)
| RespondingDnsServer=/{ip_pattern}/ OR DomainName=/{ip_pattern}/
| table([timestamp, aid, ComputerName, DomainName, RespondingDnsServer, ContextBaseFileName])
| sort(timestamp, order=desc, limit=500)"""
        queries.append({
            'type': f'Event Search: IP in DNS (last {days} days)',
            'query': query_dns,
            'query_type': 'logscale'
        })

    # Domain query - DNS requests
    if domains:
        # Escape dots in domains for regex
        domain_patterns = "|".join([re.escape(d).replace(r"\.", r"\\.") for d in domains])
        query = f"""#event_simpleName=DnsRequest
| DomainName=/(^|\\.){domain_patterns}$/i
| table([timestamp, aid, ComputerName, UserName, DomainName, RespondingDnsServer, ContextBaseFileName])
| sort(timestamp, order=desc, limit=500)"""
        queries.append({
            'type': f'Event Search: Domain DNS Requests (last {days} days)',
            'query': query,
            'query_type': 'logscale'
        })

    # URL query - HTTP requests (if available) or network connections to URL hosts
    if urls:
        # Extract hostnames from URLs for network search
        url_hosts = set()
        for url in urls:
            # Extract hostname from URL
            match = re.match(r'https?://([^/]+)', url)
            if match:
                url_hosts.add(match.group(1).lower())

        if url_hosts:
            host_patterns = "|".join([re.escape(h).replace(r"\.", r"\\.") for h in url_hosts])
            query = f"""#event_simpleName=DnsRequest
| DomainName=/(^|\\.){host_patterns}$/i
| table([timestamp, aid, ComputerName, UserName, DomainName, ContextBaseFileName])
| sort(timestamp, order=desc, limit=500)"""
            queries.append({
                'type': f'Event Search: URL Host DNS (last {days} days)',
                'query': query,
                'query_type': 'logscale'
            })

    # Hash query - Process execution
    if hashes:
        sha256_hashes = [h for h, t in hashes if t.lower() == 'sha256']
        md5_hashes = [h for h, t in hashes if t.lower() == 'md5']

        if sha256_hashes:
            hash_pattern = "|".join(sha256_hashes)
            query = f"""#event_simpleName=ProcessRollup2
| SHA256HashData=/{hash_pattern}/i
| table([timestamp, aid, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName, SHA256HashData])
| sort(timestamp, order=desc, limit=500)"""
            queries.append({
                'type': f'Event Search: SHA256 Process Execution (last {days} days)',
                'query': query,
                'query_type': 'logscale'
            })

        if md5_hashes:
            hash_pattern = "|".join(md5_hashes)
            query = f"""#event_simpleName=ProcessRollup2
| MD5HashData=/{hash_pattern}/i
| table([timestamp, aid, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName, MD5HashData])
| sort(timestamp, order=desc, limit=500)"""
            queries.append({
                'type': f'Event Search: MD5 Process Execution (last {days} days)',
                'query': query,
                'query_type': 'logscale'
            })

    # Filename query - Process execution and file writes
    if filenames:
        # Escape special regex chars but keep the filename pattern
        filename_patterns = "|".join([re.escape(f) for f in filenames])
        query = f"""#event_simpleName=ProcessRollup2
| ImageFileName=/({filename_patterns})$/i
| table([timestamp, aid, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName, SHA256HashData])
| sort(timestamp, order=desc, limit=500)"""
        queries.append({
            'type': f'Event Search: Filename Process Execution (last {days} days)',
            'query': query,
            'query_type': 'logscale'
        })

        # Also check file writes
        query_write = f"""#event_simpleName=/^(NewExecutableWritten|PeFileWritten|ScriptWritten)$/
| FileName=/({filename_patterns})$/i
| table([timestamp, aid, ComputerName, FileName, FilePath, SHA256HashData, ContextBaseFileName])
| sort(timestamp, order=desc, limit=500)"""
        queries.append({
            'type': f'Event Search: Filename File Writes (last {days} days)',
            'query': query_write,
            'query_type': 'logscale'
        })

    return queries


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
        errors = []
        logger.info(f"[CrowdStrike] Starting batched IP search ({len(ips)} IPs)...")

        try:
            # Batch search alerts for all IPs at once (using Alerts API)
            det_result = cs_client.batch_search_detections_by_ips(ips, hours=hours)
            if det_result.get('fql_query'):
                queries.append({
                    'type': 'IP Alert Search (Alerts API)',
                    'query': det_result['fql_query']
                })
            if 'error' in det_result:
                errors.append(f"Alert search: {det_result['error']}")

            # Search ThreatGraph for network activity (shows connections even without detections)
            tg_result = cs_client.batch_search_threatgraph_ips(ips)
            if tg_result.get('api_call'):
                queries.append({
                    'type': 'IP Network Activity (ThreatGraph)',
                    'query': tg_result['api_call']
                })
            if 'error' in tg_result:
                # ThreatGraph errors are non-fatal, just log
                logger.debug(f"ThreatGraph search: {tg_result['error']}")

            # Combine results by IP
            # Note: det_result now uses Alerts API (Detects API was decommissioned)
            alert_by_ip = det_result.get('by_ip', {})
            tg_by_ip = tg_result.get('by_ip', {})

            for ip in ips:
                alert_data = alert_by_ip.get(ip, {"count": 0, "hostnames": []})
                tg_data = tg_by_ip.get(ip, {"count": 0, "hosts": []})

                alert_count = alert_data.get('count', 0)
                network_hosts_count = tg_data.get('count', 0)

                # Include IP if it has alerts OR network activity
                if alert_count + network_hosts_count > 0:
                    # Combine hostnames from all sources
                    hostnames = list(set(
                        alert_data.get('hostnames', []) +
                        tg_data.get('hosts', [])
                    ))
                    ip_hits.append({
                        'ip': ip,
                        'detection_count': 0,  # Detects API decommissioned
                        'alert_count': alert_count,
                        'network_hosts_count': network_hosts_count,
                        'hostnames': hostnames[:10]
                    })
                    logger.info(f"  [CrowdStrike] HIT: IP {ip} - {alert_count} alerts, {network_hosts_count} hosts communicated")

        except Exception as e:
            logger.error(f"CrowdStrike batched IP search error: {e}")
            errors.append(f"IP search: {str(e)}")

        logger.info(f"[CrowdStrike] IP search complete: {len(ip_hits)} hits")
        return ip_hits, errors, queries

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

    # Generate LogScale/Event Search queries for analyst use
    logscale_queries = _generate_logscale_queries(
        ips=ips,
        domains=domains,
        urls=urls,
        filenames=filenames,
        hashes=all_hashes,
        hours=hours
    )
    logger.info(f"[CrowdStrike] Generated {len(logscale_queries)} Event Search queries")

    # Try to execute LogScale queries via API (gracefully handle if access not available)
    logscale_results = None
    logscale_events_found = 0
    foundry_access_denied = False
    try:
        logger.info("[CrowdStrike] Attempting to run LogScale queries via Foundry API...")
        logscale_results = cs_client.run_logscale_queries_batch(logscale_queries, hours=hours)

        if logscale_results.get('access_denied'):
            logger.info("[CrowdStrike] LogScale API access not available - queries shown for manual use")
            foundry_access_denied = True
            # Add note to queries that they need manual execution
            for q in logscale_queries:
                q['execution_status'] = 'manual'
        else:
            logscale_events_found = logscale_results.get('total_events', 0)
            queries_run = logscale_results.get('queries_run', 0)
            logger.info(f"[CrowdStrike] LogScale queries executed: {queries_run} queries, {logscale_events_found} total events")

            # Update queries with execution results
            query_results_map = {r['type']: r for r in logscale_results.get('query_results', [])}
            for q in logscale_queries:
                result = query_results_map.get(q['type'])
                if result:
                    q['execution_status'] = 'executed'
                    q['event_count'] = result.get('count', 0)
                    q['sample_events'] = result.get('events', [])[:5]
                else:
                    q['execution_status'] = 'manual'

            # Add LogScale errors if any
            for err in logscale_results.get('errors', []):
                if 'access denied' not in err.lower():
                    all_errors.append(f"LogScale: {err}")

    except Exception as e:
        logger.warning(f"[CrowdStrike] LogScale query execution failed: {e}")
        for q in logscale_queries:
            q['execution_status'] = 'manual'

    all_queries.extend(logscale_queries)

    return ToolHuntResult(
        tool_name="CrowdStrike",
        total_hits=total_hits,
        ip_hits=all_ip_hits,
        hash_hits=all_hash_hits,
        domain_hits=all_domain_hits,
        url_hits=all_url_hits,
        filename_hits=all_filename_hits,
        errors=all_errors[:5],
        queries=all_queries,
        foundry_access_denied=foundry_access_denied
    )
