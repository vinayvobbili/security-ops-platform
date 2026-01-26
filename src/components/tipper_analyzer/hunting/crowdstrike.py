"""CrowdStrike IOC hunting functions."""

import logging

from ..models import ToolHuntResult

logger = logging.getLogger(__name__)


def hunt_crowdstrike(entities, hours: int) -> ToolHuntResult:
    """Hunt IOCs in CrowdStrike (IPs, hashes, domains via detection/alert search).

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

    ip_hits = []
    hash_hits = []
    domain_hits = []
    errors = []

    try:
        cs_client = CrowdStrikeClient()

        # Validate authentication
        if not cs_client.validate_auth():
            return ToolHuntResult(
                tool_name="CrowdStrike",
                total_hits=0,
                errors=[f"CrowdStrike auth failed: {cs_client.last_error}"]
            )

        # Hunt IPs (detections + alerts)
        for ip in entities.ips[:15]:
            try:
                # Search detections by IP
                det_result = cs_client.search_detections_by_ip(ip, hours=hours)
                detection_count = det_result.get('count', 0) if 'error' not in det_result else 0

                # Search alerts by IP
                alert_result = cs_client.search_alerts_by_ip(ip, hours=hours)
                alert_count = alert_result.get('count', 0) if 'error' not in alert_result else 0

                total_count = detection_count + alert_count
                if total_count > 0:
                    # Extract hostnames from detections
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

        # Hunt Hashes (SHA256 and MD5)
        all_hashes = []
        for hash_type in ['sha256', 'md5']:  # CrowdStrike prefers SHA256
            for h in entities.hashes.get(hash_type, [])[:10]:
                all_hashes.append((h, hash_type))

        for file_hash, hash_type in all_hashes[:15]:
            try:
                result = cs_client.search_detections_by_hash(file_hash, hours=hours)
                if 'error' not in result and result.get('count', 0) > 0:
                    # Extract hostnames from detections
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

        # Hunt Domains (Falcon X intel lookup)
        for domain in entities.domains[:10]:
            try:
                result = cs_client.lookup_intel_indicator(domain)
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

    except Exception as e:
        errors.append(f"CrowdStrike connection error: {str(e)}")
        logger.error(f"CrowdStrike hunt error: {e}")

    total_hits = len(ip_hits) + len(hash_hits) + len(domain_hits)
    return ToolHuntResult(
        tool_name="CrowdStrike",
        total_hits=total_hits,
        ip_hits=ip_hits,
        hash_hits=hash_hits,
        domain_hits=domain_hits,
        errors=errors[:3]
    )
