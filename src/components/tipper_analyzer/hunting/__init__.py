"""IOC hunting across multiple security tools."""

import logging
from datetime import datetime
from typing import List, Optional, Dict

from ..models import IOCHuntResult
from .qradar import hunt_qradar
from .crowdstrike import hunt_crowdstrike
from .abnormal import hunt_abnormal

logger = logging.getLogger(__name__)

__all__ = [
    'hunt_iocs',
    'hunt_qradar',
    'hunt_crowdstrike',
    'hunt_abnormal',
]


def hunt_iocs(
    entities,
    tipper_id: str,
    tipper_title: str,
    hours: int = 720,
    tools: Optional[List[str]] = None
) -> IOCHuntResult:
    """
    Hunt for IOCs across multiple security tools.

    Args:
        entities: ExtractedEntities object from entity_extractor
        tipper_id: Tipper ID (for result tracking)
        tipper_title: Tipper title (for result tracking)
        hours: Hours to search back (default 720 = 30 days)
        tools: List of tools to hunt in (default: all)
               Options: "qradar", "crowdstrike", "abnormal"

    Returns:
        IOCHuntResult with hits from all tools
    """
    if tools is None:
        tools = ["qradar", "crowdstrike"]

    total_iocs = (
        len(entities.ips) +
        len(entities.domains) +
        len(entities.hashes.get('md5', [])) +
        len(entities.hashes.get('sha1', [])) +
        len(entities.hashes.get('sha256', []))
    )

    if total_iocs == 0:
        return IOCHuntResult(
            tipper_id=tipper_id,
            tipper_title=tipper_title,
            hunt_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_iocs_searched=0,
            total_hits=0,
            search_hours=hours,
            errors=["No IOCs found in tipper to hunt"]
        )

    logger.info(f"Hunting {total_iocs} IOCs across {tools} (last {hours} hours)...")

    # Run hunts
    qradar_result = None
    crowdstrike_result = None
    abnormal_result = None
    all_errors = []

    if "qradar" in tools:
        qradar_result = hunt_qradar(entities, hours)
        all_errors.extend(qradar_result.errors)

    if "crowdstrike" in tools:
        crowdstrike_result = hunt_crowdstrike(entities, hours)
        all_errors.extend(crowdstrike_result.errors)

    if "abnormal" in tools:
        abnormal_result = hunt_abnormal(entities, hours)
        all_errors.extend(abnormal_result.errors)

    # Calculate total hits
    total_hits = sum(
        r.total_hits for r in [qradar_result, crowdstrike_result, abnormal_result] if r
    )

    # Compute environment exposure summary
    unique_hosts = set()
    unique_sources = set()

    for tool_result in [qradar_result, crowdstrike_result, abnormal_result]:
        if not tool_result:
            continue
        # Collect unique sources from all hits
        for hit in tool_result.ip_hits + tool_result.domain_hits:
            if hit.get('sources'):
                unique_sources.update(hit['sources'])
        # Collect hostnames from hash hits (CrowdStrike)
        for hit in tool_result.hash_hits:
            if hit.get('hostnames'):
                unique_hosts.update(hit['hostnames'])

    return IOCHuntResult(
        tipper_id=tipper_id,
        tipper_title=tipper_title,
        hunt_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_iocs_searched=total_iocs,
        total_hits=total_hits,
        search_hours=hours,
        qradar=qradar_result,
        crowdstrike=crowdstrike_result,
        abnormal=abnormal_result,
        errors=all_errors[:10],
        unique_hosts=len(unique_hosts),
        unique_sources=list(unique_sources)[:20],
    )
