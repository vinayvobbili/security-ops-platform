"""IOC hunting across multiple security tools."""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Optional, Dict, Callable

from ..models import IOCHuntResult, ToolHuntResult
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
    tools: Optional[List[str]] = None,
    on_tool_complete: Optional[Callable[[ToolHuntResult, str, str, int, int, dict], None]] = None,
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
        on_tool_complete: Optional callback called when each tool finishes.
                          Signature: (tool_result, tipper_id, tipper_title, hours, total_iocs, searched_iocs_dict)
                          This allows posting each tool's results immediately without waiting for others.

    Returns:
        IOCHuntResult with hits from all tools
    """
    if tools is None:
        tools = ["qradar", "crowdstrike"]

    total_iocs = (
        len(entities.ips) +
        len(entities.domains) +
        len(entities.urls) +  # URL paths (benign domains with malicious paths)
        len(entities.filenames) +  # Malicious script filenames
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

    # Build searched IOCs dict for callbacks
    all_hashes = (
        entities.hashes.get('md5', []) +
        entities.hashes.get('sha1', []) +
        entities.hashes.get('sha256', [])
    )
    searched_iocs = {
        'domains': entities.domains[:20],
        'urls': entities.urls[:20],
        'filenames': entities.filenames[:20],
        'ips': entities.ips[:20],
        'hashes': all_hashes[:10],
    }

    # Run hunts in PARALLEL - QRadar shouldn't block CrowdStrike
    qradar_result = None
    crowdstrike_result = None
    abnormal_result = None
    all_errors = []

    futures = {}
    with ThreadPoolExecutor(max_workers=3, thread_name_prefix="hunt") as executor:
        if "qradar" in tools:
            futures[executor.submit(hunt_qradar, entities, hours)] = "qradar"
        if "crowdstrike" in tools:
            futures[executor.submit(hunt_crowdstrike, entities, hours)] = "crowdstrike"
        if "abnormal" in tools:
            futures[executor.submit(hunt_abnormal, entities, hours)] = "abnormal"

        for future in as_completed(futures):
            tool_name = futures[future]
            try:
                result = future.result()
                if tool_name == "qradar":
                    qradar_result = result
                    logger.info(f"[hunt] QRadar complete: {result.total_hits} hits")
                elif tool_name == "crowdstrike":
                    crowdstrike_result = result
                    logger.info(f"[hunt] CrowdStrike complete: {result.total_hits} hits")
                elif tool_name == "abnormal":
                    abnormal_result = result
                    logger.info(f"[hunt] Abnormal complete: {result.total_hits} hits")
                all_errors.extend(result.errors)

                # Post this tool's results immediately via callback
                if on_tool_complete:
                    try:
                        on_tool_complete(
                            result, tipper_id, tipper_title, hours, total_iocs, searched_iocs
                        )
                    except Exception as cb_err:
                        logger.error(f"[hunt] Callback failed for {tool_name}: {cb_err}")
            except Exception as e:
                logger.error(f"[hunt] {tool_name} hunt failed: {e}")
                error_msg = f"{tool_name}: {str(e)}"
                all_errors.append(error_msg)

                # Post error result to AZDO so user knows the tool failed
                if on_tool_complete:
                    tool_display_names = {
                        "qradar": "QRadar",
                        "crowdstrike": "CrowdStrike",
                        "abnormal": "Abnormal",
                    }
                    error_result = ToolHuntResult(
                        tool_name=tool_display_names.get(tool_name, tool_name),
                        total_hits=0,
                        errors=[f"Hunt failed: {str(e)}"],
                    )
                    try:
                        on_tool_complete(
                            error_result, tipper_id, tipper_title, hours, total_iocs, searched_iocs
                        )
                    except Exception as cb_err:
                        logger.error(f"[hunt] Callback failed for {tool_name} error: {cb_err}")

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
        searched_domains=searched_iocs['domains'],
        searched_urls=searched_iocs['urls'],
        searched_filenames=searched_iocs['filenames'],
        searched_ips=searched_iocs['ips'],
        searched_hashes=searched_iocs['hashes'],
    )
