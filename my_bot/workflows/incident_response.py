"""
Incident Response Workflow

LangGraph workflow for comprehensive XSOAR ticket investigation.

Workflow (sequential):
1. Fetch XSOAR ticket data
2. Extract hostname, username, and IOCs from ticket
3. Check CrowdStrike containment status
4. Check CrowdStrike detections
5. Search QRadar events
6. Enrich extracted IOCs
7. Synthesize findings
8. Generate executive summary
9. Post results back to XSOAR (optional)

Usage:
    result = run_incident_response("investigate xsoar ticket 929947 - full incident response")
"""

import logging
import re

from langgraph.graph import StateGraph, END

from my_bot.workflows.state_schemas import IncidentResponseState
from my_bot.workflows.router import extract_ticket_id_from_query, extract_ioc_from_query

logger = logging.getLogger(__name__)


def fetch_xsoar_ticket(state: IncidentResponseState) -> dict:
    """Fetch XSOAR ticket data."""
    ticket_id = state['ticket_id']
    logger.info(f"[IR Workflow] Fetching XSOAR ticket {ticket_id}")

    try:
        from my_bot.tools.xsoar_tools import get_xsoar_ticket

        result = get_xsoar_ticket.invoke({"ticket_id": ticket_id, "environment": "prod"})

        # Parse ticket data from the formatted string response
        ticket_data = {'raw_response': result}
        updates: dict = {'ticket_data': ticket_data}

        # Extract hostname
        hostname_match = re.search(r'Hostname:\s*(\S+)', result)
        if hostname_match and hostname_match.group(1) != 'N/A':
            hostname = hostname_match.group(1).upper()
            updates['hostname'] = hostname
            ticket_data['hostname'] = hostname

        # Extract username
        username_match = re.search(r'Username:\s*(\S+)', result)
        if username_match and username_match.group(1) != 'N/A':
            username = username_match.group(1)
            updates['username'] = username
            ticket_data['username'] = username

        # Extract device ID
        device_match = re.search(r'Device ID:\s*(\S+)', result)
        if device_match and device_match.group(1) != 'N/A':
            ticket_data['device_id'] = device_match.group(1)

        if "Error" in result:
            updates['errors'] = [f"XSOAR fetch: {result}"]

        return updates

    except Exception as e:
        logger.error(f"[IR Workflow] XSOAR fetch error: {e}")
        return {
            'ticket_data': None,
            'errors': [f"XSOAR fetch: {str(e)}"],
        }


def _get_internal_domains() -> set:
    """Get internal/company domains to filter from IOC extraction."""
    domains = {'example.com', 'test.com'}
    try:
        from my_config import get_config
        config = get_config()
        if config.my_web_domain:
            # Add the domain and common variations (e.g., example.com -> example.net, example.org)
            base = config.my_web_domain.lower()
            domains.add(base)
            base_name = base.rsplit('.', 1)[0]
            for tld in ('com', 'net', 'org', 'io', 'co'):
                domains.add(f"{base_name}.{tld}")
    except Exception:
        pass
    return domains


def extract_iocs(state: IncidentResponseState) -> dict:
    """Extract IOCs from ticket data."""
    logger.info("[IR Workflow] Extracting IOCs from ticket")

    ticket_data = state.get('ticket_data', {})

    if not ticket_data:
        return {}

    iocs = []
    raw_response = ticket_data.get('raw_response', '')
    internal_domains = _get_internal_domains()

    # Extract IPs from the ticket
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    ips_found = re.findall(ip_pattern, raw_response)

    # Filter out private/local IPs
    for ip in ips_found:
        octets = ip.split('.')
        if all(0 <= int(o) <= 255 for o in octets):
            # Skip private ranges
            if ip.startswith(('10.', '192.168.', '127.', '0.')):
                continue
            if ip.startswith('172.'):
                second_octet = int(octets[1])
                if 16 <= second_octet <= 31:
                    continue
            iocs.append(ip)

    # Extract domains (if any URLs or domains are mentioned)
    domain_pattern = r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.(?:com|net|org|io|co|info|biz|xyz))\b'
    domains_found = re.findall(domain_pattern, raw_response, re.IGNORECASE)
    for domain in domains_found:
        if domain.lower() not in internal_domains:
            iocs.append(domain.lower())

    # Extract hashes
    hash_pattern = r'\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b'
    hashes_found = re.findall(hash_pattern, raw_response)
    iocs.extend(hashes_found)

    # Deduplicate
    deduplicated = list(set(iocs))
    logger.info(f"[IR Workflow] Extracted {len(deduplicated)} IOCs")

    return {'iocs_extracted': deduplicated}


def check_crowdstrike_containment(state: IncidentResponseState) -> dict:
    """Check CrowdStrike containment status for the hostname."""
    hostname = state.get('hostname')

    if not hostname:
        return {'crowdstrike_status': "N/A - No hostname in ticket"}

    try:
        from my_bot.tools.crowdstrike_tools import get_device_containment_status

        logger.info(f"[IR Workflow] Checking CrowdStrike containment for {hostname}")
        result = get_device_containment_status.invoke({"hostname": hostname})
        return {'crowdstrike_status': result}

    except Exception as e:
        logger.error(f"[IR Workflow] CrowdStrike containment error: {e}")
        return {
            'crowdstrike_status': f"Error: {str(e)}",
            'errors': [f"CrowdStrike containment: {str(e)}"],
        }


def check_crowdstrike_detections(state: IncidentResponseState) -> dict:
    """Get CrowdStrike detections for the hostname."""
    hostname = state.get('hostname')

    if not hostname:
        return {'crowdstrike_detections': "N/A - No hostname in ticket"}

    try:
        from my_bot.tools.crowdstrike_tools import search_crowdstrike_detections_by_hostname

        logger.info(f"[IR Workflow] Fetching CrowdStrike detections for {hostname}")
        result = search_crowdstrike_detections_by_hostname.invoke({"hostname": hostname, "limit": 10})
        return {'crowdstrike_detections': result}

    except Exception as e:
        logger.error(f"[IR Workflow] CrowdStrike detections error: {e}")
        return {
            'crowdstrike_detections': f"Error: {str(e)}",
            'errors': [f"CrowdStrike detections: {str(e)}"],
        }


def search_qradar_events(state: IncidentResponseState) -> dict:
    """Search QRadar for events related to the hostname/user."""
    hostname = state.get('hostname')
    username = state.get('username')

    if not hostname and not username:
        return {'qradar_events': "N/A - No hostname or username to search"}

    try:
        from my_bot.tools.qradar_tools import search_qradar_by_ip, run_qradar_aql_query

        logger.info(f"[IR Workflow] Searching QRadar for {hostname or username}")

        # Search by hostname using AQL
        if hostname:
            aql_query = f"""SELECT sourceip, destinationip, eventname, logsource, magnitude, starttime
FROM events
WHERE LOGSOURCENAME ILIKE '%{hostname}%' OR UTF8(payload) ILIKE '%{hostname}%'
LAST 72 HOURS LIMIT 20"""
            result = run_qradar_aql_query.invoke({"aql_query": aql_query})
        else:
            result = "No hostname available for QRadar search"

        return {'qradar_events': result}

    except Exception as e:
        logger.error(f"[IR Workflow] QRadar search error: {e}")
        return {
            'qradar_events': f"Error: {str(e)}",
            'errors': [f"QRadar search: {str(e)}"],
        }


def enrich_iocs(state: IncidentResponseState) -> dict:
    """Enrich extracted IOCs using the IOC investigation workflow."""
    iocs = state.get('iocs_extracted', [])

    if not iocs:
        logger.info("[IR Workflow] No IOCs to enrich")
        return {}

    logger.info(f"[IR Workflow] Enriching {len(iocs)} IOCs")

    enrichment_results = {}

    # Limit to first 5 IOCs to avoid excessive API calls
    for ioc in iocs[:5]:
        try:
            # Determine IOC type
            ioc_value, ioc_type = extract_ioc_from_query(f"check {ioc}")

            if not ioc_type:
                continue

            # Quick enrichment using individual tools (not full workflow to save time)
            from my_bot.tools.virustotal_tools import (
                lookup_ip_virustotal,
                lookup_domain_virustotal,
                lookup_hash_virustotal,
            )

            logger.info(f"[IR Workflow] Enriching {ioc_type}: {ioc}")

            if ioc_type == "ip":
                vt_result = lookup_ip_virustotal.invoke({"ip_address": ioc})
            elif ioc_type == "domain":
                vt_result = lookup_domain_virustotal.invoke({"domain": ioc})
            elif ioc_type == "hash":
                vt_result = lookup_hash_virustotal.invoke({"file_hash": ioc})
            else:
                vt_result = "Unsupported IOC type"

            enrichment_results[ioc] = {
                'type': ioc_type,
                'virustotal': vt_result,
            }

        except Exception as e:
            logger.error(f"[IR Workflow] IOC enrichment error for {ioc}: {e}")
            enrichment_results[ioc] = {'error': str(e)}

    return {'ioc_enrichment_results': enrichment_results}


def synthesize_findings(state: IncidentResponseState) -> dict:
    """Synthesize all findings into severity assessment."""
    logger.info("[IR Workflow] Synthesizing findings")

    findings = []
    severity = "LOW"

    # Check CrowdStrike containment (skip N/A responses)
    cs_status = state.get('crowdstrike_status', '')
    if cs_status and 'N/A' not in cs_status:
        if 'contained' in cs_status.lower() or 'containment' in cs_status.lower():
            findings.append("Host is contained in CrowdStrike")

    # Check CrowdStrike detections (skip N/A responses)
    cs_detections = state.get('crowdstrike_detections', '')
    if cs_detections and 'N/A' not in cs_detections:
        if 'CRITICAL' in cs_detections.upper() or 'HIGH' in cs_detections.upper():
            findings.append("Critical/High severity CrowdStrike detections found")
            severity = "HIGH"
        elif 'No CrowdStrike' not in cs_detections:
            findings.append("CrowdStrike detections present")
            if severity == "LOW":
                severity = "MEDIUM"

    # Check IOC enrichment
    enrichment = state.get('ioc_enrichment_results', {})
    malicious_iocs = []
    for ioc, data in enrichment.items():
        if isinstance(data, dict) and 'virustotal' in data:
            vt_result = data['virustotal']
            if 'HIGH' in vt_result.upper() or 'MALICIOUS' in vt_result.upper():
                malicious_iocs.append(ioc)

    if malicious_iocs:
        findings.append(f"Malicious IOCs detected: {', '.join(malicious_iocs[:3])}")
        severity = "HIGH"

    # Check QRadar events
    qradar_result = state.get('qradar_events', '')
    if qradar_result and 'Total Events:' in qradar_result and 'No events' not in qradar_result:
        findings.append("SIEM events correlated to this incident")
        if severity == "LOW":
            severity = "MEDIUM"

    # Determine recommended actions based on severity
    actions = []
    if severity == "HIGH":
        actions.append("URGENT: Escalate to senior analyst immediately")
        actions.append("Verify host containment status")
        actions.append("Collect forensic artifacts")
        actions.append("Block malicious IOCs at perimeter")
        actions.append("Notify affected user's manager")
    elif severity == "MEDIUM":
        actions.append("Review all detections and determine scope")
        actions.append("Check for lateral movement indicators")
        actions.append("Document findings in ticket")
        actions.append("Consider containment if evidence of compromise")
    else:
        actions.append("Document findings and close ticket if false positive")
        actions.append("Update detection rules if needed")
        actions.append("No immediate action required")

    return {
        'severity_assessment': severity,
        'recommended_actions': actions,
    }


def generate_executive_summary(state: IncidentResponseState) -> dict:
    """Generate executive summary of the investigation."""
    logger.info("[IR Workflow] Generating executive summary")

    ticket_id = state['ticket_id']
    hostname = state.get('hostname')
    username = state.get('username')
    severity = state.get('severity_assessment', 'Unknown')
    actions = state.get('recommended_actions', [])
    errors = state.get('errors', [])

    # Build the summary
    lines = [
        f"# Incident Response Report",
        f"## XSOAR Ticket #{ticket_id}",
        "",
        "## Quick Summary",
        f"**Severity:** {severity}",
    ]
    if hostname:
        lines.append(f"**Hostname:** {hostname}")
    if username:
        lines.append(f"**Username:** {username}")
    if not hostname and not username:
        lines.append("**Note:** No hostname or username found in ticket (e.g., phishing or email-based alert)")
    lines.append("")

    # CrowdStrike section (only if we had a hostname to check)
    cs_status = state.get('crowdstrike_status', '')
    if cs_status and 'N/A' not in cs_status:
        lines.append("## CrowdStrike Status")
        lines.append(cs_status)
        lines.append("")

    # Detections (only if we had a hostname to check)
    cs_detections = state.get('crowdstrike_detections', '')
    if cs_detections and 'N/A' not in cs_detections:
        lines.append("## CrowdStrike Detections")
        if len(cs_detections) > 1500:
            lines.append(cs_detections[:1500] + "\n\n*... truncated ...*")
        else:
            lines.append(cs_detections)
        lines.append("")

    # IOC Enrichment (only if IOCs were found and enriched)
    enrichment = state.get('ioc_enrichment_results', {})
    if enrichment:
        lines.append("## IOC Enrichment Results")
        for ioc, data in list(enrichment.items())[:5]:
            if isinstance(data, dict):
                lines.append(f"### {ioc}")
                if 'virustotal' in data:
                    vt = data['virustotal']
                    if len(vt) > 500:
                        vt = vt[:500] + "\n*... truncated ...*"
                    lines.append(vt)
                if 'error' in data:
                    lines.append(f"Error: {data['error']}")
                lines.append("")
        lines.append("")

    # QRadar (only if results exist)
    qradar_result = state.get('qradar_events', '')
    if qradar_result and 'N/A' not in qradar_result:
        lines.append("## SIEM Correlation (QRadar)")
        if len(qradar_result) > 1000:
            lines.append(qradar_result[:1000] + "\n\n*... truncated ...*")
        else:
            lines.append(qradar_result)
        lines.append("")

    # Summary of what was skipped (so the report doesn't look empty)
    skipped = []
    if not hostname:
        skipped.extend(["CrowdStrike containment", "CrowdStrike detections", "QRadar SIEM search"])
    if not state.get('iocs_extracted'):
        skipped.append("IOC enrichment (no external IOCs found)")
    if skipped:
        lines.append("## Skipped Steps")
        lines.append(f"The following were skipped due to missing data: {', '.join(skipped)}")
        lines.append("")

    # Recommended Actions
    lines.append("## Recommended Actions")
    for i, action in enumerate(actions, 1):
        lines.append(f"{i}. {action}")
    lines.append("")

    # Errors
    if errors:
        lines.append("## Investigation Errors")
        for error in errors:
            lines.append(f"- {error}")
        lines.append("")

    return {'executive_summary': "\n".join(lines)}


def post_results_to_xsoar(state: IncidentResponseState) -> dict:
    """Optionally post the summary back to XSOAR ticket."""
    if not state.get('post_to_xsoar', False):
        logger.info("[IR Workflow] Skipping XSOAR post (not requested)")
        return {}

    ticket_id = state['ticket_id']
    summary = state.get('executive_summary', '')

    if not summary:
        return {}

    try:
        from my_bot.tools.xsoar_tools import add_note_to_xsoar_ticket

        logger.info(f"[IR Workflow] Posting summary to XSOAR ticket {ticket_id}")

        # Add a note header
        note = f"## Automated Investigation Summary\n\n{summary}"
        result = add_note_to_xsoar_ticket.invoke({
            "ticket_id": ticket_id,
            "note_text": note,
            "environment": "prod"
        })

        if "Error" in result:
            return {'errors': [f"XSOAR post: {result}"]}

    except Exception as e:
        logger.error(f"[IR Workflow] XSOAR post error: {e}")
        return {'errors': [f"XSOAR post: {str(e)}"]}

    return {}


def build_incident_response_graph() -> StateGraph:
    """Build the incident response LangGraph workflow.

    Workflow is sequential to avoid state merging issues with parallel nodes.
    Order: Fetch -> Extract IOCs -> CS Containment -> CS Detections -> QRadar ->
           Enrich IOCs -> Synthesize -> Summary -> Post
    """
    graph = StateGraph(IncidentResponseState)

    # Add nodes
    graph.add_node("fetch_ticket", fetch_xsoar_ticket)
    graph.add_node("extract_iocs", extract_iocs)
    graph.add_node("check_cs_containment", check_crowdstrike_containment)
    graph.add_node("check_cs_detections", check_crowdstrike_detections)
    graph.add_node("search_qradar", search_qradar_events)
    graph.add_node("enrich_iocs", enrich_iocs)
    graph.add_node("synthesize", synthesize_findings)
    graph.add_node("generate_summary", generate_executive_summary)
    graph.add_node("post_to_xsoar", post_results_to_xsoar)

    # Set entry point
    graph.set_entry_point("fetch_ticket")

    # Sequential edges (avoids LangGraph state merge conflicts)
    graph.add_edge("fetch_ticket", "extract_iocs")
    graph.add_edge("extract_iocs", "check_cs_containment")
    graph.add_edge("check_cs_containment", "check_cs_detections")
    graph.add_edge("check_cs_detections", "search_qradar")
    graph.add_edge("search_qradar", "enrich_iocs")
    graph.add_edge("enrich_iocs", "synthesize")
    graph.add_edge("synthesize", "generate_summary")
    graph.add_edge("generate_summary", "post_to_xsoar")
    graph.add_edge("post_to_xsoar", END)

    return graph


# Compile the graph once at module load
_ir_graph = None


def get_ir_graph():
    """Get the compiled incident response graph (lazy initialization)."""
    global _ir_graph
    if _ir_graph is None:
        _ir_graph = build_incident_response_graph().compile()
    return _ir_graph


def run_incident_response(query: str) -> dict:
    """
    Run the incident response workflow.

    Args:
        query: User's query containing the ticket ID to investigate

    Returns:
        dict with 'content' (the report) and token metrics
    """
    logger.info(f"[IR Workflow] Starting investigation for query: {query[:100]}")

    # Extract ticket ID from query
    ticket_id = extract_ticket_id_from_query(query)

    if not ticket_id:
        return {
            'content': "Could not identify an XSOAR ticket ID in your query. Please include the ticket number (e.g., 'investigate XSOAR ticket 929947').",
            'input_tokens': 0,
            'output_tokens': 0,
            'total_tokens': 0,
            'prompt_time': 0.0,
            'generation_time': 0.0,
            'tokens_per_sec': 0.0,
        }

    # Check if user wants to post back to XSOAR
    should_post_to_xsoar = 'post' in query.lower() or 'write' in query.lower() or 'update' in query.lower()

    # Initialize state
    initial_state: IncidentResponseState = {
        'ticket_id': ticket_id,
        'ticket_data': None,
        'hostname': None,
        'username': None,
        'iocs_extracted': [],
        'crowdstrike_status': None,
        'crowdstrike_detections': None,
        'ioc_enrichment_results': {},
        'qradar_events': None,
        'executive_summary': None,
        'severity_assessment': None,
        'recommended_actions': [],
        'errors': [],
        'post_to_xsoar': should_post_to_xsoar,
    }

    try:
        import time
        start_time = time.time()

        # Run the graph
        graph = get_ir_graph()
        final_state = graph.invoke(initial_state)

        elapsed = time.time() - start_time
        logger.info(f"[IR Workflow] Completed in {elapsed:.1f}s")

        return {
            'content': final_state.get('executive_summary', 'Investigation completed but no summary generated.'),
            'input_tokens': 0,
            'output_tokens': 0,
            'total_tokens': 0,
            'prompt_time': elapsed,
            'generation_time': 0.0,
            'tokens_per_sec': 0.0,
        }

    except Exception as e:
        logger.error(f"[IR Workflow] Error: {e}", exc_info=True)
        return {
            'content': f"Incident response workflow failed: {str(e)}",
            'input_tokens': 0,
            'output_tokens': 0,
            'total_tokens': 0,
            'prompt_time': 0.0,
            'generation_time': 0.0,
            'tokens_per_sec': 0.0,
        }
