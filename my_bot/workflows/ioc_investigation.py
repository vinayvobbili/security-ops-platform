"""
IOC Investigation Workflow

LangGraph workflow for comprehensive IOC enrichment across multiple threat intel sources.

Workflow (sequential):
1. Detect IOC type (ip/domain/hash/url)
2. VirusTotal enrichment
3. AbuseIPDB enrichment (IP only)
4. Shodan enrichment (IP/domain only)
5. Recorded Future enrichment
6. Synthesize findings and calculate risk score
7. Conditional: QRadar search if risk is high
8. Generate final report

Usage:
    result = run_ioc_investigation("investigate ip 203.0.113.50 - full threat intel analysis")
"""

import logging
from typing import Literal

from langgraph.graph import StateGraph, END

from my_bot.workflows.state_schemas import IOCInvestigationState
from my_bot.workflows.router import extract_ioc_from_query

logger = logging.getLogger(__name__)

# Risk thresholds
HIGH_RISK_THRESHOLD = 50  # Score above this triggers QRadar search
MEDIUM_RISK_THRESHOLD = 25


def detect_ioc_type(state: IOCInvestigationState) -> IOCInvestigationState:
    """Initial node: Validate and set IOC type."""
    logger.info(f"[IOC Workflow] Starting investigation for: {state.get('ioc_value')}")

    # Initialize accumulator fields if not present
    if state.get('risk_factors') is None:
        state['risk_factors'] = []
    if state.get('errors') is None:
        state['errors'] = []
    if state.get('recommended_actions') is None:
        state['recommended_actions'] = []

    return state


def lookup_virustotal(state: IOCInvestigationState) -> IOCInvestigationState:
    """Lookup IOC in VirusTotal."""
    ioc_value = state['ioc_value']
    ioc_type = state['ioc_type']

    try:
        from my_bot.tools.virustotal_tools import (
            lookup_ip_virustotal,
            lookup_domain_virustotal,
            lookup_hash_virustotal,
            lookup_url_virustotal,
        )

        logger.info(f"[IOC Workflow] VirusTotal lookup for {ioc_type}: {ioc_value}")

        if ioc_type == "ip":
            result = lookup_ip_virustotal.invoke({"ip_address": ioc_value})
        elif ioc_type == "domain":
            result = lookup_domain_virustotal.invoke({"domain": ioc_value})
        elif ioc_type == "hash":
            result = lookup_hash_virustotal.invoke({"file_hash": ioc_value})
        elif ioc_type == "url":
            result = lookup_url_virustotal.invoke({"url": ioc_value})
        else:
            result = f"Unsupported IOC type: {ioc_type}"

        state['virustotal_result'] = result

        # Extract risk factors from VT result
        if "HIGH" in result.upper() or "MALICIOUS" in result.upper():
            state['risk_factors'] = state.get('risk_factors', []) + ["VirusTotal: High threat level detected"]
        elif "MEDIUM" in result.upper() or "SUSPICIOUS" in result.upper():
            state['risk_factors'] = state.get('risk_factors', []) + ["VirusTotal: Medium threat level"]

    except Exception as e:
        logger.error(f"[IOC Workflow] VirusTotal error: {e}")
        state['errors'] = state.get('errors', []) + [f"VirusTotal: {str(e)}"]
        state['virustotal_result'] = f"Error: {str(e)}"

    return state


def lookup_abuseipdb(state: IOCInvestigationState) -> IOCInvestigationState:
    """Lookup IP in AbuseIPDB (IP addresses only)."""
    if state['ioc_type'] != "ip":
        state['abuseipdb_result'] = "N/A - AbuseIPDB only supports IP addresses"
        return state

    ioc_value = state['ioc_value']

    try:
        from my_bot.tools.abuseipdb_tools import lookup_ip_abuseipdb

        logger.info(f"[IOC Workflow] AbuseIPDB lookup for IP: {ioc_value}")
        result = lookup_ip_abuseipdb.invoke({"ip_address": ioc_value})
        state['abuseipdb_result'] = result

        # Extract risk factors
        if "HIGH RISK" in result.upper():
            state['risk_factors'] = state.get('risk_factors', []) + ["AbuseIPDB: High abuse confidence score"]
        elif "MEDIUM RISK" in result.upper():
            state['risk_factors'] = state.get('risk_factors', []) + ["AbuseIPDB: Moderate abuse reports"]

    except Exception as e:
        logger.error(f"[IOC Workflow] AbuseIPDB error: {e}")
        state['errors'] = state.get('errors', []) + [f"AbuseIPDB: {str(e)}"]
        state['abuseipdb_result'] = f"Error: {str(e)}"

    return state


def lookup_shodan(state: IOCInvestigationState) -> IOCInvestigationState:
    """Lookup IOC in Shodan (IP and domain only)."""
    ioc_type = state['ioc_type']

    if ioc_type not in ("ip", "domain"):
        state['shodan_result'] = "N/A - Shodan only supports IP addresses and domains"
        return state

    ioc_value = state['ioc_value']

    try:
        from my_bot.tools.shodan_tools import lookup_ip_shodan, lookup_domain_shodan

        logger.info(f"[IOC Workflow] Shodan lookup for {ioc_type}: {ioc_value}")

        if ioc_type == "ip":
            result = lookup_ip_shodan.invoke({"ip_address": ioc_value})
        else:
            result = lookup_domain_shodan.invoke({"domain": ioc_value})

        state['shodan_result'] = result

        # Extract risk factors
        if "Vulnerabilities" in result or "CVE" in result:
            state['risk_factors'] = state.get('risk_factors', []) + ["Shodan: Known CVEs detected on infrastructure"]
        if "HIGH" in result.upper():
            state['risk_factors'] = state.get('risk_factors', []) + ["Shodan: High-risk exposure detected"]

    except Exception as e:
        logger.error(f"[IOC Workflow] Shodan error: {e}")
        state['errors'] = state.get('errors', []) + [f"Shodan: {str(e)}"]
        state['shodan_result'] = f"Error: {str(e)}"

    return state


def lookup_recorded_future(state: IOCInvestigationState) -> IOCInvestigationState:
    """Lookup IOC in Recorded Future."""
    ioc_value = state['ioc_value']
    ioc_type = state['ioc_type']

    try:
        from my_bot.tools.recorded_future_tools import (
            lookup_ip_recorded_future,
            lookup_domain_recorded_future,
            lookup_hash_recorded_future,
            lookup_url_recorded_future,
        )

        logger.info(f"[IOC Workflow] Recorded Future lookup for {ioc_type}: {ioc_value}")

        if ioc_type == "ip":
            result = lookup_ip_recorded_future.invoke({"ip_address": ioc_value})
        elif ioc_type == "domain":
            result = lookup_domain_recorded_future.invoke({"domain": ioc_value})
        elif ioc_type == "hash":
            result = lookup_hash_recorded_future.invoke({"file_hash": ioc_value})
        elif ioc_type == "url":
            result = lookup_url_recorded_future.invoke({"url": ioc_value})
        else:
            result = f"Unsupported IOC type: {ioc_type}"

        state['recorded_future_result'] = result

        # Extract risk factors
        if "Risk Score:" in result:
            # Try to parse risk score
            import re
            score_match = re.search(r'Risk Score:\s*(\d+)/99', result)
            if score_match:
                score = int(score_match.group(1))
                if score >= 65:
                    state['risk_factors'] = state.get('risk_factors', []) + [f"Recorded Future: Critical risk score ({score}/99)"]
                elif score >= 25:
                    state['risk_factors'] = state.get('risk_factors', []) + [f"Recorded Future: Elevated risk score ({score}/99)"]

    except Exception as e:
        logger.error(f"[IOC Workflow] Recorded Future error: {e}")
        state['errors'] = state.get('errors', []) + [f"Recorded Future: {str(e)}"]
        state['recorded_future_result'] = f"Error: {str(e)}"

    return state


def synthesize_risk(state: IOCInvestigationState) -> IOCInvestigationState:
    """Synthesize findings and calculate overall risk score."""
    logger.info("[IOC Workflow] Synthesizing risk assessment")

    risk_factors = state.get('risk_factors', [])
    errors = state.get('errors', [])

    # Calculate risk score based on findings
    risk_score = 0

    # VirusTotal scoring
    vt_result = state.get('virustotal_result', '')
    if 'HIGH' in vt_result.upper() or 'MALICIOUS' in vt_result.upper():
        risk_score += 30
    elif 'MEDIUM' in vt_result.upper() or 'SUSPICIOUS' in vt_result.upper():
        risk_score += 15

    # AbuseIPDB scoring
    abuse_result = state.get('abuseipdb_result', '')
    if 'HIGH RISK' in abuse_result.upper():
        risk_score += 25
    elif 'MEDIUM RISK' in abuse_result.upper():
        risk_score += 12

    # Shodan scoring
    shodan_result = state.get('shodan_result', '')
    if 'CVE' in shodan_result or 'Vulnerabilities' in shodan_result:
        risk_score += 15
    if 'HIGH' in shodan_result.upper():
        risk_score += 10

    # Recorded Future scoring
    rf_result = state.get('recorded_future_result', '')
    import re
    rf_score_match = re.search(r'Risk Score:\s*(\d+)/99', rf_result)
    if rf_score_match:
        rf_score = int(rf_score_match.group(1))
        risk_score += min(30, rf_score // 3)  # Scale RF score contribution

    # Cap at 100
    risk_score = min(100, risk_score)
    state['risk_score'] = risk_score

    # Determine recommended actions
    actions = []
    if risk_score >= HIGH_RISK_THRESHOLD:
        actions.append("IMMEDIATE: Block IOC at perimeter")
        actions.append("Search SIEM for historical activity")
        actions.append("Create incident ticket for investigation")
        if state['ioc_type'] == 'ip':
            actions.append("Check if any endpoints communicated with this IP")
    elif risk_score >= MEDIUM_RISK_THRESHOLD:
        actions.append("Monitor IOC for additional activity")
        actions.append("Add to watchlist")
        actions.append("Review any existing alerts")
    else:
        actions.append("No immediate action required")
        actions.append("Continue monitoring as part of normal operations")

    state['recommended_actions'] = actions

    logger.info(f"[IOC Workflow] Risk score: {risk_score}, Factors: {len(risk_factors)}")

    return state


def should_search_qradar(state: IOCInvestigationState) -> Literal["search_qradar", "skip_qradar"]:
    """Conditional edge: determine if we should search QRadar."""
    risk_score = state.get('risk_score', 0)

    if risk_score >= HIGH_RISK_THRESHOLD:
        logger.info(f"[IOC Workflow] Risk score {risk_score} >= {HIGH_RISK_THRESHOLD}, searching QRadar")
        return "search_qradar"
    else:
        logger.info(f"[IOC Workflow] Risk score {risk_score} < {HIGH_RISK_THRESHOLD}, skipping QRadar")
        return "skip_qradar"


def search_qradar(state: IOCInvestigationState) -> IOCInvestigationState:
    """Search QRadar for IOC activity (only for high-risk IOCs)."""
    ioc_value = state['ioc_value']
    ioc_type = state['ioc_type']

    try:
        from my_bot.tools.qradar_tools import search_qradar_by_ip, search_qradar_by_domain

        logger.info(f"[IOC Workflow] QRadar search for {ioc_type}: {ioc_value}")

        if ioc_type == "ip":
            result = search_qradar_by_ip.invoke({"ip_address": ioc_value, "hours": 72})
        elif ioc_type == "domain":
            result = search_qradar_by_domain.invoke({"domain": ioc_value, "hours": 72})
        else:
            result = "QRadar search only supports IP addresses and domains"

        state['qradar_result'] = result

        # Add risk factor if events found
        if "No events found" not in result and "Total Events:" in result:
            state['risk_factors'] = state.get('risk_factors', []) + ["QRadar: Activity detected in SIEM logs"]

    except Exception as e:
        logger.error(f"[IOC Workflow] QRadar error: {e}")
        state['errors'] = state.get('errors', []) + [f"QRadar: {str(e)}"]
        state['qradar_result'] = f"Error: {str(e)}"

    return state


def skip_qradar(state: IOCInvestigationState) -> IOCInvestigationState:
    """Skip QRadar search for low-risk IOCs."""
    state['qradar_result'] = "Skipped - IOC risk score below threshold"
    return state


def generate_report(state: IOCInvestigationState) -> IOCInvestigationState:
    """Generate the final investigation report."""
    logger.info("[IOC Workflow] Generating final report")

    ioc_value = state['ioc_value']
    ioc_type = state['ioc_type']
    risk_score = state.get('risk_score', 0)
    # Deduplicate risk factors while preserving order
    risk_factors = list(dict.fromkeys(state.get('risk_factors', [])))
    actions = state.get('recommended_actions', [])
    # Deduplicate errors while preserving order
    errors = list(dict.fromkeys(state.get('errors', [])))

    # Determine risk level label
    if risk_score >= HIGH_RISK_THRESHOLD:
        risk_level = "HIGH"
        risk_emoji = "HIGH"
    elif risk_score >= MEDIUM_RISK_THRESHOLD:
        risk_level = "MEDIUM"
        risk_emoji = "MEDIUM"
    else:
        risk_level = "LOW"
        risk_emoji = "LOW"

    # Build report sections
    report_lines = [
        f"# IOC Investigation Report",
        "",
        f"## Summary",
        f"**IOC:** `{ioc_value}`",
        f"**Type:** {ioc_type.upper()}",
        f"**Risk Score:** {risk_score}/100",
        f"**Risk Level:** {risk_level}",
        "",
    ]

    # Risk factors
    if risk_factors:
        report_lines.append("## Risk Factors")
        for factor in risk_factors:
            report_lines.append(f"- {factor}")
        report_lines.append("")

    # Tool results
    report_lines.append("## Enrichment Results")
    report_lines.append("")

    report_lines.append("### VirusTotal")
    report_lines.append(state.get('virustotal_result', 'No result'))
    report_lines.append("")

    if state['ioc_type'] == 'ip':
        report_lines.append("### AbuseIPDB")
        report_lines.append(state.get('abuseipdb_result', 'No result'))
        report_lines.append("")

    if state['ioc_type'] in ('ip', 'domain'):
        report_lines.append("### Shodan")
        report_lines.append(state.get('shodan_result', 'No result'))
        report_lines.append("")

    report_lines.append("### Recorded Future")
    report_lines.append(state.get('recorded_future_result', 'No result'))
    report_lines.append("")

    qradar_result = state.get('qradar_result', '')
    if qradar_result and "Skipped" not in qradar_result:
        report_lines.append("### QRadar SIEM")
        report_lines.append(qradar_result)
        report_lines.append("")

    # Recommended actions
    report_lines.append("## Recommended Actions")
    for i, action in enumerate(actions, 1):
        report_lines.append(f"{i}. {action}")
    report_lines.append("")

    # Errors (if any)
    if errors:
        report_lines.append("## Errors During Investigation")
        for error in errors:
            report_lines.append(f"- {error}")
        report_lines.append("")

    state['final_report'] = "\n".join(report_lines)

    return state


def build_ioc_investigation_graph() -> StateGraph:
    """Build the IOC investigation LangGraph workflow.

    Workflow is sequential to avoid state merging issues with parallel nodes.
    Order: VT → AbuseIPDB → Shodan → Recorded Future → Risk → QRadar → Report
    """
    graph = StateGraph(IOCInvestigationState)

    # Add nodes
    graph.add_node("detect_type", detect_ioc_type)
    graph.add_node("lookup_virustotal", lookup_virustotal)
    graph.add_node("lookup_abuseipdb", lookup_abuseipdb)
    graph.add_node("lookup_shodan", lookup_shodan)
    graph.add_node("lookup_recorded_future", lookup_recorded_future)
    graph.add_node("synthesize_risk", synthesize_risk)
    graph.add_node("search_qradar", search_qradar)
    graph.add_node("skip_qradar", skip_qradar)
    graph.add_node("generate_report", generate_report)

    # Set entry point
    graph.set_entry_point("detect_type")

    # Sequential enrichment (avoids LangGraph state merge conflicts)
    graph.add_edge("detect_type", "lookup_virustotal")
    graph.add_edge("lookup_virustotal", "lookup_abuseipdb")
    graph.add_edge("lookup_abuseipdb", "lookup_shodan")
    graph.add_edge("lookup_shodan", "lookup_recorded_future")

    # After RF, synthesize risk
    graph.add_edge("lookup_recorded_future", "synthesize_risk")

    # Conditional: QRadar search based on risk
    graph.add_conditional_edges(
        "synthesize_risk",
        should_search_qradar,
        {
            "search_qradar": "search_qradar",
            "skip_qradar": "skip_qradar",
        }
    )

    # After QRadar decision, generate report
    graph.add_edge("search_qradar", "generate_report")
    graph.add_edge("skip_qradar", "generate_report")

    # Report is the end
    graph.add_edge("generate_report", END)

    return graph


# Compile the graph once at module load
_ioc_graph = None


def get_ioc_graph():
    """Get the compiled IOC investigation graph (lazy initialization)."""
    global _ioc_graph
    if _ioc_graph is None:
        _ioc_graph = build_ioc_investigation_graph().compile()
    return _ioc_graph


def run_ioc_investigation(query: str) -> dict:
    """
    Run the IOC investigation workflow.

    Args:
        query: User's query containing the IOC to investigate

    Returns:
        dict with 'content' (the report) and token metrics
    """
    logger.info(f"[IOC Workflow] Starting investigation for query: {query[:100]}")

    # Extract IOC from query
    ioc_value, ioc_type = extract_ioc_from_query(query)

    if not ioc_value or not ioc_type:
        return {
            'content': "Could not identify an IOC (IP address, domain, hash, or URL) in your query. Please include the indicator you want to investigate.",
            'input_tokens': 0,
            'output_tokens': 0,
            'total_tokens': 0,
            'prompt_time': 0.0,
            'generation_time': 0.0,
            'tokens_per_sec': 0.0,
        }

    # Initialize state
    initial_state: IOCInvestigationState = {
        'ioc_value': ioc_value,
        'ioc_type': ioc_type,
        'virustotal_result': None,
        'abuseipdb_result': None,
        'shodan_result': None,
        'recorded_future_result': None,
        'qradar_result': None,
        'risk_score': 0,
        'risk_factors': [],
        'recommended_actions': [],
        'errors': [],
        'final_report': None,
    }

    try:
        import time
        start_time = time.time()

        # Run the graph
        graph = get_ioc_graph()
        final_state = graph.invoke(initial_state)

        elapsed = time.time() - start_time
        logger.info(f"[IOC Workflow] Completed in {elapsed:.1f}s")

        return {
            'content': final_state.get('final_report', 'Investigation completed but no report generated.'),
            'input_tokens': 0,
            'output_tokens': 0,
            'total_tokens': 0,
            'prompt_time': elapsed,
            'generation_time': 0.0,
            'tokens_per_sec': 0.0,
        }

    except Exception as e:
        logger.error(f"[IOC Workflow] Error: {e}", exc_info=True)
        return {
            'content': f"IOC investigation workflow failed: {str(e)}",
            'input_tokens': 0,
            'output_tokens': 0,
            'total_tokens': 0,
            'prompt_time': 0.0,
            'generation_time': 0.0,
            'tokens_per_sec': 0.0,
        }
