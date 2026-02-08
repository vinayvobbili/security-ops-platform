"""
Remediation Suggestion Tools Module

Tools for suggesting incident remediation actions based on XSOAR ticket
details and local runbook/playbook documentation (team guides).
"""

import logging
from typing import Dict, Any, List
from langchain_core.tools import tool

from src.utils.tool_decorator import log_tool_call
from services.xsoar.ticket_handler import TicketHandler
from src.utils.xsoar_enums import XsoarEnvironment

logger = logging.getLogger(__name__)


def _extract_incident_context(ticket_data: Dict[str, Any]) -> Dict[str, str]:
    """
    Extract key incident attributes for playbook matching.

    Args:
        ticket_data: Raw ticket data from XSOAR

    Returns:
        Dictionary with normalized incident context
    """
    custom_fields = ticket_data.get('CustomFields', {})

    return {
        "ticket_id": str(ticket_data.get('id', 'Unknown')),
        "title": ticket_data.get('name', ''),
        "severity": str(ticket_data.get('severity', 'Unknown')),
        "status": ticket_data.get('status', 'Unknown'),
        "security_category": custom_fields.get('securitycategory', ''),
        "detection_source": custom_fields.get('detectionsource', ''),
        "hostname": custom_fields.get('hostname', ''),
        "username": custom_fields.get('username', ''),
        "close_reason": ticket_data.get('closeReason', ''),
        "close_notes": ticket_data.get('closeNotes', ''),
    }


def _build_search_queries(context: Dict[str, str]) -> List[str]:
    """
    Generate search queries to find relevant playbooks.

    Creates multiple queries based on incident attributes to maximize
    the chance of finding relevant team documentation.

    Args:
        context: Incident context dictionary

    Returns:
        List of search queries ordered by specificity
    """
    queries = []

    # Primary: search by security category (most specific)
    if context["security_category"]:
        category = context["security_category"].lower()
        queries.append(f"{category} remediation response actions")
        queries.append(f"{category} incident handling steps")

    # Secondary: search by detection source
    if context["detection_source"]:
        source = context["detection_source"].lower()
        queries.append(f"{source} detection response remediation")

    # Tertiary: extract keywords from title
    if context["title"]:
        # Common incident type keywords to look for
        title_lower = context["title"].lower()
        keywords = ["phishing", "malware", "ransomware", "brute force", "lateral movement",
                    "credential", "privilege escalation", "data exfiltration", "c2", "command and control",
                    "unauthorized access", "suspicious", "anomaly", "vulnerability", "exploit"]
        for keyword in keywords:
            if keyword in title_lower:
                queries.append(f"{keyword} remediation steps")
                break

        # Also search with the full title
        queries.append(f"{context['title']} remediation")

    # Fallback queries
    if not queries:
        queries.append("incident response remediation steps")
        queries.append("security incident handling procedure")

    return queries[:5]  # Limit to 5 queries to avoid over-searching


def _search_playbooks(queries: List[str]) -> str:
    """
    Search local documents for relevant playbook content.

    Uses the existing document processor's hybrid retriever (65% semantic + 35% BM25)
    to find relevant team runbook content.

    Args:
        queries: List of search queries

    Returns:
        Formatted string with relevant playbook excerpts
    """
    from my_bot.core.state_manager import get_state_manager

    state_manager = get_state_manager()
    if not state_manager or not state_manager.document_processor:
        logger.warning("Document processor not available for playbook search")
        return ""

    retriever = state_manager.document_processor.retriever
    if not retriever:
        logger.warning("Retriever not initialized for playbook search")
        return ""

    all_docs = []
    seen_content = set()

    for query in queries:
        try:
            docs = retriever.invoke(query)
            for doc in docs:
                # Dedupe by content hash (first 300 chars)
                content_hash = hash(doc.page_content[:300])
                if content_hash not in seen_content:
                    seen_content.add(content_hash)
                    all_docs.append(doc)
        except Exception as e:
            logger.warning(f"Playbook search failed for query '{query}': {e}")

    if not all_docs:
        return "No relevant playbooks found in local documentation."

    # Format results with source attribution
    results = []
    for doc in all_docs[:8]:  # Top 8 chunks for comprehensive coverage
        source = doc.metadata.get('source', 'Unknown')
        source_name = source.split('/')[-1] if '/' in source else source
        results.append(f"[Source: {source_name}]\n{doc.page_content.strip()}")

    return "\n\n---\n\n".join(results)


def _generate_remediation_with_llm(context: Dict[str, str], playbook_content: str) -> str:
    """
    Use LLM to synthesize remediation steps from incident context and playbooks.

    Args:
        context: Incident context dictionary
        playbook_content: Retrieved playbook excerpts

    Returns:
        Formatted remediation guidance
    """
    from my_bot.core.state_manager import get_state_manager

    state_manager = get_state_manager()
    if not state_manager or not state_manager.is_initialized:
        return "Error: LLM not initialized. Cannot generate remediation suggestions."

    # Use higher temperature for more natural remediation prose
    remediation_llm = state_manager.get_llm_with_temperature(0.4)
    if not remediation_llm:
        remediation_llm = state_manager.llm  # Fallback to default

    # Build context section
    context_section = f"""INCIDENT DETAILS:
- Ticket ID: #{context['ticket_id']}
- Title: {context['title']}
- Severity: {context['severity']}
- Status: {context['status']}
- Security Category: {context['security_category'] or 'Not specified'}
- Detection Source: {context['detection_source'] or 'Not specified'}
- Affected Host: {context['hostname'] or 'Not specified'}
- Affected User: {context['username'] or 'Not specified'}"""

    prompt = f"""You are a SOC analyst assistant providing remediation guidance. Based on the incident details and relevant playbook excerpts below, provide specific, actionable remediation steps.

{context_section}

RELEVANT PLAYBOOK/RUNBOOK EXCERPTS:
{playbook_content if playbook_content else "No specific playbooks found for this incident type."}

---

Provide remediation guidance following this EXACT format:

**Immediate Actions** (do first):
1. [Specific containment action]
2. [Specific containment action]
(List 2-4 critical first-response actions)

**Investigation Steps**:
1. [What to check/verify]
2. [What to check/verify]
(List 3-5 investigation steps)

**Containment & Eradication**:
1. [How to contain the threat]
2. [How to remove/remediate]
(List 2-4 containment/eradication steps)

**Recovery**:
1. [How to restore normal operations]
2. [Verification steps]
(List 1-3 recovery steps)

**Escalation Criteria**:
• [When to escalate to Tier 2/3]
• [Red flags that require immediate escalation]

IMPORTANT GUIDELINES:
- Be SPECIFIC to THIS incident based on the details provided
- Reference the playbook guidance where applicable (cite source names)
- If playbooks don't cover this scenario fully, supplement with security best practices and note this
- Use imperative language (e.g., "Disable the account" not "You should disable")
- Include specific tool/system names where relevant (CrowdStrike, XSOAR, etc.)
"""

    try:
        response = remediation_llm.invoke(prompt)
        return response.content if hasattr(response, 'content') else str(response)
    except Exception as e:
        logger.error(f"LLM remediation generation failed: {e}")
        return f"Error generating remediation guidance: {str(e)}"


@tool
@log_tool_call
def suggest_remediation(ticket_id: str, environment: str = "prod") -> str:
    """
    Suggest remediation actions for an XSOAR ticket based on local playbooks/runbooks.

    Use this tool when users ask how to remediate or respond to an XSOAR ticket/case/incident.

    Examples:
    - "How do I remediate XSOAR ticket 929947?"
    - "What are the remediation steps for XSOAR case 123456?"
    - "Suggest response actions for XSOAR incident 456789"

    This tool fetches XSOAR incident details and searches team runbooks to provide
    tailored remediation guidance.

    Args:
        ticket_id: The XSOAR ticket/case/incident ID (numeric, e.g., "929947")
        environment: XSOAR environment - "prod" (default) or "dev"

    Returns:
        Tailored remediation guidance based on incident type and local playbooks
    """
    try:
        # Normalize ticket ID - strip "X#" prefix if present
        ticket_id = ticket_id.strip()
        if ticket_id.upper().startswith("X#"):
            ticket_id = ticket_id[2:]

        # Validate environment
        if environment.lower() == "prod":
            xsoar_env = XsoarEnvironment.PROD
        elif environment.lower() == "dev":
            xsoar_env = XsoarEnvironment.DEV
        else:
            return f"Error: Invalid environment '{environment}'. Must be 'prod' or 'dev'."

        # 1. Fetch ticket details
        logger.info(f"Fetching ticket {ticket_id} for remediation suggestions...")
        ticket_handler = TicketHandler(environment=xsoar_env)
        ticket_data = ticket_handler.get_case_data(ticket_id)

        if not ticket_data:
            return f"Error: Could not fetch ticket {ticket_id}. Please verify the ticket ID exists in {environment} environment."

        # 2. Extract incident context
        context = _extract_incident_context(ticket_data)
        logger.info(f"Incident context: category={context['security_category']}, source={context['detection_source']}")

        # 3. Build search queries and find relevant playbooks
        queries = _build_search_queries(context)
        logger.info(f"Searching playbooks with {len(queries)} queries: {queries}")
        playbook_content = _search_playbooks(queries)

        # 4. Generate remediation guidance with LLM
        logger.info("Generating remediation suggestions with LLM...")
        remediation = _generate_remediation_with_llm(context, playbook_content)

        # 5. Format final response
        result = f"**Remediation Guidance for Ticket #{ticket_id}**\n"
        result += f"*{context['title']}*\n"
        result += f"Category: {context['security_category'] or 'N/A'} | Severity: {context['severity']} | Status: {context['status']}\n\n"
        result += remediation

        logger.info(f"Successfully generated remediation guidance for ticket {ticket_id}")
        return result

    except Exception as e:
        logger.error(f"Error suggesting remediation for {ticket_id}: {e}", exc_info=True)
        return f"Error generating remediation suggestions: {str(e)}\n\nPlease verify:\n- Ticket ID is correct\n- You have access to the XSOAR environment\n- Network connectivity is available"


# =============================================================================
# SAMPLE PROMPTS FOR LLM GUIDANCE
# =============================================================================
# Use these prompts to help users discover remediation capabilities:
#
# - "How do I remediate XSOAR ticket 123456?"
# - "Suggest remediation steps for XSOAR case 929947"
# - "What are the response actions for ticket 456789?"
# - "How should I handle XSOAR incident 789012?"
# - "Give me remediation guidance for X#123456"
# - "What playbook applies to XSOAR ticket 929947?"
# =============================================================================
