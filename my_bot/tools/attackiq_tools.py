"""AttackIQ Breach and Attack Simulation (BAS) tools."""

import logging
from typing import List, Optional

from langchain_core.tools import tool

from src.utils.tool_decorator import log_tool_call

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        from services.attackiq import AttackIQClient
        _client = AttackIQClient()
    return _client


@tool
@log_tool_call
def attackiq_list_templates() -> str:
    """List available AttackIQ BAS assessment templates.

    Returns the names and IDs of all assessment templates configured in AttackIQ.
    Use before creating a new assessment to find the right template.
    """
    try:
        client = _get_client()
        templates = client.list_templates()
        if not templates:
            return "No AttackIQ templates found."
        lines = [f"- {t.get('name', 'Unknown')} (ID: {t.get('id', 'N/A')})" for t in templates]
        return f"AttackIQ Assessment Templates ({len(templates)}):\n" + "\n".join(lines)
    except Exception as e:
        logger.error(f"AttackIQ list_templates failed: {e}")
        return f"Error listing AttackIQ templates: {e}"


@tool
@log_tool_call
def attackiq_create_assessment(
    azdo_id: int,
    title: str,
    technique_ids: str,
    template_id: str = "",
    asset_group_id: str = "",
) -> str:
    """Create an AttackIQ BAS assessment from MITRE ATT&CK technique IDs.

    Use this to set up a breach and attack simulation from threat tipper data.
    Maps MITRE technique IDs to AttackIQ scenarios and creates the assessment.

    Args:
        azdo_id: Azure DevOps work item ID for tracking (e.g. 12345)
        title: Assessment name
        technique_ids: Comma-separated MITRE technique IDs (e.g. 'T1059.001,T1053.005')
        template_id: Optional template ID (use attackiq_list_templates to find one)
        asset_group_id: Optional target asset group ID
    """
    try:
        client = _get_client()
        tech_list = [t.strip() for t in technique_ids.split(",") if t.strip()]
        result = client.create_tipper_assessment(
            azdo_id=azdo_id,
            title=title,
            technique_ids=tech_list,
            template_id=template_id or None,
            asset_group_id=asset_group_id or None,
        )
        assessment_id = result.get("id", "unknown")
        return f"AttackIQ assessment created: ID={assessment_id}, Title='{title}', Techniques={tech_list}"
    except Exception as e:
        logger.error(f"AttackIQ create_assessment failed: {e}")
        return f"Error creating AttackIQ assessment: {e}"


@tool
@log_tool_call
def attackiq_run_assessment(assessment_id: str) -> str:
    """Execute an AttackIQ BAS assessment.

    Triggers the assessment to run against the configured asset group.
    Results may take several minutes to populate.

    Args:
        assessment_id: The assessment ID to run
    """
    try:
        client = _get_client()
        result = client.run_assessment(assessment_id)
        return f"AttackIQ assessment {assessment_id} started: {result}"
    except Exception as e:
        logger.error(f"AttackIQ run_assessment failed: {e}")
        return f"Error running AttackIQ assessment {assessment_id}: {e}"


@tool
@log_tool_call
def attackiq_get_results(assessment_id: str) -> str:
    """Get results for a completed AttackIQ BAS assessment.

    Returns pass/fail status for each simulated attack technique,
    including which scenarios succeeded (evaded defenses) and which were blocked.

    Args:
        assessment_id: The assessment ID to retrieve results for
    """
    try:
        client = _get_client()
        results = client.get_results(assessment_id)
        if not results:
            return f"No results available yet for assessment {assessment_id}. Assessment may still be running."
        lines = []
        for r in results:
            status = r.get("result_status", "unknown")
            name = r.get("scenario_name", r.get("name", "Unknown scenario"))
            lines.append(f"- [{status.upper()}] {name}")
        return f"AttackIQ Assessment {assessment_id} Results ({len(results)}):\n" + "\n".join(lines)
    except Exception as e:
        logger.error(f"AttackIQ get_results failed: {e}")
        return f"Error getting AttackIQ results for {assessment_id}: {e}"
