"""AttackIQ BAS (Breach and Attack Simulation) tools."""

import logging
from typing import Optional, List

from mcp_server.server import mcp

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        from services.attackiq import AttackIQClient
        _client = AttackIQClient()
    return _client


@mcp.tool(tags={"readonly"})
def attackiq_list_templates() -> dict:
    """List available AttackIQ assessment templates."""
    client = _get_client()
    templates = client.list_templates()
    return {"count": len(templates), "templates": templates}


@mcp.tool(tags={"mutating"})
def attackiq_create_assessment(
    azdo_id: int,
    title: str,
    technique_ids: List[str],
    template_id: Optional[str] = None,
    asset_group_id: Optional[str] = None,
) -> dict:
    """Create an AttackIQ BAS assessment from MITRE ATT&CK techniques.

    Args:
        azdo_id: Azure DevOps work item ID (for tracking)
        title: Assessment name
        technique_ids: List of MITRE technique IDs (e.g. ['T1059.001', 'T1053.005'])
        template_id: Optional assessment template ID
        asset_group_id: Optional target asset group ID
    """
    client = _get_client()
    return client.create_tipper_assessment(
        azdo_id=azdo_id,
        title=title,
        technique_ids=technique_ids,
        template_id=template_id,
        asset_group_id=asset_group_id,
    )


@mcp.tool(tags={"mutating"})
def attackiq_run_assessment(assessment_id: str) -> dict:
    """Execute an AttackIQ assessment.

    Args:
        assessment_id: The assessment ID to run
    """
    client = _get_client()
    return client.run_assessment(assessment_id)


@mcp.tool(tags={"readonly"})
def attackiq_get_results(assessment_id: str) -> dict:
    """Get results for an AttackIQ assessment.

    Args:
        assessment_id: The assessment ID
    """
    client = _get_client()
    results = client.get_results(assessment_id)
    return {"count": len(results), "results": results}
