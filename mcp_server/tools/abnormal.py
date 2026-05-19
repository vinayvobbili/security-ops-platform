"""Abnormal Security email security tools."""

import logging
from typing import Optional

from mcp_server.server import mcp

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        from services.abnormal_security import AbnormalSecurityClient
        _client = AbnormalSecurityClient()
    return _client


@mcp.tool(tags={"readonly"})
def abnormal_get_threats(
    filter_param: Optional[str] = None,
    page_size: int = 100,
    page_number: int = 1,
    source: str = "all",
) -> dict:
    """List email threats detected by Abnormal Security.

    Args:
        filter_param: Optional filter expression
        page_size: Results per page
        page_number: Page number
        source: Threat source filter ('all', 'advanced', 'attacks', 'borderline', 'spam')
    """
    client = _get_client()
    return client.get_threats(
        filter_param=filter_param,
        page_size=page_size,
        page_number=page_number,
        source=source,
    )


@mcp.tool(tags={"readonly"})
def abnormal_get_threat_details(
    threat_id: str, page_size: int = 100, page_number: int = 1
) -> dict:
    """Get detailed information about a specific Abnormal Security threat.

    Args:
        threat_id: The threat ID
        page_size: Results per page for messages
        page_number: Page number
    """
    client = _get_client()
    return client.get_threat_details(
        threat_id, page_size=page_size, page_number=page_number
    )


@mcp.tool(tags={"readonly"})
def abnormal_get_cases(
    filter_param: Optional[str] = None,
    page_size: int = 100,
    page_number: int = 1,
) -> dict:
    """List Abnormal Security cases.

    Args:
        filter_param: Optional filter expression
        page_size: Results per page
        page_number: Page number
    """
    client = _get_client()
    return client.get_cases(
        filter_param=filter_param, page_size=page_size, page_number=page_number
    )


@mcp.tool(tags={"readonly"})
def abnormal_get_employee_info(email_address: str) -> dict:
    """Get employee information from Abnormal Security.

    Args:
        email_address: Employee email address
    """
    client = _get_client()
    return client.get_employee_information(email_address)


@mcp.tool(tags={"readonly"})
def abnormal_get_threat_intel() -> dict:
    """Get the Abnormal Security threat intelligence feed."""
    client = _get_client()
    return client.get_threat_intel_feed()
