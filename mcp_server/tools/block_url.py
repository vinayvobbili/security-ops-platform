"""URL blocking tools via XSOAR.

For MCP/Barnacles, confirmation is handled conversationally by Claude —
no Webex card needed. The tool creates the ticket directly.
"""

import logging

from mcp_server.server import mcp

logger = logging.getLogger(__name__)


@mcp.tool(tags={"mutating"})
def block_url(
    url: str,
    reason: str,
    owner: str,
    xsoar_ticket_id: str = "",
) -> dict:
    """Block a malicious URL or domain via XSOAR.

    Creates an XSOAR CIRT Case (or uses an existing ticket) with the
    offending URL and required fields. The analyst should review the ticket
    and close it manually.

    IMPORTANT: This is a destructive action. Confirm with the user before calling
    this tool unless they have already explicitly confirmed they want to block it.

    Args:
        url: URL or domain to block (e.g. 'evil-domain.com' or 'https://phishing.com/path')
        reason: Reason for blocking — used as the audit note in the XSOAR ticket
        owner: Email address of the person requesting the block — set as XSOAR ticket owner
        xsoar_ticket_id: Existing XSOAR ticket ID to use (leave empty to create a new one)
    """
    from services.xsoar.url_block import block_url_via_xsoar

    return block_url_via_xsoar(url, reason, owner, xsoar_ticket_id)
