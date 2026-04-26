"""URL blocking tools via XSOAR.

For MCP/the alert triage service, confirmation is handled conversationally by Claude —
no Webex card needed. The tool creates the ticket directly.
"""

import logging
import re
import time

from mcp_server.server import mcp

logger = logging.getLogger(__name__)


def _clean_url(url: str) -> str:
    """Strip protocol prefix and trailing paths — XSOAR stores domain only."""
    url = re.sub(r'^https?://', '', url.strip())
    url = url.split('/')[0]
    return url


@mcp.tool()
def block_url(
    url: str,
    reason: str,
    owner: str,
    xsoar_ticket_id: str = "",
) -> dict:
    """Block a malicious URL or domain via XSOAR.

    Creates an XSOAR METCIRT Case (or uses an existing ticket) with the
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
    from services.xsoar.ticket_handler import TicketHandler
    from src.utils.xsoar_enums import XsoarEnvironment

    clean = _clean_url(url)
    handler = TicketHandler(environment=XsoarEnvironment.DEV)

    try:
        if xsoar_ticket_id:
            ticket_id = str(xsoar_ticket_id).strip()
            logger.info(f"Using existing XSOAR ticket {ticket_id} for URL block: {clean}")
            handler.assign_owner(ticket_id, owner)
        else:
            payload = {
                'name': f'URL Block - {clean}',
                'owner': owner,
                'CustomFields': {
                    'url': clean,
                    'offendingurl': clean,
                    'securitycategory': 'CAT-5: Scans/Probes/Attempted Access',
                },
            }
            result = handler.create(payload)
            ticket_id = str(result.get('id', ''))
            logger.info(f"Created XSOAR ticket {ticket_id} for URL block: {clean}")

        # Wait for XSOAR to finish processing the ticket
        time.sleep(10)

        # Complete the acknowledgement task so the playbook can proceed
        handler.complete_task(ticket_id, "Acknowledge Ticket", "Yes")
        logger.info(f"Completed acknowledgement task in ticket {ticket_id}")

        # Execute the URL block script in the ticket's war room
        handler.execute_command_in_war_room(ticket_id, f'!METCIRT_Start_URL_Block Reason="{reason}"')
        logger.info(f"Executed !METCIRT_Start_URL_Block in ticket {ticket_id}")

        # Add audit note
        handler.create_new_entry_in_existing_ticket(
            ticket_id,
            f"URL block requested by {owner}\nReason: {reason}",
        )

        return {
            "success": True,
            "url": clean,
            "ticket_id": ticket_id,
            "message": f"XSOAR ticket #{ticket_id} has been created for this URL block (`{clean}`) and `!METCIRT_Start_URL_Block` executed. Please review the ticket and close it.",
        }

    except Exception as e:
        logger.error(f"URL block failed for {clean}: {e}", exc_info=True)
        return {"success": False, "url": clean, "error": str(e)}
