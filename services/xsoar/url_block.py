"""Core URL/domain block flow via XSOAR.

A single plain implementation of the CIRT URL-block flow (create case →
acknowledge → fire ``!CIRT_Start_URL_Block`` → audit note), shared by the
MCP tool, the Webex bot card handler, and the Domain Monitoring web route so
the logic lives in exactly one place.

This module has no MCP or Webex dependencies — callers that need those layers
(confirmation cards, room notifications) wrap this.
"""

import logging
import re
import time

logger = logging.getLogger(__name__)


def clean_url(url: str) -> str:
    """Strip protocol prefix and trailing path — XSOAR stores the host only."""
    url = re.sub(r'^https?://', '', (url or '').strip())
    return url.split('/')[0]


def block_url_via_xsoar(
    url: str,
    reason: str,
    owner: str,
    xsoar_ticket_id: str = "",
) -> dict:
    """Block a malicious URL/domain via XSOAR (PROD tenant).

    Creates a CIRT Case (or reuses ``xsoar_ticket_id``), completes the
    acknowledgement task, executes ``!CIRT_Start_URL_Block`` in the war room,
    and adds an audit note. Returns
    ``{success, url, ticket_id, message}`` on success, or
    ``{success: False, url, error}`` on failure.

    The TicketHandler is pinned to the PROD XSOAR tenant, so this always acts on
    production — callers running off-prod must gate before invoking.
    """
    from services.xsoar.ticket_handler import TicketHandler
    from src.utils.xsoar_enums import XsoarEnvironment

    clean = clean_url(url)
    handler = TicketHandler(environment=XsoarEnvironment.PROD)

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
        handler.execute_command_in_war_room(ticket_id, f'!CIRT_Start_URL_Block Reason="{reason}"')
        logger.info(f"Executed !CIRT_Start_URL_Block in ticket {ticket_id}")

        # Add audit note
        handler.create_new_entry_in_existing_ticket(
            ticket_id,
            f"URL block requested by {owner}\nReason: {reason}",
        )

        return {
            "success": True,
            "url": clean,
            "ticket_id": ticket_id,
            "message": (
                f"XSOAR ticket #{ticket_id} has been created for this URL block "
                f"(`{clean}`) and `!CIRT_Start_URL_Block` executed. "
                f"Please review the ticket and close it."
            ),
        }

    except Exception as e:
        logger.error(f"URL block failed for {clean}: {e}", exc_info=True)
        return {"success": False, "url": clean, "error": str(e)}
