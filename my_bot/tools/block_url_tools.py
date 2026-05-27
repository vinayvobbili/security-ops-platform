"""
URL Block Tool

Allows threat hunters to request blocking a URL via XSOAR.
The tool sends a confirmation Adaptive Card directly to Webex.
On confirmation, execute_url_block() handles XSOAR ticket creation and script execution.
"""

import logging
import os
import re
import time

from langchain_core.tools import tool
from my_bot.tools._tagging import readonly_tool, mutating_tool

from src.utils.tool_decorator import log_tool_call
from my_config import get_config

FINAL_RESPONSE_PREFIX = "[FINAL_RESPONSE]"  # duplicated from state_manager to avoid circular import

logger = logging.getLogger(__name__)

CONFIG = get_config()


def _get_allowed_rooms() -> list[str]:
    """Return room IDs allowed to use block URL."""
    rooms = []
    for var in ("WEBEX_ROOM_ID_THREATCON_COLLAB", "WEBEX_ROOM_ID_GOSC_T2", "WEBEX_ROOM_ID_DEV_TEST_SPACE"):
        val = os.environ.get(var)
        if val:
            rooms.append(val)
    return rooms


def _get_current_room_id() -> str | None:
    """Extract room_id from thread-local logging context."""
    from src.utils.tool_logging import get_logging_context
    session_id = get_logging_context()
    if session_id and "_" in session_id:
        parts = session_id.split("_", 1)
        return parts[1] if len(parts) > 1 else None
    return None


@mutating_tool
@log_tool_call
def request_url_block(url: str) -> str:
    """Request blocking a URL/domain via XSOAR.

    Use this tool when a threat hunter or analyst asks to block a URL or domain.
    This sends a confirmation card — the actual block happens after the user confirms.

    Args:
        url: The URL or domain to block (e.g., 'evil-domain.com' or 'https://evil-domain.com/path')

    Returns:
        Confirmation message
    """
    # Check room authorization
    room_id = _get_current_room_id()
    allowed = _get_allowed_rooms()
    if allowed and (not room_id or room_id not in allowed):
        logger.warning(f"Block URL tool blocked - unauthorized room: {room_id}")
        return FINAL_RESPONSE_PREFIX + "This command is only available in authorized rooms (Threat Con, GOSC T2, or Test Dev Space)."

    # Strip http(s):// prefix — XSOAR stores domain only
    clean_url = re.sub(r'^https?://', '', url.strip())

    # Send confirmation card directly to Webex
    try:
        from webexpythonsdk import WebexAPI
        from webex_bots.cards.block_url_cards import build_block_url_card

        webex_api = WebexAPI(access_token=CONFIG.webex_bot_access_token_pokedex)
        card = build_block_url_card(clean_url)
        webex_api.messages.create(
            roomId=room_id,
            text=f"URL Block Request: {clean_url}",
            attachments=[{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": card,
            }],
        )
        logger.info(f"Sent block URL confirmation card for {clean_url} in room {room_id}")
        return FINAL_RESPONSE_PREFIX + f"🚫 Confirmation card sent for blocking `{clean_url}`. Please confirm via the card."

    except Exception as e:
        logger.error(f"Failed to send block URL card: {e}", exc_info=True)
        return FINAL_RESPONSE_PREFIX + f"❌ Failed to send confirmation card: {e}"


def execute_url_block(room_id: str, url: str, xsoar_ticket_id: str, reason: str,
                      user_email: str, parent_msg_id: str,
                      bot_access_token: str | None = None):
    """Execute the URL block after user confirms via Adaptive Card.

    Called from the bot's card action handler. Handles XSOAR ticket creation,
    script execution, audit note, and Webex confirmation.

    Args:
        room_id: Webex room ID
        url: Domain to block
        xsoar_ticket_id: Existing ticket ID (empty string to create new)
        reason: Reason for blocking the URL
        user_email: Email of the requester
        parent_msg_id: Message ID to delete (the triggering card); empty to skip
        bot_access_token: Webex bot access token (defaults to Pokedex's token)
    """
    from webexpythonsdk import WebexAPI
    from services.xsoar.ticket_handler import TicketHandler
    from src.utils.xsoar_enums import XsoarEnvironment

    token = bot_access_token or CONFIG.webex_bot_access_token_pokedex
    webex_api = WebexAPI(access_token=token)

    # Delete the confirmation card to prevent accidental re-clicks
    if parent_msg_id:
        try:
            webex_api.messages.delete(parent_msg_id)
            logger.info(f"Deleted block URL confirmation card {parent_msg_id}")
        except Exception as e:
            logger.warning(f"Failed to delete confirmation card: {e}")

    try:
        handler = TicketHandler(environment=XsoarEnvironment.PROD)

        # Create or use existing XSOAR ticket
        if xsoar_ticket_id:
            ticket_id = xsoar_ticket_id
            logger.info(f"Using existing XSOAR ticket {ticket_id} for URL block: {url}")
            handler.assign_owner(ticket_id, user_email)
        else:
            payload = {
                'name': f'URL Block - {url}',
                'owner': user_email,
                'CustomFields': {
                    'url': url,
                    'offendingurl': url,
                    'securitycategory': 'CAT-5: Scans/Probes/Attempted Access',
                },
            }
            result = handler.create(payload)
            ticket_id = str(result.get('id', ''))
            logger.info(f"Created XSOAR ticket {ticket_id} for URL block: {url}")

        # Wait for XSOAR to finish processing the ticket
        time.sleep(10)

        # Complete the acknowledgement task so the playbook can proceed
        handler.complete_task(ticket_id, "Acknowledge Ticket", "Yes")
        logger.info(f"Completed acknowledgement task in ticket {ticket_id}")

        # Execute the URL block script in the ticket's war room
        handler.execute_command_in_war_room(ticket_id, f'!CIRT_Start_URL_Block Reason="{reason}"')
        logger.info(f"Executed !CIRT_Start_URL_Block in ticket {ticket_id}")

        # Add audit note
        audit_note = f"URL block requested by {user_email}\nReason: {reason}"
        handler.create_new_entry_in_existing_ticket(ticket_id, audit_note)

        # Send confirmation to Webex
        ticket_link = f"[{ticket_id}]({CONFIG.xsoar_prod_ui_base_url}/Custom/caseinfoid/{ticket_id})"
        confirm_msg = (
            f"✅ **URL Block Initiated**\n\n"
            f"- **URL:** `{url}`\n"
            f"- **XSOAR Ticket:** {ticket_link}\n"
            f"- **Reason:** {reason}\n"
            f"- **Requested by:** {user_email}\n"
            f"- `!CIRT_Start_URL_Block` executed in war room\n"
            f"- Please review the ticket and close it."
        )
        webex_api.messages.create(
            roomId=room_id,
            markdown=confirm_msg,
        )

    except Exception as e:
        logger.error(f"URL block failed for {url}: {e}", exc_info=True)
        webex_api.messages.create(
            roomId=room_id,
            markdown=f"❌ **URL Block Failed**\n\n`{url}` — {e}",
        )
