"""Command handlers for XSOAR Sentinel triage card actions.

Handles button clicks from XSOAR triage adaptive cards:
- Close Ticket: close as FP in XSOAR + record outcome
- Escalate: add war room note + bump severity + record outcome
- Add Note: return XSOAR link for manual note entry
- Investigate: return direct XSOAR incident link
"""

import logging
from webex_bot.models.command import Command

logger = logging.getLogger(__name__)


def _get_ticket_handler():
    """Lazy-load XSOAR TicketHandler for prod."""
    from services.xsoar.ticket_handler import TicketHandler
    from src.utils.xsoar_enums import XsoarEnvironment
    return TicketHandler(XsoarEnvironment.PROD)


class XsoarCloseCommand(Command):
    """Close XSOAR ticket as false positive."""

    def __init__(self):
        super().__init__(command_keyword="sentinel_xsoar_close", help_message="", card=None)

    def execute(self, message, attachment_actions, activity):
        inputs = attachment_actions.inputs if attachment_actions else {}
        alert_id = inputs.get("alert_id", "")
        xsoar_ticket_id = inputs.get("xsoar_ticket_id", "")
        analyst_email = getattr(attachment_actions, "personEmail", "")
        suggested_reason = inputs.get("suggested_close_reason", "")

        # Use suggested close reason from AI triage if available, fallback to FP
        close_reason = suggested_reason if suggested_reason else "Resolved - FP"
        close_label = close_reason if close_reason != "Resolved - FP" else "false positive"

        logger.info(f"[Sentinel XSOAR] Close ticket: alert={alert_id}, ticket={xsoar_ticket_id}, reason={close_reason}")

        try:
            handler = _get_ticket_handler()
            handler.update_incident(xsoar_ticket_id, {
                "closeReason": close_reason,
                "closeNotes": f"Closed as {close_label} via Sentinel AI triage by {analyst_email}",
                "status": 2,  # XSOAR closed status
            })
            return f"XSOAR ticket **#{xsoar_ticket_id}** closed as **{close_label}**."
        except Exception as e:
            logger.error(f"XSOAR close failed: {e}", exc_info=True)
            return f"XSOAR API error: {e}"


class XsoarEscalateCommand(Command):
    """Escalate XSOAR ticket — add war room note and bump severity."""

    def __init__(self):
        super().__init__(command_keyword="sentinel_xsoar_escalate", help_message="", card=None)

    def execute(self, message, attachment_actions, activity):
        inputs = attachment_actions.inputs if attachment_actions else {}
        alert_id = inputs.get("alert_id", "")
        xsoar_ticket_id = inputs.get("xsoar_ticket_id", "")
        analyst_email = getattr(attachment_actions, "personEmail", "")

        logger.info(f"[Sentinel XSOAR] Escalate: alert={alert_id}, ticket={xsoar_ticket_id}")

        try:
            handler = _get_ticket_handler()

            # Add war room note
            handler.create_new_entry_in_existing_ticket(
                xsoar_ticket_id,
                f"**Escalated via Sentinel AI Triage** by {analyst_email}",
            )

            # Bump severity to High (3) if not already Critical
            handler.update_incident(xsoar_ticket_id, {"severity": 3})

            return f"XSOAR ticket **#{xsoar_ticket_id}** escalated (severity bumped, war room note added)."
        except Exception as e:
            logger.error(f"XSOAR escalate failed: {e}", exc_info=True)
            return f"XSOAR API error: {e}"


class XsoarAddNoteCommand(Command):
    """Add note — returns XSOAR link for manual note entry."""

    def __init__(self):
        super().__init__(command_keyword="sentinel_xsoar_note", help_message="", card=None)

    def execute(self, message, attachment_actions, activity):
        inputs = attachment_actions.inputs if attachment_actions else {}
        xsoar_ticket_id = inputs.get("xsoar_ticket_id", "")

        from src.utils.xsoar_helpers import build_incident_url
        url = build_incident_url(xsoar_ticket_id)
        return f"Open ticket in XSOAR to add notes: [#{xsoar_ticket_id}]({url})"


class XsoarInvestigateCommand(Command):
    """Investigate — returns direct XSOAR incident link."""

    def __init__(self):
        super().__init__(command_keyword="sentinel_xsoar_investigate", help_message="", card=None)

    def execute(self, message, attachment_actions, activity):
        inputs = attachment_actions.inputs if attachment_actions else {}
        xsoar_ticket_id = inputs.get("xsoar_ticket_id", "")
        xsoar_url = inputs.get("xsoar_url", "")

        if not xsoar_url:
            from src.utils.xsoar_helpers import build_incident_url
            xsoar_url = build_incident_url(xsoar_ticket_id)

        return f"Investigate in XSOAR: [#{xsoar_ticket_id}]({xsoar_url})"
