"""
Stale Containment Cleanup Component

Verifies that all contained hosts have open tickets.
If a ticket is closed, updates both the Contained Hosts and Contained Hosts History lists
as if the host was uncontained.

This handles cases where hosts were uncontained directly in CrowdStrike
without going through XSOAR.
"""
import logging
from datetime import datetime

import pytz

from my_config import get_config
from services.xsoar import ListHandler, TicketHandler, XsoarEnvironment

logger = logging.getLogger(__name__)

CONFIG = get_config()
prod_list_handler = ListHandler(XsoarEnvironment.PROD)


def cleanup_stale_containments():
    """
    Verify that all contained hosts have open tickets.
    If a ticket is closed, update both the Contained Hosts and Contained Hosts History lists
    as if the host was uncontained.
    """
    try:
        contained_hosts_list_name = f'{CONFIG.team_name} Contained Hosts'
        history_list_name = f'{CONFIG.team_name} Contained Hosts History'
        timezone = pytz.timezone('US/Eastern')

        # Get current contained hosts
        contained_hosts = prod_list_handler.get_list_data_by_name(contained_hosts_list_name)
        if not contained_hosts:
            logger.info("No hosts in containment list - nothing to verify")
            return

        logger.info(f"Verifying {len(contained_hosts)} contained host(s) against ticket status...")

        # Create ticket handler to check ticket status
        ticket_handler = TicketHandler(XsoarEnvironment.PROD)

        # Track hosts to remove (those with closed tickets)
        hosts_to_remove = []

        for host in contained_hosts:
            ticket_id = host.get('ticket#')
            hostname = host.get('hostname', 'Unknown')

            if not ticket_id:
                logger.warning(f"Host {hostname} has no ticket# - skipping")
                continue

            try:
                # Fetch ticket data to check status
                ticket_data = ticket_handler.get_case_data(ticket_id)
                # Status 2 = Closed in XSOAR
                if ticket_data and ticket_data.get('status') == 2:
                    logger.info(f"Ticket {ticket_id} is closed but host {hostname} is still in containment list. Marking for cleanup...")
                    hosts_to_remove.append(host)
                else:
                    logger.debug(f"Ticket {ticket_id} for host {hostname} is still open (status: {ticket_data.get('status') if ticket_data else 'N/A'})")
            except Exception as e:
                logger.warning(f"Could not verify ticket {ticket_id} for host {hostname}: {e}")
                continue

        if not hosts_to_remove:
            logger.info("No stale containment entries found - all tickets are still open")
            return

        logger.info(f"Found {len(hosts_to_remove)} stale containment entry(ies) to clean up")

        # Update the contained hosts list - remove stale entries
        updated_contained_hosts = [
            h for h in contained_hosts
            if not any(
                h.get('hostname') == remove_host.get('hostname') and
                h.get('ticket#') == remove_host.get('ticket#')
                for remove_host in hosts_to_remove
            )
        ]

        # Update history list for each removed host
        history_data = prod_list_handler.get_list_data_by_name(history_list_name)
        if history_data:
            for host in hosts_to_remove:
                hostname = host.get('hostname')
                ticket_id = host.get('ticket#')
                for entry in history_data:
                    if entry.get('hostname') == hostname and entry.get('ticket#') == ticket_id:
                        # Only update if not already marked as uncontained
                        if not entry.get('uncontained_at'):
                            entry.update({
                                "uncontained_at": datetime.now(timezone).strftime("%m/%d/%Y %I:%M:%S %p %Z"),
                                "uncontained_by": "System (Auto-cleanup)",
                                "uncontainment_reason": "Ticket closed without marking the host as uncontained"
                            })
                            logger.info(f"Updated history for host {hostname} (ticket {ticket_id})")

            # Save updated history
            prod_list_handler.save(history_list_name, history_data)

        # Save updated contained hosts list
        prod_list_handler.save(contained_hosts_list_name, updated_contained_hosts)
        logger.info(f"Successfully cleaned up {len(hosts_to_remove)} stale containment entry(ies)")

    except Exception as e:
        logger.error(f"Error in cleanup_stale_containments: {e}")
        import traceback
        traceback.print_exc()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    cleanup_stale_containments()
