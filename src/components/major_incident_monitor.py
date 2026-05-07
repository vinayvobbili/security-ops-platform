"""
Monitor ServiceNow for new Major Incidents assigned to configured groups.

Polls ServiceNow every 15 minutes for incidents assigned to groups defined in
data/transient/secOps/assignment_groups.json and sends notifications to Webex.

Detection model: catch *new MIM assignments*, not new INC creations. SNOW
returns up to 100 incidents per group; we dedupe against a per-group seen-ID
set so each INC alerts exactly once when it enters the group's result window.
No createdDate filter — an incident assigned days after creation must still
trigger an alert.
"""

import json
import logging
from pathlib import Path

from webexpythonsdk import WebexAPI
from webexpythonsdk.models.cards import (
    AdaptiveCard, TextBlock, ColumnSet, Column, FactSet, Fact, Container,
    ActionSet, options
)
from webexpythonsdk.models.cards.actions import OpenUrl

from my_config import get_config
from services.service_now import ServiceNowClient
from src.utils.webex_utils import send_card_with_retry, send_message_with_retry

logger = logging.getLogger(__name__)

CONFIG_FILE = Path(__file__).parent.parent.parent / "data/transient/secOps/assignment_groups.json"
_SEEN_IDS_FILE = Path(__file__).parent.parent.parent / "data/transient/secOps/mim_seen_ids.json"

# Terminal states — closed tickets that resurface in SNOW's 100-result window
# (because someone touched them) are not new MIM assignments. Filter them out
# before the diff so they can't re-alert.
_TERMINAL_STATES = {"Closed", "Resolved", "Cancelled"}

# Guard to send missing-config Webex alert only once per scheduler lifetime
_config_missing_notified = False


def _load_seen_ids():
    """Load per-group sets of previously seen incident numbers from disk."""
    if _SEEN_IDS_FILE.exists():
        try:
            with open(_SEEN_IDS_FILE) as f:
                data = json.load(f)
            # Convert lists back to sets
            return {group: set(ids) for group, ids in data.items()}
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to read seen-IDs state, starting fresh: {e}")
    return {}


def _save_seen_ids(state):
    """Persist per-group sets of seen incident numbers to disk."""
    try:
        _SEEN_IDS_FILE.parent.mkdir(parents=True, exist_ok=True)
        # Convert sets to lists for JSON serialization
        with open(_SEEN_IDS_FILE, 'w') as f:
            json.dump({group: sorted(ids) for group, ids in state.items()}, f, indent=2)
    except OSError as e:
        logger.error(f"Failed to save seen-IDs state: {e}")


def _get_snow_incident_url(sys_id):
    """Build ServiceNow incident URL from sys_id."""
    if not sys_id:
        return None
    config = get_config()
    instance_url = (config.snow_instance_url or "").rstrip("/")
    if not instance_url:
        return None
    return f"{instance_url}/now/nav/ui/classic/params/target/incident.do%3Fsys_id%3D{sys_id}"

# Priority colors and emojis
PRIORITY_CONFIG = {
    '1': {'emoji': '🔴', 'label': 'Critical', 'color': options.Colors.ATTENTION},
    '2': {'emoji': '🟠', 'label': 'High', 'color': options.Colors.WARNING},
    '3': {'emoji': '🟡', 'label': 'Medium', 'color': options.Colors.WARNING},
    '4': {'emoji': '🟢', 'label': 'Low', 'color': options.Colors.GOOD},
    '5': {'emoji': '⚪', 'label': 'Planning', 'color': options.Colors.DEFAULT},
}


def load_assignment_groups():
    """Load assignment groups configuration from JSON file."""
    if not CONFIG_FILE.exists():
        logger.warning(f"Assignment groups config not found: {CONFIG_FILE}")
        return []

    with open(CONFIG_FILE) as f:
        data = json.load(f)

    return [g for g in data.get('assignment_groups', []) if g.get('enabled', True)]


def _get_priority_info(priority):
    """Get priority emoji, label, and color."""
    return PRIORITY_CONFIG.get(str(priority), {
        'emoji': '❓',
        'label': f'Priority {priority}',
        'color': options.Colors.DEFAULT
    })


def _render_ticket_items(ticket, ticket_type="INC"):
    """Render card items for a single INC or CHG ticket.

    Returns:
        Tuple of (container_items, actions)
    """
    priority_info = _get_priority_info(ticket.get('priority'))
    number = ticket.get('number', 'Unknown')
    short_desc = ticket.get('shortDescription', ticket.get('short_description', 'No description'))
    created = ticket.get('createdDate', ticket.get('sys_created_on', 'Unknown'))
    sys_id = ticket.get('id', ticket.get('sys_id', ''))

    snow_url = _get_snow_incident_url(sys_id) if sys_id else None

    if ticket_type == "INC":
        caller = ticket.get('caller', 'Unknown')
        label_emoji = "🚨"
        extra_facts = [Fact(title="👤 Caller", value=caller)]
    else:
        label_emoji = "🔧"
        state = ticket.get('state', 'Unknown')
        extra_facts = [Fact(title="📌 State", value=state)]

    items = [
        ColumnSet(
            columns=[
                Column(
                    width="auto",
                    items=[TextBlock(
                        text=f"{label_emoji} {number}",
                        size=options.FontSize.MEDIUM,
                        weight=options.FontWeight.BOLDER,
                        color=priority_info['color']
                    )]
                ),
                Column(
                    width="stretch",
                    items=[TextBlock(
                        text=f"  {priority_info['label']}",
                        size=options.FontSize.SMALL,
                        color=priority_info['color'],
                        horizontalAlignment=options.HorizontalAlignment.RIGHT
                    )]
                )
            ]
        ),
        TextBlock(text=short_desc, wrap=True, size=options.FontSize.DEFAULT),
        FactSet(facts=[
            *extra_facts,
            Fact(title="⏰ Created", value=f"{created} ET"),
        ])
    ]

    actions = []
    if snow_url:
        actions.append(OpenUrl(url=snow_url, title=f"🔗 Open {number} in ServiceNow"))

    return items, actions


def _create_alert_card(incidents_by_group, changes_by_group):
    """Create a colorful adaptive card for MIM incident and change notifications.

    Args:
        incidents_by_group: Dict of {group_name: [incidents]}
        changes_by_group: Dict of {group_name: [changes]}

    Returns:
        AdaptiveCard instance
    """
    total_incs = sum(len(v) for v in incidents_by_group.values())
    total_chgs = sum(len(v) for v in changes_by_group.values())
    total_count = total_incs + total_chgs

    parts = []
    if total_incs:
        parts.append(f"{total_incs} incident(s)")
    if total_chgs:
        parts.append(f"{total_chgs} change(s)")
    subtitle = " · ".join(parts) + " detected"

    card_body: list = [
        Container(
            style=options.ContainerStyle.ATTENTION,
            items=[
                TextBlock(
                    text="🚨 MAJOR INCIDENT ALERT 🚨",
                    size=options.FontSize.EXTRA_LARGE,
                    weight=options.FontWeight.BOLDER,
                    horizontalAlignment=options.HorizontalAlignment.CENTER,
                    color=options.Colors.LIGHT
                ),
                TextBlock(
                    text=subtitle,
                    size=options.FontSize.MEDIUM,
                    horizontalAlignment=options.HorizontalAlignment.CENTER,
                    color=options.Colors.LIGHT
                )
            ]
        )
    ]

    all_groups = set(list(incidents_by_group.keys()) + list(changes_by_group.keys()))
    for group_name in sorted(all_groups):
        group_incs = incidents_by_group.get(group_name, [])
        group_chgs = changes_by_group.get(group_name, [])
        summary_parts = []
        if group_incs:
            summary_parts.append(f"{len(group_incs)} INC")
        if group_chgs:
            summary_parts.append(f"{len(group_chgs)} CHG")

        card_body.append(
            Container(
                style=options.ContainerStyle.EMPHASIS,
                items=[
                    TextBlock(
                        text=f"📋 {group_name}",
                        size=options.FontSize.MEDIUM,
                        weight=options.FontWeight.BOLDER,
                        color=options.Colors.ACCENT
                    ),
                    TextBlock(
                        text=" · ".join(summary_parts),
                        size=options.FontSize.SMALL,
                        isSubtle=True
                    )
                ]
            )
        )

        for incident in group_incs:
            items, actions = _render_ticket_items(incident, ticket_type="INC")
            card_body.append(Container(style=options.ContainerStyle.DEFAULT, items=items))
            if actions:
                card_body.append(ActionSet(actions=actions))

        for change in group_chgs:
            items, actions = _render_ticket_items(change, ticket_type="CHG")
            card_body.append(Container(style=options.ContainerStyle.DEFAULT, items=items))
            if actions:
                card_body.append(ActionSet(actions=actions))

    card_body.append(
        Container(items=[
            TextBlock(
                text="💡 Check ServiceNow for full details",
                size=options.FontSize.SMALL,
                isSubtle=True,
                horizontalAlignment=options.HorizontalAlignment.CENTER
            )
        ])
    )

    return AdaptiveCard(body=card_body)


def check_for_new_incidents(room_id=None):
    """Poll ServiceNow for new incidents and send Webex notifications.

    Args:
        room_id: Webex room ID to send notifications to. Defaults to dev test space.

    Note:
        All exceptions are caught and logged to prevent scheduler disruption.
    """
    try:
        config = get_config()
        room_id = room_id or config.webex_room_id_dev_test_space
        webex_token = config.webex_bot_access_token_moneyball

        if not room_id:
            logger.error("No Webex room ID configured")
            return

        if not webex_token:
            logger.error("No Webex bot token available for notifications")
            return

        groups = load_assignment_groups()
        if not groups:
            global _config_missing_notified
            logger.warning("No assignment groups configured for monitoring")
            if not _config_missing_notified and not CONFIG_FILE.exists():
                _config_missing_notified = True
                try:
                    dev_room = config.webex_room_id_dev_test_space
                    if dev_room and webex_token:
                        webex_api = WebexAPI(access_token=webex_token)
                        send_message_with_retry(
                            webex_api, dev_room,
                            markdown=f"⚠️ **Major Incident Monitor disabled** — config file missing:\n"
                                     f"`{CONFIG_FILE}`\n\n"
                                     f"No SNOW assignment groups are being polled. "
                                     f"Recreate the file and restart the scheduler."
                        )
                        logger.warning("Sent missing-config notification to dev test space")
                except Exception as notify_err:
                    logger.error(f"Failed to send missing-config notification: {notify_err}")
            return

        # Initialize ServiceNow client with error handling
        try:
            client = ServiceNowClient()
        except Exception as e:
            logger.error(f"Failed to initialize ServiceNow client: {e}")
            return

        incidents_by_group = {}
        seen_ids = _load_seen_ids()

        for group in groups:
            group_name = group.get('name')

            try:
                recent_incidents = client.get_recent_incidents_by_group_name(group_name, minutes=0)
                if isinstance(recent_incidents, dict) and 'error' in recent_incidents:
                    logger.error(f"Error fetching incidents for {group_name}: {recent_incidents.get('error')}")
                    continue  # Don't update seen IDs on error
            except Exception as e:
                logger.error(f"Exception fetching incidents for {group_name}: {e}")
                continue

            open_incidents = [inc for inc in recent_incidents if inc.get('state') not in _TERMINAL_STATES]
            current_ids = {inc.get('number') for inc in open_incidents if inc.get('number')}
            logger.info(f"MIM '{group_name}': {len(open_incidents)} open / {len(recent_incidents)} total")

            # First run for this group: seed the seen set without alerting.
            # Check key presence, not truthiness — an empty set means "polled,
            # had no results", and we must not re-seed (and miss alerts) next time.
            if group_name not in seen_ids:
                logger.info(f"First run for {group_name}: seeding {len(current_ids)} seen IDs (no alert)")
                seen_ids[group_name] = current_ids
                continue

            previously_seen = seen_ids[group_name]
            new_ids = current_ids - previously_seen
            if new_ids:
                new_incidents = [inc for inc in recent_incidents if inc.get('number') in new_ids]
                logger.info(f"Found {len(new_incidents)} new INC(s) for {group_name}: {sorted(new_ids)}")
                incidents_by_group[group_name] = new_incidents

            seen_ids[group_name] = current_ids

        _save_seen_ids(seen_ids)

        # Send notification if any incidents found
        if incidents_by_group:
            total_count = sum(len(v) for v in incidents_by_group.values())
            logger.info(f"Sending alert card: {total_count} INC(s)")

            webex_api = WebexAPI(access_token=webex_token)
            card = _create_alert_card(incidents_by_group, {})
            fallback_text = f"🚨 {total_count} new Major Incident(s)! Check ServiceNow for details."

            card_sent = None
            try:
                card_sent = send_card_with_retry(
                    webex_api,
                    room_id,
                    text=fallback_text,
                    attachments=[{
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "content": card.to_dict()
                    }]
                )
            except Exception as e:
                logger.error(f"Exception sending alert card: {e}")

            # send_card_with_retry returns None on failure (it swallows the exception
            # and logs internally). Treat None as failure so the markdown fallback fires.
            if card_sent is not None:
                logger.info("Alert card sent successfully")
            else:
                logger.warning("Alert card not delivered, sending markdown fallback")
                try:
                    message_parts = [f"🚨 **MAJOR INCIDENT ALERT** ({total_count} new)\n"]
                    for group_name, incidents in incidents_by_group.items():
                        message_parts.append(f"\n**📋 {group_name}**")
                        for inc in incidents:
                            priority_info = _get_priority_info(inc.get('priority'))
                            short_desc = inc.get('shortDescription', inc.get('short_description', 'No description'))
                            message_parts.append(f"- {priority_info['emoji']} **{inc.get('number')}** {short_desc}")
                    send_message_with_retry(webex_api, room_id, markdown="\n".join(message_parts))
                    logger.info("Fallback markdown message sent")
                except Exception as fallback_error:
                    logger.error(f"Fallback message also failed: {fallback_error}")
        else:
            logger.debug("No new incidents to report")

    except Exception as e:
        logger.error(f"Unexpected error in major incident monitor: {e}")
        # Don't re-raise - let the scheduler continue


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    # Manual run uses dev test space (default)
    check_for_new_incidents()
