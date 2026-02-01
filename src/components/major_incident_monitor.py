"""
Monitor ServiceNow for new Major Incidents assigned to configured groups.

Polls ServiceNow every 15 minutes for incidents assigned to groups defined in
data/transient/secops/assignment_groups.json and sends notifications to Webex.
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

CONFIG_FILE = Path(__file__).parent.parent.parent / "data/transient/secops/assignment_groups.json"


def _get_snow_incident_url(sys_id):
    """Build ServiceNow incident URL from sys_id."""
    config = get_config()
    # Extract base instance URL from snow_base_url (e.g., https://company.service-now.com/api/... -> https://company.service-now.com)
    base_url = config.snow_base_url or ""
    # Parse to get just the scheme and host
    if base_url:
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        instance_url = f"{parsed.scheme}://{parsed.netloc}"
        return f"{instance_url}/nav_to.do?uri=incident.do?sys_id={sys_id}"
    return None

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


def _create_incident_card(incidents_by_group):
    """Create a colorful adaptive card for incident notifications.

    Args:
        incidents_by_group: Dict of {group_name: [incidents]}

    Returns:
        AdaptiveCard instance
    """
    total_count = sum(len(incs) for incs in incidents_by_group.values())

    # Header with fire emoji and attention-grabbing styling
    card_body = [
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
                    text=f"{total_count} new incident(s) detected",
                    size=options.FontSize.MEDIUM,
                    horizontalAlignment=options.HorizontalAlignment.CENTER,
                    color=options.Colors.LIGHT
                )
            ]
        )
    ]

    # Add each group's incidents
    for group_name, incidents in incidents_by_group.items():
        # Group header
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
                        text=f"{len(incidents)} incident(s)",
                        size=options.FontSize.SMALL,
                        isSubtle=True
                    )
                ]
            )
        )

        # Each incident in this group
        # Field names per ITSM API KB0224060
        for incident in incidents:
            priority_info = _get_priority_info(incident.get('priority'))
            number = incident.get('number', 'Unknown')
            short_desc = incident.get('shortDescription', incident.get('short_description', 'No description'))
            created = incident.get('createdDate', incident.get('sys_created_on', 'Unknown'))
            caller = incident.get('caller', 'Unknown')
            sys_id = incident.get('id', incident.get('sys_id', ''))

            # Build ServiceNow URL for this incident
            snow_url = _get_snow_incident_url(sys_id) if sys_id else None

            # Incident container with priority-based styling
            incident_items = [
                # Incident number and priority
                ColumnSet(
                    columns=[
                        Column(
                            width="auto",
                            items=[
                                TextBlock(
                                    text=f"{priority_info['emoji']} {number}",
                                    size=options.FontSize.MEDIUM,
                                    weight=options.FontWeight.BOLDER,
                                    color=priority_info['color']
                                )
                            ]
                        ),
                        Column(
                            width="stretch",
                            items=[
                                TextBlock(
                                    text=f"  {priority_info['label']}",
                                    size=options.FontSize.SMALL,
                                    color=priority_info['color'],
                                    horizontalAlignment=options.HorizontalAlignment.RIGHT
                                )
                            ]
                        )
                    ]
                ),
                # Description
                TextBlock(
                    text=short_desc,
                    wrap=True,
                    size=options.FontSize.DEFAULT
                ),
                # Facts (metadata)
                FactSet(
                    facts=[
                        Fact(title="👤 Caller", value=caller),
                        Fact(title="⏰ Created", value=f"{created} ET"),
                    ]
                )
            ]

            # Add action button if we have a URL
            actions = []
            if snow_url:
                actions.append(OpenUrl(url=snow_url, title=f"🔗 Open {number} in ServiceNow"))

            incident_container = Container(
                style=options.ContainerStyle.DEFAULT,
                items=incident_items
            )

            card_body.append(incident_container)

            # Add action set after container if we have actions
            if actions:
                card_body.append(ActionSet(actions=actions))

    # Footer
    card_body.append(
        Container(
            items=[
                TextBlock(
                    text="💡 Check ServiceNow for full details",
                    size=options.FontSize.SMALL,
                    isSubtle=True,
                    horizontalAlignment=options.HorizontalAlignment.CENTER
                )
            ]
        )
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
            logger.warning("No assignment groups configured for monitoring")
            return

        # Initialize ServiceNow client with error handling
        try:
            client = ServiceNowClient()
        except Exception as e:
            logger.error(f"Failed to initialize ServiceNow client: {e}")
            return

        incidents_by_group = {}

        for group in groups:
            group_name = group.get('name')
            poll_interval = group.get('poll_interval_minutes', 15)

            logger.info(f"Checking incidents for group: {group_name} (past {poll_interval} mins)")

            try:
                incidents = client.get_recent_incidents_by_group_name(group_name, minutes=poll_interval)

                if isinstance(incidents, dict) and 'error' in incidents:
                    logger.error(f"Error fetching incidents for {group_name}: {incidents.get('error')}")
                    continue

                if incidents:
                    logger.info(f"Found {len(incidents)} new incident(s) for {group_name}")
                    incidents_by_group[group_name] = incidents
                else:
                    logger.debug(f"No new incidents for {group_name}")

            except Exception as e:
                logger.error(f"Exception while fetching incidents for {group_name}: {e}")
                continue  # Continue to next group even if one fails

        # Send notification if any incidents found
        if incidents_by_group:
            total_count = sum(len(incs) for incs in incidents_by_group.values())
            logger.info(f"Sending adaptive card notification for {total_count} total incident(s)")

            # Create Webex API instance
            webex_api = WebexAPI(access_token=webex_token)

            # Create and send adaptive card
            card = _create_incident_card(incidents_by_group)
            fallback_text = f"🚨 {total_count} new Major Incident(s) detected! Check ServiceNow for details."

            try:
                send_card_with_retry(
                    webex_api,
                    room_id,
                    text=fallback_text,
                    attachments=[{
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "content": card.to_dict()
                    }]
                )
                logger.info("Adaptive card notification sent successfully")
            except Exception as e:
                logger.error(f"Failed to send adaptive card: {e}")
                # Fallback to markdown message
                try:
                    message_parts = [f"🚨 **MAJOR INCIDENT ALERT** ({total_count} new)\n"]
                    for group_name, incidents in incidents_by_group.items():
                        message_parts.append(f"\n**📋 {group_name}**")
                        for inc in incidents:
                            priority_info = _get_priority_info(inc.get('priority'))
                            message_parts.append(
                                f"- {priority_info['emoji']} **{inc.get('number')}** - {priority_info['label']}"
                            )
                            short_desc = inc.get('shortDescription', inc.get('short_description', 'No description'))
                            message_parts.append(f"  > {short_desc}")

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
