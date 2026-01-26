"""Helper functions for XSOAR incident operations in Webex bots."""

from my_config import get_config

CONFIG = get_config()


def build_incident_url(incident_id, base_url=None):
    """
    Build XSOAR incident URL from ID.

    Args:
        incident_id: The XSOAR incident ID
        base_url: Optional base URL (defaults to prod)

    Returns:
        str: Full URL to the incident
    """
    if base_url is None:
        base_url = CONFIG.xsoar_prod_ui_base_url
    return f"{base_url}/Custom/caseinfoid/{incident_id}"


def create_incident_with_response(
    incident_handler,
    incident_dict,
    activity,
    success_message_template,
    append_submitter=True
):
    """
    Create XSOAR incident and return formatted response.

    Args:
        incident_handler: XSOAR incident handler instance
        incident_dict: Incident data dictionary
        activity: Webex activity object
        success_message_template: Template string with placeholders:
            {actor}, {ticket_no}, {ticket_url}, {ticket_title}
        append_submitter: Whether to append submitter to details (default: True)

    Returns:
        str: Formatted success message

    Example:
        return create_incident_with_response(
            incident_handler,
            {
                'name': title,
                'details': details,
                'CustomFields': {...}
            },
            activity,
            "{actor}, Ticket [#{ticket_no}]({ticket_url}) has been created."
        )
    """
    # Append submitter info if requested
    if append_submitter and 'details' in incident_dict:
        submitter_email = activity['actor']['emailAddress']
        incident_dict['details'] += f"\nSubmitted by: {submitter_email}"

    # Create incident
    result = incident_handler.create(incident_dict)
    ticket_no = result.get('id')
    ticket_url = build_incident_url(ticket_no)
    ticket_title = incident_dict.get('name', '')

    # Format response
    return success_message_template.format(
        actor=activity['actor']['displayName'],
        ticket_no=ticket_no,
        ticket_url=ticket_url,
        ticket_title=ticket_title
    )
