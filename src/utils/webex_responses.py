"""Response formatting utilities for Webex bots."""


def format_user_response(activity, message):
    """
    Format response with user's display name prefix.

    Args:
        activity: Webex activity object
        message: Response message

    Returns:
        str: Formatted response with user name

    Example:
        return format_user_response(activity, "Ticket has been created.")
        # Returns: "John Doe, Ticket has been created."
    """
    display_name = get_user_display_name(activity)
    return f"{display_name}, {message}"


def get_user_email(activity):
    """Extract user email from activity."""
    return activity['actor']['emailAddress']


def get_user_display_name(activity):
    """Extract user display name from activity."""
    return activity['actor']['displayName']


def get_user_person_id(activity):
    """Extract user person ID from activity (for direct messages)."""
    return activity.get('actor', {}).get('id')
