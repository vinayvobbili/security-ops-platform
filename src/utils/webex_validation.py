"""Validation utilities for Webex bot inputs."""


def validate_required_inputs(attachment_actions, field_names, error_message=None):
    """
    Validate that required input fields are not empty.

    Args:
        attachment_actions: Webex attachment_actions object
        field_names: List of field names to validate (or single string)
        error_message: Custom error message (optional)

    Returns:
        tuple: (is_valid: bool, error_message: str or None)

    Example:
        valid, error = validate_required_inputs(
            attachment_actions,
            ['title', 'details'],
            "Please fill in both title and details."
        )
        if not valid:
            return error
    """
    if isinstance(field_names, str):
        field_names = [field_names]

    empty_fields = []
    for field in field_names:
        value = attachment_actions.inputs.get(field, '').strip()
        if not value:
            empty_fields.append(field)

    if empty_fields:
        if error_message is None:
            field_list = ", ".join(empty_fields)
            error_message = f"Please fill in the following required fields: {field_list}"
        return False, error_message

    return True, None


def get_input_value(attachment_actions, field_name, default=''):
    """
    Safely get a stripped input value from attachment_actions.

    Args:
        attachment_actions: Webex attachment_actions object
        field_name: Name of the input field
        default: Default value if field is missing or empty

    Returns:
        str: The stripped input value or default
    """
    value = attachment_actions.inputs.get(field_name, default)
    if isinstance(value, str):
        return value.strip()
    return value if value else default
