"""
XSOAR Entry Operations

Handles entries, notes, and war room commands for XSOAR incidents.
"""
import json
import logging
import time
from datetime import datetime
from typing import Any, Dict, List

import pytz

from ._client import ApiException
from ._retry import truncate_error_message
from ._utils import _parse_generic_response

log = logging.getLogger(__name__)


def get_entries(client, incident_id: str) -> List[Dict[str, Any]]:
    """
    Fetch entries (comments, notes) for a given incident.

    Args:
        client: XSOAR demisto-py client
        incident_id: The XSOAR incident ID

    Returns:
        List of entry dictionaries

    Raises:
        ApiException: If API call fails
    """
    try:
        response = client.generic_request(
            path=f'/incidents/{incident_id}/entries',
            method='GET'
        )
        data = json.loads(response[0]) if response else {}
        return data.get('data', [])
    except ApiException as e:
        log.error(f"Error fetching entries for incident {incident_id}: {truncate_error_message(e)}")
        raise


def get_case_data_with_notes(
    client,
    incident_id: str,
    max_retries: int = 3,
    filter_body: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """
    Fetch incident details along with notes.

    Args:
        client: XSOAR demisto-py client
        incident_id: The XSOAR incident ID
        max_retries: Maximum number of retry attempts for rate limiting/server errors
        filter_body: Optional InvestigationFilter dict sent as the POST body. Use
            e.g. ``{"categories": ["notes"]}`` to ask XSOAR to return only note
            entries — full investigations can be many MB each (playbook runs,
            integration dumps, war-room commands), so filtering matters when
            looping over thousands of tickets.

    Returns:
        Dictionary containing incident investigation data with notes

    Raises:
        ApiException: If API call fails after all retries
    """
    retry_count = 0
    body = filter_body if filter_body is not None else {}

    while retry_count <= max_retries:
        try:
            response = client.generic_request(
                path=f'/investigation/{incident_id}',
                method='POST',
                body=body
            )
            return _parse_generic_response(response)
        except ApiException as e:
            # Handle rate limiting (429)
            if e.status == 429:
                retry_count += 1
                if retry_count > max_retries:
                    log.error(f"Exceeded max retries ({max_retries}) for investigation {incident_id} due to rate limiting")
                    raise

                backoff_time = 5 * (2 ** (retry_count - 1))
                log.warning(f"Rate limit hit (429) for investigation {incident_id}. "
                            f"Retry {retry_count}/{max_retries}. "
                            f"Backing off for {backoff_time} seconds...")
                time.sleep(backoff_time)
                continue

            # Handle server errors (502, 503, 504)
            elif e.status in [502, 503, 504]:
                retry_count += 1
                if retry_count > max_retries:
                    log.error(f"Exceeded max retries ({max_retries}) for investigation {incident_id} due to server error {e.status}")
                    raise

                backoff_time = 5 * (2 ** (retry_count - 1))
                log.warning(f"Server error {e.status} for investigation {incident_id}. "
                            f"Retry {retry_count}/{max_retries}. "
                            f"Backing off for {backoff_time} seconds...")
                time.sleep(backoff_time)
                continue

            # For other errors, log and raise immediately
            else:
                log.error(f"Error fetching investigation {incident_id}: {truncate_error_message(e)}")
                raise

    # Should not reach here, but just in case
    raise ApiException(f"Failed to fetch investigation {incident_id} after {max_retries} retries")


def get_user_notes(client, incident_id: str, max_retries: int = 3) -> List[Dict[str, str]]:
    """
    Fetch user notes for a given incident.

    Args:
        client: XSOAR demisto-py client
        incident_id: The XSOAR incident ID
        max_retries: Maximum retry attempts for API calls (default: 3)

    Returns:
        List of formatted notes with note_text, author, and created_at fields,
        sorted with latest note first
    """
    # Ask XSOAR to filter server-side to the `notes` category — without this,
    # every call returns the full investigation (playbook runs, integration
    # outputs, war-room commands), which is many MB per ticket and blows up
    # memory when parallelising across thousands of tickets.
    case_data_with_notes = get_case_data_with_notes(
        client, incident_id,
        max_retries=max_retries,
        filter_body={"categories": ["notes"]},
    )
    entries = case_data_with_notes.get('entries', [])
    user_notes = [entry for entry in entries if entry.get('note')]

    # Format notes with required fields
    et_tz = pytz.timezone('America/New_York')
    formatted_notes = []
    for note in user_notes:
        # Parse ISO format timestamp
        created_str = note.get('created', '')
        if created_str:
            # Parse ISO 8601 format: "2025-10-23T22:24:17.48233Z"
            dt_utc = datetime.fromisoformat(created_str.replace('Z', '+00:00'))
            dt_et = dt_utc.astimezone(et_tz)
            created_at = dt_et.strftime('%m/%d/%Y %I:%M %p ET')
        else:
            created_at = ''

        formatted_notes.append({
            'note_text': note.get('contents', ''),
            'author': note.get('user', 'DBot'),
            'created_at': created_at
        })

    # Return with latest note first
    return list(reversed(formatted_notes))


def create_entry(
    client,
    incident_id: str,
    entry_data: str,
    endpoint: str,
    markdown: bool,
    max_retries: int = 3
) -> Dict[str, Any]:
    """
    Internal helper function to create an entry in an existing ticket with retry logic.

    Args:
        client: XSOAR demisto-py client
        incident_id: The XSOAR incident ID
        entry_data: The entry content (note text or command)
        endpoint: API endpoint ('/xsoar/entry/note' or '/xsoar/entry')
        markdown: Whether to render the entry as Markdown
        max_retries: Maximum number of retry attempts for rate limiting/server errors

    Returns:
        Response data from the API

    Raises:
        ValueError: If incident_id or entry_data is empty
        ApiException: If API call fails after all retries
    """
    # Validate inputs
    if not incident_id:
        raise ValueError("incident_id cannot be empty")
    if not entry_data:
        raise ValueError("entry_data cannot be empty")

    retry_count = 0

    while retry_count <= max_retries:
        try:
            payload = {
                "id": "",
                "version": 0,
                "investigationId": incident_id,
                "data": entry_data,
                "markdown": markdown,
            }

            response = client.generic_request(
                path=endpoint,
                method='POST',
                body=payload
            )
            return _parse_generic_response(response)

        except ApiException as e:
            # Handle rate limiting (429)
            if e.status == 429:
                retry_count += 1
                if retry_count > max_retries:
                    log.error(f"Exceeded max retries ({max_retries}) for {endpoint} on incident {incident_id} due to rate limiting")
                    raise

                backoff_time = 5 * (2 ** (retry_count - 1))
                log.warning(f"Rate limit hit (429) for {endpoint} on incident {incident_id}. "
                            f"Retry {retry_count}/{max_retries}. "
                            f"Backing off for {backoff_time} seconds...")
                time.sleep(backoff_time)
                continue

            # Handle server errors (502, 503, 504)
            elif e.status in [502, 503, 504]:
                retry_count += 1
                if retry_count > max_retries:
                    log.error(f"Exceeded max retries ({max_retries}) for {endpoint} on incident {incident_id} due to server error {e.status}")
                    raise

                backoff_time = 5 * (2 ** (retry_count - 1))
                log.warning(f"Server error {e.status} for {endpoint} on incident {incident_id}. "
                            f"Retry {retry_count}/{max_retries}. "
                            f"Backing off for {backoff_time} seconds...")
                time.sleep(backoff_time)
                continue

            # For other errors, log and raise immediately
            else:
                log.error(f"Error calling {endpoint} for incident {incident_id}: {truncate_error_message(e)}")
                raise

    # Should not reach here, but just in case
    raise ApiException(f"Failed to create entry at {endpoint} for incident {incident_id} after {max_retries} retries")


def create_new_entry_in_existing_ticket(
    client,
    incident_id: str,
    entry_data: str,
    markdown: bool = True
) -> Dict[str, Any]:
    """
    Create a new entry (note) in an existing ticket.

    Args:
        client: XSOAR demisto-py client
        incident_id: The XSOAR incident ID
        entry_data: The entry content (note text)
        markdown: Whether to render the entry as Markdown (default: True)

    Returns:
        Response data from the API

    Raises:
        ValueError: If incident_id or entry_data is empty
        ApiException: If API call fails after retries

    Example:
        create_new_entry_in_existing_ticket(client, "123456", "This is a note")
    """
    log.debug(f"Creating new note in ticket {incident_id}")
    result = create_entry(client, incident_id, entry_data, '/xsoar/entry/note', markdown)
    log.debug(f"Successfully created note in ticket {incident_id}")
    return result


def execute_command_in_war_room(client, incident_id: str, command: str) -> Dict[str, Any]:
    """
    Execute a command in the war room of the specified incident.

    ⚠️ SECURITY WARNING:
    This method executes arbitrary XSOAR commands in the war room.
    Only use with trusted input.

    Args:
        client: XSOAR demisto-py client
        incident_id: The XSOAR incident ID
        command: The XSOAR command to execute (e.g., "!ad-get-user username=jdoe")

    Returns:
        Response data from the API

    Raises:
        ValueError: If incident_id or command is empty
        ApiException: If API call fails after retries

    Example:
        execute_command_in_war_room(client, "123456", "!ad-get-user username=jsmith")
    """
    log.debug(f"Executing war room command in ticket {incident_id}: {command}")
    result = create_entry(client, incident_id, command, '/xsoar/entry', markdown=False)
    log.debug(f"Successfully executed command '{command}' in ticket {incident_id}")
    return result


def run_command_and_read_context(
    client,
    incident_id: str,
    command: str,
    args: Dict[str, str],
    context_path: str,
    wait_seconds: int = 10,
    using: str = "",
) -> Any:
    """Fire an XSOAR integration command and return the context it writes.

    Used by services that don't have direct API credentials (e.g. Varonis,
    Active Directory) — XSOAR holds their credentials and connection, so the
    service fires a war room command and reads the structured result back from
    the incident context.

    Flow:
      1. POST /xsoar/entry  — fires the command asynchronously in the war room
      2. sleep wait_seconds — gives the integration time to respond
      3. GET /incident/load/{incident_id} — reads the full incident context
      4. Walk context_path and return whatever the command wrote there

    Args:
        client:        XSOAR demisto-py client
        incident_id:   XSOAR incident ID — command runs in this investigation
        command:       XSOAR integration command, e.g. "!varonis-get-alert-evidence"
        args:          Command arguments as plain strings {"username": "jsmith"}.
                       Empty-string values are dropped.
        context_path:  Dot-notation path where the command writes its output,
                       e.g. "Varonis.Alert" or "ActiveDirectory.Users"
        wait_seconds:  Seconds to wait before reading context (default 10).
                       Increase for slow integrations.
        using:         Integration instance name to target. Without this, XSOAR
                       runs the command against ALL configured instances of that
                       integration. Always supply the specific instance name.

    Returns:
        The value at context_path in the incident context (dict, list, or
        primitive), or None if the path is absent or the command failed.
        All exceptions are caught — callers receive None on any failure.
    """
    if not incident_id or not command:
        return None

    # Build XSOAR args format: {"argName": {"simple": "value"}}
    xsoar_args = {k: {"simple": str(v)} for k, v in args.items() if v}
    if using:
        xsoar_args["using"] = {"simple": using}

    # Step 1: Fire the command async
    try:
        payload = {
            "id": "",
            "version": 0,
            "investigationId": incident_id,
            "data": command,
            "args": xsoar_args,
            "markdown": False,
        }
        client.generic_request(path="/xsoar/entry", method="POST", body=payload)
        log.debug(f"Fired command '{command}' in ticket {incident_id}")
    except ApiException as e:
        log.warning(
            f"Failed to fire '{command}' in ticket {incident_id}: "
            f"{e.status} {getattr(e, 'reason', '')}"
        )
        return None
    except Exception as e:
        log.warning(f"Failed to fire '{command}' in ticket {incident_id}: {e}")
        return None

    # Step 2: Wait for the integration to respond
    time.sleep(wait_seconds)

    # Step 3: Fetch the incident context
    try:
        response = client.generic_request(
            path=f"/incident/load/{incident_id}",
            method="GET",
        )
        from ._utils import _parse_generic_response
        parsed = _parse_generic_response(response)
        context = parsed.get("context", {}) or {}
    except Exception as e:
        log.warning(f"Failed to read incident context for ticket {incident_id}: {e}")
        return None

    # Step 4: Walk the context_path
    current: Any = context
    for part in context_path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
            if current is None:
                log.debug(
                    f"context_path '{context_path}' not found in ticket {incident_id} "
                    f"(missing segment '{part}')"
                )
                return None
        else:
            return None

    log.info(f"Command '{command}' → '{context_path}' returned data for ticket {incident_id}")
    return current
