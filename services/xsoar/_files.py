"""
XSOAR File Upload Operations

Handles file uploads to XSOAR incident attachments and war room.
"""
import json
import logging
import os
from typing import Any, Dict

import requests

from ._client import DISABLE_SSL_VERIFY

log = logging.getLogger(__name__)


def upload_file_to_attachment(
    base_url: str,
    auth_key: str,
    auth_id: str,
    incident_id: str,
    file_path: str,
    comment: str = ""
) -> Dict[str, Any]:
    """
    Upload a file to the incident's Attachments field (not war room).

    Args:
        base_url: XSOAR API base URL
        auth_key: XSOAR API auth key
        auth_id: XSOAR API auth ID
        incident_id: The XSOAR incident ID
        file_path: Path to the file to upload
        comment: Optional comment for the file upload

    Returns:
        Response data from the API

    Raises:
        ValueError: If incident_id or file_path is empty
        FileNotFoundError: If the file doesn't exist
        requests.exceptions.RequestException: If API call fails

    Example:
        upload_file_to_attachment(base_url, auth_key, auth_id, "123456", "/path/to/file.txt", "Evidence")
    """
    # Validate inputs
    if not incident_id:
        raise ValueError("incident_id cannot be empty")
    if not file_path:
        raise ValueError("file_path cannot be empty")
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    log.debug(f"Uploading file {file_path} to attachments field of ticket {incident_id}")

    # Build full URL
    url = f'{base_url}/xsoar/public/v1/incident/upload/{incident_id}'
    file_name = os.path.basename(file_path)

    try:
        from requests_toolbelt.multipart.encoder import MultipartEncoder

        # Prepare multipart form data
        with open(file_path, 'rb') as f:
            file_content = f.read()

        file_size = len(file_content)
        log.debug(f"File size: {file_size} bytes")

        multipart_data = MultipartEncoder(
            fields={
                'file': (file_name, file_content, 'application/octet-stream'),
                'fileComment': comment
            }
        )

        headers = {
            'Authorization': auth_key,
            'x-xdr-auth-id': auth_id,
            'Content-Type': multipart_data.content_type,
            'Accept': 'application/json'
        }

        response = requests.post(
            url,
            data=multipart_data,
            headers=headers,
            verify=not DISABLE_SSL_VERIFY,
            timeout=60
        )

        response.raise_for_status()

        # Parse response
        if response.text:
            try:
                response_data = response.json()
            except json.JSONDecodeError:
                log.warning(f"Could not parse response as JSON: {response.text}")
                response_data = {"raw_response": response.text}

            # Check for XSOAR-specific errors
            if isinstance(response_data, dict) and 'error' in response_data:
                error_msg = response_data['error']
                log.error(f"Error from XSOAR when uploading file to attachments of ticket {incident_id}: {error_msg}")
                raise ValueError(f"XSOAR error: {error_msg}")

            log.debug(f"Successfully uploaded file {file_name} to attachments of ticket {incident_id}")
            return response_data
        else:
            log.debug(f"Successfully uploaded file {file_name} to attachments of ticket {incident_id}")
            return {}

    except requests.exceptions.RequestException as e:
        log.error(f"Error uploading file to attachments of ticket {incident_id}: {e}")
        raise
    except (IOError, OSError) as e:
        log.error(f"Error reading file {file_path}: {e}")
        raise


def upload_file_to_war_room(
    base_url: str,
    auth_key: str,
    auth_id: str,
    incident_id: str,
    file_path: str,
    comment: str = "",
    is_note_entry: bool = False,
    show_media_files: bool = False,
    tags: str = ""
) -> Dict[str, Any]:
    """
    Upload a file to the specified ticket's war room (appears in Evidence/Indicators).

    Args:
        base_url: XSOAR API base URL
        auth_key: XSOAR API auth key
        auth_id: XSOAR API auth ID
        incident_id: The XSOAR incident ID
        file_path: Path to the file to upload
        comment: Optional comment for the file upload
        is_note_entry: Whether to show this as a note entry (default: False)
        show_media_files: Whether to show media files (default: False)
        tags: Comma-separated tags for the file

    Returns:
        Response data from the API

    Raises:
        ValueError: If incident_id or file_path is empty
        FileNotFoundError: If the file doesn't exist
        requests.exceptions.RequestException: If API call fails

    Example:
        upload_file_to_war_room(base_url, auth_key, auth_id, "123456", "/path/to/file.txt", "Evidence")
    """
    # Validate inputs
    if not incident_id:
        raise ValueError("incident_id cannot be empty")
    if not file_path:
        raise ValueError("file_path cannot be empty")
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    log.debug(f"Uploading file {file_path} to ticket {incident_id}")

    # Build full URL
    url = f'{base_url}/xsoar/public/v1/entry/upload/{incident_id}'
    file_name = os.path.basename(file_path)

    try:
        from requests_toolbelt.multipart.encoder import MultipartEncoder

        # Prepare multipart form data
        with open(file_path, 'rb') as f:
            file_content = f.read()

        file_size = len(file_content)
        log.debug(f"File size: {file_size} bytes")

        multipart_data = MultipartEncoder(
            fields={
                'file': (file_name, file_content, 'application/octet-stream'),
                'fileComment': comment,
                'isNoteEntry': str(is_note_entry).lower(),
                'showMediaFiles': str(show_media_files).lower(),
                'tags': tags
            }
        )

        headers = {
            'Authorization': auth_key,
            'x-xdr-auth-id': auth_id,
            'Content-Type': multipart_data.content_type,
            'Accept': 'application/json'
        }

        response = requests.post(
            url,
            data=multipart_data,
            headers=headers,
            verify=not DISABLE_SSL_VERIFY,
            timeout=60
        )

        response.raise_for_status()

        # Parse response
        if response.text:
            try:
                response_data = response.json()
            except json.JSONDecodeError:
                log.warning(f"Could not parse response as JSON: {response.text}")
                response_data = {"raw_response": response.text}

            # Check for XSOAR-specific errors
            if isinstance(response_data, dict) and 'error' in response_data:
                error_msg = response_data['error']
                log.error(f"Error from XSOAR when uploading file to ticket {incident_id}: {error_msg}")
                raise ValueError(f"XSOAR error: {error_msg}")

            log.debug(f"Successfully uploaded file {file_name} to ticket {incident_id}")
            return response_data
        else:
            log.debug(f"Successfully uploaded file {file_name} to ticket {incident_id}")
            return {}

    except requests.exceptions.RequestException as e:
        log.error(f"Error uploading file to ticket {incident_id}: {e}")
        raise
    except (IOError, OSError) as e:
        log.error(f"Error reading file {file_path}: {e}")
        raise


def upload_file_to_ticket(
    base_url: str,
    auth_key: str,
    auth_id: str,
    incident_id: str,
    file_path: str,
    comment: str = "",
    upload_to: str = "attachment"
) -> Dict[str, Any]:
    """
    Upload a file to a ticket (attachments field or war room).

    Args:
        base_url: XSOAR API base URL
        auth_key: XSOAR API auth key
        auth_id: XSOAR API auth ID
        incident_id: The XSOAR incident ID
        file_path: Path to the file to upload
        comment: Optional comment for the file upload
        upload_to: Where to upload - "attachment" (default) or "war_room"

    Returns:
        Response data from the API

    Raises:
        ValueError: If incident_id, file_path is empty, or upload_to is invalid
        FileNotFoundError: If the file doesn't exist
        requests.exceptions.RequestException: If API call fails

    Example:
        # Upload to attachments (default)
        upload_file_to_ticket(base_url, auth_key, auth_id, "123456", "/path/to/file.txt", "Evidence")

        # Upload to war room
        upload_file_to_ticket(base_url, auth_key, auth_id, "123456", "/path/to/file.txt", "Evidence", upload_to="war_room")
    """
    if upload_to == "attachment":
        return upload_file_to_attachment(base_url, auth_key, auth_id, incident_id, file_path, comment)
    elif upload_to == "war_room":
        return upload_file_to_war_room(base_url, auth_key, auth_id, incident_id, file_path, comment)
    else:
        raise ValueError(f"Invalid upload_to value: {upload_to}. Must be 'attachment' or 'war_room'")
