"""
XSOAR List Handler

Handles all XSOAR list operations including:
- Fetching all lists
- Getting list data and version by name
- Saving lists (JSON and text formats)
- Adding items to lists
"""
import inspect
import json
import logging
import time
from typing import Any, Dict, List

from src.utils.xsoar_enums import XsoarEnvironment
from ._client import ApiException, get_prod_client, get_dev_client
from ._utils import _parse_generic_response

log = logging.getLogger(__name__)


class ListHandler:
    """Handler for XSOAR list operations."""

    def __init__(self, environment: XsoarEnvironment = XsoarEnvironment.PROD):
        """
        Initialize ListHandler with XSOAR environment.

        Args:
            environment: XsoarEnvironment enum (PROD or DEV), defaults to PROD
        """
        if environment == XsoarEnvironment.PROD:
            self.client = get_prod_client()
        elif environment == XsoarEnvironment.DEV:
            self.client = get_dev_client()
        else:
            raise ValueError(f"Invalid environment: {environment}. Must be XsoarEnvironment.PROD or XsoarEnvironment.DEV")

    def get_all_lists(self) -> List[Dict[str, Any]]:
        """
        Get all lists from XSOAR.

        Returns:
            List of XSOAR list dictionaries
        """
        # Get caller information for debugging
        caller_frame = inspect.currentframe().f_back
        caller_info = inspect.getframeinfo(caller_frame)
        caller_function = caller_frame.f_code.co_name
        caller_file = caller_info.filename.split('/')[-1] if caller_info.filename else 'unknown'

        start_time = time.time()
        log.debug(f"get_all_lists() called by {caller_file}:{caller_function}() at line {caller_info.lineno}")

        try:
            log.debug(f"Making request to /lists endpoint...")
            response = self.client.generic_request(
                path='/lists',
                method='GET'
            )
            elapsed = time.time() - start_time
            log.debug(f"get_all_lists() completed successfully in {elapsed:.2f}s")

            result = _parse_generic_response(response)
            # Result should be a list, but if it's a dict, return empty list
            return result if isinstance(result, list) else []
        except ApiException as e:
            elapsed = time.time() - start_time
            log.error(f"Error in get_all_lists after {elapsed:.2f}s (called by {caller_file}:{caller_function}): {e}")
            return []
        except Exception as e:
            elapsed = time.time() - start_time
            log.error(f"Unexpected error in get_all_lists after {elapsed:.2f}s (called by {caller_file}:{caller_function}): {e}")
            return []

    def get_list_data_by_name(self, list_name):
        """Get list data by name"""
        all_lists = self.get_all_lists()
        list_item = next((item for item in all_lists if item['id'] == list_name), None)
        if list_item is None:
            log.warning(f"List '{list_name}' not found")
            return None
        try:
            return json.loads(list_item['data'])
        except (TypeError, json.JSONDecodeError):
            return list_item['data']

    def get_list_version_by_name(self, list_name):
        """Get list version by name"""
        all_lists = self.get_all_lists()
        list_item = next((item for item in all_lists if item['id'] == list_name), None)
        if list_item is None:
            log.warning(f"List '{list_name}' not found")
            return None
        return list_item['version']

    def save(self, list_name: str, list_data: Any) -> Dict[str, Any]:
        """
        Save list data to XSOAR.

        Args:
            list_name: Name of the list
            list_data: Data to save (will be JSON serialized)

        Returns:
            Response data from save operation

        Raises:
            ApiException: If save operation fails
        """
        list_version = self.get_list_version_by_name(list_name)

        payload = {
            "data": json.dumps(list_data, indent=4),
            "name": list_name,
            "type": "json",
            "id": list_name,
            "version": list_version
        }

        try:
            response = self.client.generic_request(
                path='/lists/save',
                method='POST',
                body=payload
            )
            return _parse_generic_response(response)
        except ApiException as e:
            log.error(f"Error saving list: {e}")
            raise

    def save_as_text(self, list_name: str, list_data: List[str]) -> Dict[str, Any]:
        """
        Save list data as plain text (comma-separated string).

        Args:
            list_name: Name of the list
            list_data: List of strings to save

        Returns:
            Response data from save operation

        Raises:
            ApiException: If save operation fails
        """
        list_version = self.get_list_version_by_name(list_name)
        payload = {
            "data": ','.join(list_data),
            "name": list_name,
            "type": "text",
            "id": list_name,
            "version": list_version
        }

        try:
            response = self.client.generic_request(
                path='/lists/save',
                method='POST',
                body=payload
            )
            return _parse_generic_response(response)
        except ApiException as e:
            log.error(f"Error saving list as text: {e}")
            raise

    def add_item_to_list(self, list_name, new_entry):
        """Add item to existing list"""
        list_data = self.get_list_data_by_name(list_name)
        list_data.append(new_entry)
        self.save(list_name, list_data)
