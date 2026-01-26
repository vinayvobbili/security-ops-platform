"""
QRadar API Client

Provides integration with IBM QRadar SIEM for security event searches,
offense management, and reference set operations.
"""

import logging
import time
from typing import Optional, Dict, Any, List
from urllib.parse import quote

import requests

from my_config import get_config

logger = logging.getLogger(__name__)

# Default API version
QRADAR_API_VERSION = "19.0"


class QRadarClient:
    """Client for interacting with the IBM QRadar SIEM API."""

    def __init__(self):
        self.config = get_config()
        self.api_key = self.config.qradar_api_key
        self.base_url = self.config.qradar_api_url
        self.timeout = 60
        self.api_version = QRADAR_API_VERSION

        if not self.api_key:
            logger.warning("QRadar API key not configured")
        if not self.base_url:
            logger.warning("QRadar API URL not configured")

    def is_configured(self) -> bool:
        """Check if the client is properly configured."""
        return bool(self.api_key and self.base_url)

    def _get_headers(self) -> Dict[str, str]:
        """Get headers for QRadar API requests."""
        return {
            "SEC": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Version": self.api_version,
        }

    def _make_request(
        self,
        endpoint: str,
        method: str = "GET",
        params: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        range_header: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Make authenticated request to QRadar API.

        Args:
            endpoint: API endpoint path (without base URL)
            method: HTTP method (GET, POST, DELETE)
            params: Query parameters
            json_data: JSON body for POST requests
        """
        if not self.is_configured():
            return {"error": "QRadar API not configured (missing URL or API key)"}

        headers = self._get_headers()
        if range_header:
            headers["Range"] = range_header
        url = f"{self.base_url.rstrip('/')}/api/{endpoint.lstrip('/')}"

        try:
            logger.debug(f"Making QRadar {method} request to: {endpoint}")

            if method == "POST":
                response = requests.post(
                    url, headers=headers, params=params, json=json_data, timeout=self.timeout, verify=True
                )
            elif method == "DELETE":
                response = requests.delete(
                    url, headers=headers, params=params, timeout=self.timeout, verify=True
                )
            else:
                response = requests.get(
                    url, headers=headers, params=params, timeout=self.timeout, verify=True
                )

            response.raise_for_status()

            # Some QRadar endpoints return empty responses
            if response.text:
                return response.json()
            return {"success": True}

        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code
            error_msg = e.response.text if e.response.text else str(e)

            if status_code == 401:
                return {"error": "Invalid QRadar API key"}
            elif status_code == 403:
                return {"error": "Access denied - insufficient permissions"}
            elif status_code == 404:
                return {"error": "Resource not found"}
            elif status_code == 409:
                return {"error": f"Conflict: {error_msg}"}
            elif status_code == 422:
                return {"error": f"Validation error: {error_msg}"}
            elif status_code == 429:
                return {"error": "QRadar API rate limit exceeded"}
            elif status_code >= 500:
                return {"error": f"QRadar server error: {status_code}"}
            else:
                logger.error(f"QRadar API error: {status_code} - {error_msg}")
                return {"error": f"QRadar API error ({status_code}): {error_msg}"}

        except requests.exceptions.Timeout:
            logger.error("QRadar API request timed out")
            return {"error": "Request timed out"}

        except requests.exceptions.RequestException as e:
            logger.error(f"QRadar request failed: {e}")
            return {"error": f"Request failed: {str(e)}"}

    # ==================== AQL Search Methods ====================

    def create_search(self, aql_query: str) -> Dict[str, Any]:
        """Create a new AQL search.

        Args:
            aql_query: The AQL (Ariel Query Language) query string

        Returns:
            dict: Search object with search_id for status polling
        """
        logger.debug(f"Creating AQL search: {aql_query[:100]}...")
        return self._make_request(
            "ariel/searches",
            method="POST",
            params={"query_expression": aql_query}
        )

    def get_search_status(self, search_id: str) -> Dict[str, Any]:
        """Get the status of an AQL search.

        Args:
            search_id: The search ID from create_search

        Returns:
            dict: Search status with 'status' field (WAIT, EXECUTE, SORTING, COMPLETED, CANCELED, ERROR)
        """
        return self._make_request(f"ariel/searches/{search_id}")

    def get_search_results(
        self,
        search_id: str,
        start: int = 0,
        limit: int = 100
    ) -> Dict[str, Any]:
        """Get results from a completed AQL search.

        Args:
            search_id: The search ID from create_search
            start: Starting record offset (for pagination)
            limit: Maximum records to return

        Returns:
            dict: Search results with 'events' or 'flows' array
        """
        return self._make_request(
            f"ariel/searches/{search_id}/results",
            range_header=f"items={start}-{start + limit - 1}"
        )

    def run_aql_search(
        self,
        aql_query: str,
        timeout: int = 300,
        poll_interval: int = 5,
        max_results: int = 100
    ) -> Dict[str, Any]:
        """Run an AQL search and wait for results.

        This is a convenience method that creates a search, polls for completion,
        and returns the results.

        Args:
            aql_query: The AQL query string
            timeout: Maximum seconds to wait for completion
            poll_interval: Seconds between status checks
            max_results: Maximum results to return

        Returns:
            dict: Search results or error
        """
        # Create the search
        search_result = self.create_search(aql_query)
        if "error" in search_result:
            return search_result

        search_id = search_result.get("search_id") or search_result.get("cursor_id")
        if not search_id:
            return {"error": "No search ID returned from QRadar"}

        logger.info(f"Search created with ID: {search_id}")

        # Poll for completion
        elapsed = 0
        while elapsed < timeout:
            status_result = self.get_search_status(search_id)
            if "error" in status_result:
                return status_result

            status = status_result.get("status", "")
            logger.debug(f"Search status: {status} (elapsed: {elapsed}s)")

            if status == "COMPLETED":
                logger.info(f"Search completed in {elapsed}s")
                return self.get_search_results(search_id, limit=max_results)

            elif status in ("CANCELED", "ERROR"):
                error_msg = status_result.get("error_messages", [])
                return {"error": f"Search {status}: {error_msg}"}

            time.sleep(poll_interval)
            elapsed += poll_interval

        return {"error": f"Search timed out after {timeout}s"}

    # ==================== Offense Methods ====================

    def get_offenses(
        self,
        filter_query: Optional[str] = None,
        fields: Optional[str] = None,
        sort: Optional[str] = None,
        start: int = 0,
        limit: int = 50
    ) -> Dict[str, Any]:
        """Get offenses from QRadar.

        Args:
            filter_query: QRadar filter expression (e.g., "status=OPEN")
            fields: Comma-separated list of fields to return
            sort: Field to sort by (prefix with - for descending)
            start: Starting offset for pagination
            limit: Maximum offenses to return

        Returns:
            dict: List of offenses or error
        """
        params = {}
        if filter_query:
            params["filter"] = filter_query
        if fields:
            params["fields"] = fields
        if sort:
            params["sort"] = sort

        range_header = f"items={start}-{start + limit - 1}"
        result = self._make_request("siem/offenses", params=params or None, range_header=range_header)

        # Wrap list response in dict for consistency
        if isinstance(result, list):
            return {"offenses": result, "count": len(result)}
        return result

    def get_offense(self, offense_id: int, fields: Optional[str] = None) -> Dict[str, Any]:
        """Get a specific offense by ID.

        Args:
            offense_id: The offense ID
            fields: Comma-separated list of fields to return

        Returns:
            dict: Offense details or error
        """
        params = {}
        if fields:
            params["fields"] = fields

        return self._make_request(f"siem/offenses/{offense_id}", params=params)

    def get_offense_notes(self, offense_id: int) -> Dict[str, Any]:
        """Get notes for an offense.

        Args:
            offense_id: The offense ID

        Returns:
            dict: List of notes or error
        """
        result = self._make_request(f"siem/offenses/{offense_id}/notes")
        if isinstance(result, list):
            return {"notes": result, "count": len(result)}
        return result

    # ==================== Reference Set Methods ====================

    def get_reference_sets(self, filter_query: Optional[str] = None) -> Dict[str, Any]:
        """List all reference sets.

        Args:
            filter_query: Optional filter expression

        Returns:
            dict: List of reference sets or error
        """
        params = {}
        if filter_query:
            params["filter"] = filter_query

        result = self._make_request("reference_data/sets", params=params)
        if isinstance(result, list):
            return {"reference_sets": result, "count": len(result)}
        return result

    def get_reference_set(self, name: str) -> Dict[str, Any]:
        """Get a specific reference set by name.

        Args:
            name: The reference set name

        Returns:
            dict: Reference set details including data values
        """
        encoded_name = quote(name, safe="")
        return self._make_request(f"reference_data/sets/{encoded_name}")

    def add_to_reference_set(
        self,
        name: str,
        value: str,
        source: Optional[str] = None
    ) -> Dict[str, Any]:
        """Add a value to a reference set.

        Args:
            name: The reference set name
            value: The value to add
            source: Optional source description

        Returns:
            dict: Updated reference set or error
        """
        encoded_name = quote(name, safe="")
        params = {"value": value}
        if source:
            params["source"] = source

        return self._make_request(
            f"reference_data/sets/{encoded_name}",
            method="POST",
            params=params
        )

    def delete_from_reference_set(self, name: str, value: str) -> Dict[str, Any]:
        """Delete a value from a reference set.

        Args:
            name: The reference set name
            value: The value to delete

        Returns:
            dict: Success status or error
        """
        encoded_name = quote(name, safe="")
        return self._make_request(
            f"reference_data/sets/{encoded_name}/{quote(value, safe='')}",
            method="DELETE"
        )

    def purge_reference_set(self, name: str) -> Dict[str, Any]:
        """Delete all values from a reference set (purge).

        Args:
            name: The reference set name

        Returns:
            dict: Success status or error
        """
        encoded_name = quote(name, safe="")
        return self._make_request(
            f"reference_data/sets/{encoded_name}",
            method="DELETE",
            params={"purge_only": "true"}
        )

    # ==================== Utility Methods ====================

    def _extract_tsld(self, domain: str) -> Optional[str]:
        """Extract TSLD (registrable domain) for faster exact matching.

        Returns the TSLD if the domain is suitable for exact matching,
        or None if ILIKE on URL is needed (for paths, protocols, etc.).

        Note: Using TSLD matches ALL subdomains of the domain, which is
        typically desired for threat hunting (e.g., searching "malicious.com"
        will find activity to any *.malicious.com subdomain).
        """
        domain = domain.lower().strip()

        # Has protocol, path, query string, or wildcard? Need ILIKE on full URL
        if any(x in domain for x in ['://', '/', '?', '*']):
            return None

        parts = domain.split('.')
        if len(parts) < 2:
            return None

        # Common two-part country-code TLDs where TSLD is 3 parts
        two_part_tlds = {
            'co.uk', 'com.au', 'co.nz', 'co.jp', 'com.br', 'co.in',
            'org.uk', 'net.au', 'ac.uk', 'gov.uk', 'edu.au', 'co.za',
            'com.mx', 'co.kr', 'or.jp', 'ne.jp', 'com.cn', 'com.tw',
            'org.au', 'gov.au', 'com.sg', 'com.hk', 'co.th', 'com.my'
        }

        potential_tld = f"{parts[-2]}.{parts[-1]}"

        if potential_tld in two_part_tlds:
            # Country code TLD - TSLD is last 3 parts
            return '.'.join(parts[-3:]) if len(parts) >= 3 else None
        else:
            # Regular TLD - TSLD is last 2 parts
            return '.'.join(parts[-2:])

    def search_events_by_ip(
        self,
        ip_address: str,
        hours: int = 24,
        max_results: int = 100
    ) -> Dict[str, Any]:
        """Search for events involving an IP address.

        Args:
            ip_address: The IP address to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        aql = f"""
            SELECT sourceip, prenatsourceip, destinationip, prenatdestinationip,
                   URL, "URL Path", "Referer URL", "File Name", "Destination Domain Name",
                   "Threat Name", "Threat Type", eventname, magnitude, starttime
            FROM events
            WHERE (sourceip = '{ip_address}' OR destinationip = '{ip_address}')
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def search_events_by_domain(
        self,
        domain: str,
        hours: int = 24,
        max_results: int = 100
    ) -> Dict[str, Any]:
        """Search for events involving a domain.

        Args:
            domain: The domain to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        aql = f"""
            SELECT sourceip, destinationip, "Computer Hostname", username,
                   URL, "Referer", "User Agent", filename, starttime
            FROM events
            WHERE (
                logsourcetypename(devicetype) = 'Zscaler Nss'
                OR logsourcetypename(devicetype) = 'Blue Coat Web Security Service'
            )
            AND URL ILIKE '%{domain}%'
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def search_email_by_sender(
        self,
        sender_domain: str,
        hours: int = 168,
        max_results: int = 100
    ) -> Dict[str, Any]:
        """Search for email events by sender domain.

        Searches Area1 Security and Abnormal Security log sources.

        Args:
            sender_domain: The sender domain to search for (e.g., "malicious.com")
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        aql = f"""
            SELECT sourceip, destinationip, username, "Computer Hostname",
                   qidname(qid) AS eventName, sender, recipient, "Subject", starttime
            FROM events
            WHERE (
                logsourcetypename(devicetype) = 'Area1 Security'
                OR logsourcetypename(devicetype) = 'Abnormal Security'
            )
            AND sender ILIKE '%{sender_domain}%'
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def search_email_by_subject(
        self,
        subject_pattern: str,
        hours: int = 168,
        max_results: int = 100
    ) -> Dict[str, Any]:
        """Search for email events by subject pattern.

        Searches Area1 Security and Abnormal Security log sources.

        Args:
            subject_pattern: The subject pattern to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        aql = f"""
            SELECT sourceip, destinationip, username, "Computer Hostname",
                   qidname(qid) AS eventName, sender, recipient, "Subject", starttime
            FROM events
            WHERE (
                logsourcetypename(devicetype) = 'Area1 Security'
                OR logsourcetypename(devicetype) = 'Abnormal Security'
            )
            AND "Subject" ILIKE '%{subject_pattern}%'
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def search_email_by_recipient(
        self,
        recipient: str,
        hours: int = 168,
        max_results: int = 100
    ) -> Dict[str, Any]:
        """Search for email threats targeting a specific recipient/user.

        Searches Area1 Security and Abnormal Security log sources.

        Args:
            recipient: The recipient email or username to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        aql = f"""
            SELECT sourceip, destinationip, username, "Computer Hostname",
                   qidname(qid) AS eventName, sender, recipient, "Subject", starttime
            FROM events
            WHERE (
                logsourcetypename(devicetype) = 'Area1 Security'
                OR logsourcetypename(devicetype) = 'Abnormal Security'
            )
            AND (
                username ILIKE '%{recipient}%'
                OR recipient ILIKE '%{recipient}%'
            )
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def search_o365_by_filename(
        self,
        filename: str,
        hours: int = 168,
        max_results: int = 100
    ) -> Dict[str, Any]:
        """Search for O365 file events by filename.

        Searches O365 logs for file operations matching the filename.

        Args:
            filename: The filename pattern to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        aql = f"""
            SELECT sourceip, destinationip, username, "Computer Hostname",
                   qidname(qid) AS eventName, "Filename", Operation, starttime
            FROM events
            WHERE "deviceType" = '397'
            AND Operation IN ('FileModified', 'FileAccessed', 'FileAccessedExtended',
                              'FileUploaded', 'FileDownloaded', 'FileMalwareDetected')
            AND "Filename" ILIKE '%{filename}%'
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def search_o365_threat_intel(
        self,
        indicator: str,
        hours: int = 168,
        max_results: int = 100
    ) -> Dict[str, Any]:
        """Search for O365 threat intelligence events.

        Searches O365 TI events (URL clicks, mail data, investigations).

        Args:
            indicator: The indicator to search for (URL, domain, etc.)
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        aql = f"""
            SELECT sourceip, destinationip, username, "Computer Hostname",
                   qidname(qid) AS eventName, "Filename", "Subject", URL, starttime
            FROM events
            WHERE "deviceType" = '397'
            AND Operation IN ('TIUrlClickData', 'TIMailData', 'AirInvestigationData')
            AND (
                URL ILIKE '%{indicator}%'
                OR "Subject" ILIKE '%{indicator}%'
                OR "Filename" ILIKE '%{indicator}%'
            )
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def search_zpa_logons_by_ip(
        self,
        ip: str,
        hours: int = 168,
        max_results: int = 100
    ) -> Dict[str, Any]:
        """Search for Zscaler Private Access logon events by IP.

        Args:
            ip: The IP address to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        aql = f"""
            SELECT sourceip, destinationip, username, "Computer Hostname",
                   qidname(qid) AS eventName, "ZPN-Sess-Status", starttime
            FROM events
            WHERE logsourcetypename(devicetype) = 'Zscaler Private Access'
            AND (sourceip = '{ip}' OR destinationip = '{ip}')
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def search_zpa_logons_by_user(
        self,
        username: str,
        hours: int = 168,
        max_results: int = 100
    ) -> Dict[str, Any]:
        """Search for Zscaler Private Access logon events by username.

        Args:
            username: The username to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        aql = f"""
            SELECT sourceip, destinationip, username, "Computer Hostname",
                   qidname(qid) AS eventName, "ZPN-Sess-Status", starttime
            FROM events
            WHERE logsourcetypename(devicetype) = 'Zscaler Private Access'
            AND username ILIKE '%{username}%'
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def search_entra_by_ip(
        self,
        ip: str,
        hours: int = 168,
        max_results: int = 100
    ) -> Dict[str, Any]:
        """Search for Microsoft Entra ID events by IP.

        Args:
            ip: The IP address to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        aql = f"""
            SELECT sourceip, destinationip, username, "Computer Hostname",
                   qidname(qid) AS eventName, Operation, "Conditional Access Status",
                   "Log Type", "Authentication Requirement", "Region", starttime
            FROM events
            WHERE logsourcetypename(devicetype) = 'Microsoft Entra ID'
            AND (sourceip = '{ip}' OR destinationip = '{ip}')
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def search_entra_by_user(
        self,
        username: str,
        hours: int = 168,
        max_results: int = 100
    ) -> Dict[str, Any]:
        """Search for Microsoft Entra ID events by username.

        Args:
            username: The username to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        aql = f"""
            SELECT sourceip, destinationip, username, "Computer Hostname",
                   qidname(qid) AS eventName, Operation, "Conditional Access Status",
                   "Log Type", "Authentication Requirement", "Region", starttime
            FROM events
            WHERE logsourcetypename(devicetype) = 'Microsoft Entra ID'
            AND username ILIKE '%{username}%'
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def search_endpoint_by_hash(
        self,
        file_hash: str,
        hours: int = 168,
        max_results: int = 100
    ) -> Dict[str, Any]:
        """Search for endpoint events by file hash.

        Searches CrowdStrike Endpoint and Tanium HTTP log sources.

        Args:
            file_hash: The MD5 or SHA256 hash to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        aql = f"""
            SELECT sourceip, destinationip, "Computer Hostname", username,
                   qidname(qid) AS eventName, "MD5", "MD5 Hash", "SHA256 Hash",
                   "Process Name", Command, "Parent Command Line", "Intel Name",
                   "Action", starttime
            FROM events
            WHERE (
                logsourcetypename(devicetype) = 'CrowdStrikeEndpoint'
                OR logsourcetypename(devicetype) = 'Tanium HTTP'
            )
            AND (
                "MD5" = '{file_hash}'
                OR "MD5 Hash" = '{file_hash}'
                OR "SHA256 Hash" = '{file_hash}'
            )
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def search_endpoint_by_ip(
        self,
        ip: str,
        hours: int = 168,
        max_results: int = 100
    ) -> Dict[str, Any]:
        """Search for endpoint events by IP address.

        Searches CrowdStrike Endpoint and Tanium HTTP log sources.

        Args:
            ip: The IP address to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        aql = f"""
            SELECT sourceip, destinationip, "Computer Hostname", username,
                   qidname(qid) AS eventName, "MD5 Hash", "SHA256 Hash",
                   "Process Name", Command, "Intel Name", "Action", starttime
            FROM events
            WHERE (
                logsourcetypename(devicetype) = 'CrowdStrikeEndpoint'
                OR logsourcetypename(devicetype) = 'Tanium HTTP'
            )
            AND (sourceip = '{ip}' OR destinationip = '{ip}')
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def search_endpoint_by_filename(
        self,
        filename: str,
        hours: int = 168,
        max_results: int = 100
    ) -> Dict[str, Any]:
        """Search for endpoint events by filename/process name.

        Searches CrowdStrike Endpoint and Tanium HTTP log sources.

        Args:
            filename: The filename or process name to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        aql = f"""
            SELECT sourceip, destinationip, "Computer Hostname", username,
                   qidname(qid) AS eventName, "MD5 Hash", "SHA256 Hash",
                   "Process Name", "Parent Image File Name", Command,
                   "Parent Command Line", "Intel Name", "Action", starttime
            FROM events
            WHERE (
                logsourcetypename(devicetype) = 'CrowdStrikeEndpoint'
                OR logsourcetypename(devicetype) = 'Tanium HTTP'
            )
            AND (
                "Process Name" ILIKE '%{filename}%'
                OR "Parent Image File Name" ILIKE '%{filename}%'
            )
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def search_paloalto_threat_by_ip(
        self,
        ip: str,
        hours: int = 168,
        max_results: int = 100
    ) -> Dict[str, Any]:
        """Search for Palo Alto firewall threat events by IP.

        Args:
            ip: The IP address to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        aql = f"""
            SELECT sourceip, destinationip, qidname(qid) AS eventName,
                   "Threat Name", "Action", URL, "TSLD", "PAN Log SubType", starttime
            FROM events
            WHERE logsourcetypename(devicetype) = 'Palo Alto PA Series'
            AND "PAN Log Type" = 'THREAT'
            AND (sourceip = '{ip}' OR destinationip = '{ip}')
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def search_paloalto_threat_by_domain(
        self,
        domain: str,
        hours: int = 168,
        max_results: int = 100
    ) -> Dict[str, Any]:
        """Search for Palo Alto firewall threat events by domain/URL.

        Uses exact TSLD match for simple domains (faster indexed lookup),
        falls back to ILIKE for URLs with paths/protocols.

        Args:
            domain: The domain to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        tsld = self._extract_tsld(domain)

        if tsld:
            # Fast exact match on indexed TSLD field
            domain_condition = f"\"TSLD\" = '{tsld}'"
        else:
            # Complex pattern (URL with path, protocol, etc.) - use ILIKE
            domain_condition = f"URL ILIKE '%{domain}%'"

        aql = f"""
            SELECT sourceip, destinationip, qidname(qid) AS eventName,
                   "Threat Name", "Action", URL, "TSLD", "PAN Log SubType", starttime
            FROM events
            WHERE logsourcetypename(devicetype) = 'Palo Alto PA Series'
            AND "PAN Log Type" = 'THREAT'
            AND {domain_condition}
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    # ==================== Batched Search Methods ====================
    # These methods search for multiple IOCs in a single query for efficiency

    def batch_search_domains_webproxy(
        self,
        domains: List[str],
        hours: int = 168,
        max_results: int = 500
    ) -> Dict[str, Any]:
        """Search for multiple domains in web proxy logs (single query).

        Args:
            domains: List of domains to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        if not domains:
            return {"events": [], "count": 0}

        # Build OR conditions for domains
        domain_conditions = " OR ".join([f"URL ILIKE '%{d}%'" for d in domains])

        aql = f"""
            SELECT sourceip, destinationip, "Computer Hostname", username,
                   URL, "Referer", "User Agent", filename, starttime
            FROM events
            WHERE (
                logsourcetypename(devicetype) = 'Zscaler Nss'
                OR logsourcetypename(devicetype) = 'Blue Coat Web Security Service'
            )
            AND ({domain_conditions})
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def batch_search_domains_email(
        self,
        domains: List[str],
        hours: int = 168,
        max_results: int = 500
    ) -> Dict[str, Any]:
        """Search for multiple domains in email logs (single query).

        Args:
            domains: List of domains to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        if not domains:
            return {"events": [], "count": 0}

        domain_conditions = " OR ".join([f"sender ILIKE '%{d}%'" for d in domains])

        aql = f"""
            SELECT sourceip, destinationip, username, "Computer Hostname",
                   qidname(qid) AS eventName, sender, recipient, "Subject", starttime
            FROM events
            WHERE (
                logsourcetypename(devicetype) = 'Area1 Security'
                OR logsourcetypename(devicetype) = 'Abnormal Security'
            )
            AND ({domain_conditions})
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def batch_search_domains_o365(
        self,
        domains: List[str],
        hours: int = 168,
        max_results: int = 500
    ) -> Dict[str, Any]:
        """Search for multiple domains in O365 threat intel (single query).

        Args:
            domains: List of domains to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        if not domains:
            return {"events": [], "count": 0}

        domain_conditions = " OR ".join([
            f"(URL ILIKE '%{d}%' OR \"Subject\" ILIKE '%{d}%')"
            for d in domains
        ])

        aql = f"""
            SELECT sourceip, destinationip, username, "Computer Hostname",
                   qidname(qid) AS eventName, "Filename", "Subject", URL, starttime
            FROM events
            WHERE "deviceType" = '397'
            AND Operation IN ('TIUrlClickData', 'TIMailData', 'AirInvestigationData')
            AND ({domain_conditions})
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def batch_search_domains_paloalto(
        self,
        domains: List[str],
        hours: int = 168,
        max_results: int = 500
    ) -> Dict[str, Any]:
        """Search for multiple domains in Palo Alto threat logs (single query).

        Uses exact TSLD match for simple domains (faster indexed lookup),
        falls back to ILIKE for URLs with paths/protocols.

        Args:
            domains: List of domains to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        if not domains:
            return {"events": [], "count": 0}

        conditions = []
        for domain in domains:
            tsld = self._extract_tsld(domain)
            if tsld:
                # Fast exact match on indexed TSLD field
                conditions.append(f"\"TSLD\" = '{tsld}'")
            else:
                # Complex pattern - use ILIKE on URL
                conditions.append(f"URL ILIKE '%{domain}%'")

        domain_conditions = " OR ".join(conditions)

        aql = f"""
            SELECT sourceip, destinationip, qidname(qid) AS eventName,
                   "Threat Name", "Action", URL, "TSLD", "PAN Log SubType", starttime
            FROM events
            WHERE logsourcetypename(devicetype) = 'Palo Alto PA Series'
            AND "PAN Log Type" = 'THREAT'
            AND ({domain_conditions})
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def batch_search_ips_general(
        self,
        ips: List[str],
        hours: int = 168,
        max_results: int = 500
    ) -> Dict[str, Any]:
        """Search for multiple IPs in general events (single query).

        Args:
            ips: List of IP addresses to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        if not ips:
            return {"events": [], "count": 0}

        ip_conditions = " OR ".join([
            f"(sourceip = '{ip}' OR destinationip = '{ip}')"
            for ip in ips
        ])

        aql = f"""
            SELECT sourceip, destinationip, "Computer Hostname", username,
                   qidname(qid) AS eventName, URL, "Threat Name", magnitude, starttime
            FROM events
            WHERE ({ip_conditions})
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def batch_search_ips_zpa(
        self,
        ips: List[str],
        hours: int = 168,
        max_results: int = 500
    ) -> Dict[str, Any]:
        """Search for multiple IPs in ZPA logs (single query).

        Args:
            ips: List of IP addresses to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        if not ips:
            return {"events": [], "count": 0}

        ip_conditions = " OR ".join([
            f"(sourceip = '{ip}' OR destinationip = '{ip}')"
            for ip in ips
        ])

        aql = f"""
            SELECT sourceip, destinationip, username, "Computer Hostname",
                   qidname(qid) AS eventName, "ZPN-Sess-Status", starttime
            FROM events
            WHERE logsourcetypename(devicetype) = 'Zscaler Private Access'
            AND ({ip_conditions})
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def batch_search_ips_entra(
        self,
        ips: List[str],
        hours: int = 168,
        max_results: int = 500
    ) -> Dict[str, Any]:
        """Search for multiple IPs in Entra ID logs (single query).

        Args:
            ips: List of IP addresses to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        if not ips:
            return {"events": [], "count": 0}

        ip_conditions = " OR ".join([
            f"(sourceip = '{ip}' OR destinationip = '{ip}')"
            for ip in ips
        ])

        aql = f"""
            SELECT sourceip, destinationip, username, "Computer Hostname",
                   qidname(qid) AS eventName, Operation, "Conditional Access Status",
                   "Log Type", "Region", starttime
            FROM events
            WHERE logsourcetypename(devicetype) = 'Microsoft Entra ID'
            AND ({ip_conditions})
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def batch_search_ips_endpoint(
        self,
        ips: List[str],
        hours: int = 168,
        max_results: int = 500
    ) -> Dict[str, Any]:
        """Search for multiple IPs in endpoint logs (single query).

        Args:
            ips: List of IP addresses to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        if not ips:
            return {"events": [], "count": 0}

        ip_conditions = " OR ".join([
            f"(sourceip = '{ip}' OR destinationip = '{ip}')"
            for ip in ips
        ])

        aql = f"""
            SELECT sourceip, destinationip, "Computer Hostname", username,
                   qidname(qid) AS eventName, "MD5 Hash", "SHA256 Hash",
                   "Process Name", Command, "Intel Name", "Action", starttime
            FROM events
            WHERE (
                logsourcetypename(devicetype) = 'CrowdStrikeEndpoint'
                OR logsourcetypename(devicetype) = 'Tanium HTTP'
            )
            AND ({ip_conditions})
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def batch_search_ips_paloalto(
        self,
        ips: List[str],
        hours: int = 168,
        max_results: int = 500
    ) -> Dict[str, Any]:
        """Search for multiple IPs in Palo Alto threat logs (single query).

        Args:
            ips: List of IP addresses to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        if not ips:
            return {"events": [], "count": 0}

        ip_conditions = " OR ".join([
            f"(sourceip = '{ip}' OR destinationip = '{ip}')"
            for ip in ips
        ])

        aql = f"""
            SELECT sourceip, destinationip, qidname(qid) AS eventName,
                   "Threat Name", "Action", URL, "TSLD", "PAN Log SubType", starttime
            FROM events
            WHERE logsourcetypename(devicetype) = 'Palo Alto PA Series'
            AND "PAN Log Type" = 'THREAT'
            AND ({ip_conditions})
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    def batch_search_hashes_endpoint(
        self,
        hashes: List[str],
        hours: int = 168,
        max_results: int = 500
    ) -> Dict[str, Any]:
        """Search for multiple hashes in endpoint logs (single query).

        Args:
            hashes: List of MD5 or SHA256 hashes to search for
            hours: Number of hours to look back
            max_results: Maximum events to return

        Returns:
            dict: Search results with events
        """
        if not hashes:
            return {"events": [], "count": 0}

        hash_conditions = " OR ".join([
            f"(\"MD5\" = '{h}' OR \"MD5 Hash\" = '{h}' OR \"SHA256 Hash\" = '{h}')"
            for h in hashes
        ])

        aql = f"""
            SELECT sourceip, destinationip, "Computer Hostname", username,
                   qidname(qid) AS eventName, "MD5", "MD5 Hash", "SHA256 Hash",
                   "Process Name", Command, "Parent Command Line", "Intel Name",
                   "Action", starttime
            FROM events
            WHERE (
                logsourcetypename(devicetype) = 'CrowdStrikeEndpoint'
                OR logsourcetypename(devicetype) = 'Tanium HTTP'
            )
            AND ({hash_conditions})
            LIMIT {max_results}
            LAST {hours} HOURS
        """
        return self.run_aql_search(aql.strip(), max_results=max_results)

    # ==================== Detection Rules Catalog Methods ====================

    def list_analytics_rules(self, origin: str = "USER") -> Dict[str, Any]:
        """List custom analytics rules from QRadar.

        Args:
            origin: Rule origin filter - "USER" for custom, "SYSTEM" for built-in

        Returns:
            Dict with rules list or error
        """
        try:
            params = {"filter": f'origin="{origin}"', "fields": "id,name,notes,enabled,type,creation_date,modification_date"}
            result = self._make_request("GET", "analytics/rules", params=params)
            if isinstance(result, dict) and "error" in result:
                return result
            return {"rules": result if isinstance(result, list) else [], "count": len(result) if isinstance(result, list) else 0}
        except Exception as e:
            logger.error(f"Error listing analytics rules: {e}")
            return {"error": str(e)}

    def list_saved_searches(self) -> Dict[str, Any]:
        """List all saved AQL searches from QRadar.

        Returns:
            Dict with saved searches list or error
        """
        try:
            result = self._make_request("GET", "ariel/saved_searches")
            if isinstance(result, dict) and "error" in result:
                return result
            return {"searches": result if isinstance(result, list) else [], "count": len(result) if isinstance(result, list) else 0}
        except Exception as e:
            logger.error(f"Error listing saved searches: {e}")
            return {"error": str(e)}

    @staticmethod
    def format_offense_summary(offense: Dict[str, Any]) -> str:
        """Format an offense for display.

        Args:
            offense: Offense data from QRadar

        Returns:
            str: Formatted offense summary
        """
        if not offense or "error" in offense:
            return "No offense data available"

        parts = [
            f"## QRadar Offense #{offense.get('id', 'Unknown')}",
            f"**Description:** {offense.get('description', 'N/A')}",
            f"**Status:** {offense.get('status', 'Unknown')}",
            f"**Severity:** {offense.get('severity', 'Unknown')}/10",
            f"**Magnitude:** {offense.get('magnitude', 'Unknown')}/10",
            f"**Event Count:** {offense.get('event_count', 0):,}",
            f"**Flow Count:** {offense.get('flow_count', 0):,}",
            f"**Source IPs:** {offense.get('source_count', 0)}",
            f"**Destination IPs:** {offense.get('destination_count', 0)}",
        ]

        # Add offense source if available
        offense_source = offense.get("offense_source")
        if offense_source:
            parts.append(f"**Offense Source:** {offense_source}")

        # Add categories if available
        categories = offense.get("categories", [])
        if categories:
            parts.append(f"**Categories:** {', '.join(categories[:5])}")

        return "\n".join(parts)

    @staticmethod
    def format_event_results(events: List[Dict[str, Any]], title: str = "QRadar Events") -> str:
        """Format event search results for display.

        Args:
            events: List of events from search results
            title: Title for the results section

        Returns:
            str: Formatted events summary
        """
        if not events:
            return "No events found"

        parts = [
            f"## {title}",
            f"**Total Events:** {len(events)}",
            ""
        ]

        for i, event in enumerate(events[:10], 1):
            event_parts = [f"### Event {i}"]

            for key in ["sourceip", "destinationip", "eventname", "magnitude"]:
                if key in event:
                    label = key.replace("ip", " IP").replace("name", " Name").title()
                    event_parts.append(f"**{label}:** {event[key]}")

            if "starttime" in event:
                # Convert epoch ms to readable format
                try:
                    from datetime import datetime
                    ts = event["starttime"] / 1000 if event["starttime"] > 1e12 else event["starttime"]
                    dt = datetime.fromtimestamp(ts)
                    event_parts.append(f"**Time:** {dt.strftime('%Y-%m-%d %H:%M:%S')}")
                except (ValueError, OSError):
                    event_parts.append(f"**Time:** {event['starttime']}")

            parts.append("\n".join(event_parts))

        if len(events) > 10:
            parts.append(f"\n*... and {len(events) - 10} more events*")

        return "\n\n".join(parts)


if __name__ == "__main__":
    # Quick test for QRadar client
    import sys

    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    client = QRadarClient()

    if not client.is_configured():
        print("ERROR: QRadar API not configured")
        print("Set QRADAR_API_URL and QRADAR_API_KEY in your secrets file")
        sys.exit(1)

    print("QRadar Client Test")
    print("=" * 50)

    # Test getting offenses
    print("\n1. Testing offense listing...")
    result = client.get_offenses(limit=5)
    if "error" in result:
        print(f"   Error: {result['error']}")
    else:
        print(f"   Found {result.get('count', 0)} offenses")

    # Test reference sets listing
    print("\n2. Testing reference set listing...")
    result = client.get_reference_sets()
    if "error" in result:
        print(f"   Error: {result['error']}")
    else:
        print(f"   Found {result.get('count', 0)} reference sets")

    # Test new search methods (use short time window for speed)
    test_hours = 1

    print("\n3. Testing domain search (Zscaler/Blue Coat)...")
    result = client.search_events_by_domain("google.com", hours=test_hours, max_results=5)
    if "error" in result:
        print(f"   Error: {result['error']}")
    else:
        print(f"   Found {len(result.get('events', []))} events")

    print("\n4. Testing email sender search (Area1/Abnormal)...")
    result = client.search_email_by_sender("gmail.com", hours=test_hours, max_results=5)
    if "error" in result:
        print(f"   Error: {result['error']}")
    else:
        print(f"   Found {len(result.get('events', []))} events")

    print("\n5. Testing O365 threat intel search...")
    result = client.search_o365_threat_intel("microsoft.com", hours=test_hours, max_results=5)
    if "error" in result:
        print(f"   Error: {result['error']}")
    else:
        print(f"   Found {len(result.get('events', []))} events")

    print("\n6. Testing ZPA logon search...")
    result = client.search_zpa_logons_by_ip("10.0.0.1", hours=test_hours, max_results=5)
    if "error" in result:
        print(f"   Error: {result['error']}")
    else:
        print(f"   Found {len(result.get('events', []))} events")

    print("\n7. Testing Entra ID search...")
    result = client.search_entra_by_ip("10.0.0.1", hours=test_hours, max_results=5)
    if "error" in result:
        print(f"   Error: {result['error']}")
    else:
        print(f"   Found {len(result.get('events', []))} events")

    print("\n8. Testing endpoint hash search (CrowdStrike/Tanium)...")
    result = client.search_endpoint_by_hash("d41d8cd98f00b204e9800998ecf8427e", hours=test_hours, max_results=5)
    if "error" in result:
        print(f"   Error: {result['error']}")
    else:
        print(f"   Found {len(result.get('events', []))} events")

    print("\n9. Testing Palo Alto threat search by IP...")
    result = client.search_paloalto_threat_by_ip("10.0.0.1", hours=test_hours, max_results=5)
    if "error" in result:
        print(f"   Error: {result['error']}")
    else:
        print(f"   Found {len(result.get('events', []))} events")

    print("\n10. Testing Palo Alto threat search by domain...")
    result = client.search_paloalto_threat_by_domain("malware.com", hours=test_hours, max_results=5)
    if "error" in result:
        print(f"   Error: {result['error']}")
    else:
        print(f"   Found {len(result.get('events', []))} events")

    print("\n" + "=" * 50)
    print("Tests complete!")
